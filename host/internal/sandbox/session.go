// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/dbcrit/vesta/api/channel"
	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/transport"
	"github.com/dbcrit/vesta/host/internal/wire"
)

// Errors surfaced to the NRI gate.
var (
	ErrIneligible = errors.New("sandbox is not eligible for vesta")
	ErrStopped    = errors.New("sandbox session stopped")
)

// Config is shared by all sessions.
type Config struct {
	Node         string
	AgentVersion string
	CtrlPort     uint32
	EvtPort      uint32
	GlobalMode   channelv1.GlobalMode

	// Discover returns the guest endpoint of a sandbox.
	Discover func(ctx context.Context, sandboxID string) (transport.Endpoint, error)
	// DialerFor returns a dialer for an endpoint.
	DialerFor func(transport.Endpoint) (transport.Dialer, error)

	// RequestTimeout bounds handshake and policy requests. Default 5s.
	RequestTimeout time.Duration
	// BindTimeout bounds how long a bind may stay unacked. Default 30s.
	BindTimeout time.Duration
	// BackoffMin and BackoffMax bound reconnect delays. Defaults 100ms, 10s.
	BackoffMin, BackoffMax time.Duration
	// HeartbeatGrace is the multiple of the heartbeat interval after which a
	// heartbeat counts as missing. Default 2.
	HeartbeatGrace float64
	// Wire tunes framing timeouts.
	Wire wire.Options

	Metrics  *metrics.Metrics
	Log      *slog.Logger
	Pipeline *events.Pipeline
}

func (c *Config) defaults() {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.BindTimeout <= 0 {
		c.BindTimeout = 30 * time.Second
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = 100 * time.Millisecond
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 10 * time.Second
	}
	if c.HeartbeatGrace < 1 {
		c.HeartbeatGrace = 2
	}
	if c.CtrlPort == 0 {
		c.CtrlPort = channel.DefaultCtrlPort
	}
	if c.EvtPort == 0 {
		c.EvtPort = channel.DefaultEvtPort
	}
}

type state int

const (
	stateConnecting state = iota
	stateReady
	stateIneligible
	stateStopped
)

// Container is what the NRI plugin tells a session about a container.
type Container struct {
	Info       events.ContainerInfo
	CgroupPath string
	Policy     *policy.Policy // nil: monitor only
}

type boundContainer struct {
	Container
	done   chan struct{}
	once   sync.Once
	err    error
	bound  bool
	policy uint32
}

func (b *boundContainer) finish(err error) {
	b.once.Do(func() {
		b.err = err
		close(b.done)
	})
}

// Session owns the channel to one sandbox's guest. All guest data it reads
// is validated before use.
type Session struct {
	cfg    *Config
	info   events.SandboxInfo
	set    *policy.Set
	log    *slog.Logger
	source *events.Source

	cancel context.CancelFunc
	done   chan struct{}
	// reload is signalled (non-blocking, capacity 1) when the policy set changes.
	reload chan struct{}

	mu                  sync.Mutex
	st                  state
	changed             chan struct{}
	ineligErr           error
	ctrl                *ctrlConn
	hello               *channelv1.HelloReply
	features            map[string]bool
	appliedGen          uint64
	appliedSet          *policy.Set // the set appliedGen was sent from
	applyErr            error
	containers          map[string]*boundContainer
	lastSeq             uint64 // highest event seq received
	hb                  *hbMonitor
	countedProgFailures bool
	alertLog            map[string]*alertLogState
}

// alertLogState rate-limits alert log lines per reason; counters always count.
type alertLogState struct {
	last       time.Time
	suppressed int
}

// alertLogInterval is the minimum spacing of log lines for one alert reason
// of one session. A guest can trigger alerts at will; the log must not
// become its amplifier.
const alertLogInterval = time.Minute

func newSession(cfg *Config, info events.SandboxInfo, set *policy.Set) *Session {
	return &Session{
		cfg: cfg, info: info, set: set,
		log:        cfg.Log.With("sandbox", info.SandboxID, "namespace", info.PodNamespace, "pod", info.PodName),
		source:     cfg.Pipeline.NewSource(),
		done:       make(chan struct{}),
		reload:     make(chan struct{}, 1),
		changed:    make(chan struct{}),
		containers: make(map[string]*boundContainer),
		hb:         newHBMonitor(cfg.HeartbeatGrace, time.Now()),
		alertLog:   make(map[string]*alertLogState),
	}
}

func (s *Session) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	go func() {
		defer close(s.done)
		s.run(ctx)
	}()
}

// Stop ends the session and waits for its goroutines.
func (s *Session) Stop() {
	<-s.StopAsync()
}

// StopAsync cancels the session and returns a channel closed once it has
// fully stopped. It never blocks, so NRI hooks can call it.
func (s *Session) StopAsync() <-chan struct{} {
	stopped := make(chan struct{})
	if s.cancel != nil {
		s.cancel()
	}
	go func() {
		defer close(stopped)
		if s.cancel != nil {
			<-s.done
		}
		s.finishStop()
	}()
	return stopped
}

func (s *Session) finishStop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st != stateIneligible {
		s.setStateLocked(stateStopped)
	}
	for _, c := range s.containers {
		c.finish(ErrStopped)
	}
}

func (s *Session) setStateLocked(st state) {
	s.st = st
	close(s.changed)
	s.changed = make(chan struct{})
}

// State returns the metrics state of the session.
func (s *Session) State() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.st == stateIneligible:
		return metrics.StateIneligible
	case s.st == stateReady && !s.hb.stale():
		return metrics.StateMonitored
	default:
		return metrics.StateUnmonitored
	}
}

func (s *Session) run(ctx context.Context) {
	delay := s.cfg.BackoffMin
	for ctx.Err() == nil {
		err := s.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		var inelig *ineligibleError
		if errors.As(err, &inelig) {
			s.log.Warn("sandbox not eligible, not monitoring", "reason", inelig.err)
			s.cfg.Metrics.ChannelConnects.WithLabelValues("ineligible").Inc()
			s.mu.Lock()
			s.ineligErr = inelig.err
			s.setStateLocked(stateIneligible)
			for _, c := range s.containers {
				c.finish(fmt.Errorf("%w: %w", ErrIneligible, inelig.err))
			}
			s.mu.Unlock()
			return
		}
		if err != nil {
			if errors.Is(err, transport.ErrNotReady) {
				s.log.Debug("guest endpoint not ready", "err", err)
			} else {
				s.log.Warn("channel down", "err", err)
			}
			s.cfg.Metrics.ChannelConnects.WithLabelValues("error").Inc()
		} else {
			delay = s.cfg.BackoffMin
		}
		// Full jitter keeps reconnects of many sandboxes from aligning.
		wait := time.Duration(rand.Int64N(int64(delay)) + 1) //nolint:gosec // G404: reconnect jitter, not a secret
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		delay = min(delay*2, s.cfg.BackoffMax)
	}
}

type ineligibleError struct{ err error }

func (e *ineligibleError) Error() string { return e.err.Error() }

// connectOnce runs one connection epoch: discover, handshake, apply policy,
// rebind, then stream events until either connection fails.
func (s *Session) connectOnce(ctx context.Context) error {
	ep, err := s.cfg.Discover(ctx, s.info.SandboxID)
	if err != nil {
		return fmt.Errorf("discover endpoint: %w", err)
	}
	d, err := s.cfg.DialerFor(ep)
	if err != nil {
		return err
	}
	cc, reply, err := s.handshake(ctx, d)
	if err != nil {
		return err
	}
	defer cc.Close()

	if err := validateHelloReply(reply); err != nil {
		s.cfg.Metrics.ProtocolErrors.WithLabelValues("ctrl").Inc()
		return fmt.Errorf("hello reply: %w", err)
	}
	if err := eligibility(reply); err != nil {
		return &ineligibleError{err}
	}
	s.recordHello(reply)

	if err := s.applyPolicy(ctx, cc, reply.GetAppliedGeneration(), reply.GetAdoptedGeneration()); err != nil {
		return err
	}
	if err := s.syncMode(ctx, cc, reply); err != nil {
		return err
	}
	if err := s.syncSandboxDefault(ctx, cc); err != nil {
		return err
	}

	evtCtx, cancelEvt := context.WithCancel(ctx)
	defer cancelEvt()
	evtDone := make(chan error, 1)
	go func() { evtDone <- s.streamEvents(evtCtx, d, reply.GetProtoMajor()) }()

	s.mu.Lock()
	s.ctrl = cc
	s.hb.restart(time.Now())
	s.setStateLocked(stateReady)
	rebind := make([]*boundContainer, 0, len(s.containers))
	for _, c := range s.containers {
		rebind = append(rebind, c)
	}
	s.mu.Unlock()
	s.cfg.Metrics.ChannelConnects.WithLabelValues("ok").Inc()
	s.log.Info("channel ready", "guest_image", reply.GetGuestImageVersion(), "kernel", reply.GetKernelRelease(),
		"proto", fmt.Sprintf("%d.%d", reply.GetProtoMajor(), reply.GetProtoMinor()), "generation", s.appliedGeneration())

	for _, c := range rebind {
		rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		err := s.sendBind(rctx, cc, c)
		cancel()
		if err != nil {
			s.log.Warn("rebind failed", "container", c.Info.ID, "err", err)
		}
	}

	var result error
	evtFinished := false
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case <-cc.Done():
			result = fmt.Errorf("control connection: %w", cc.Err())
			break wait
		case err := <-evtDone:
			evtFinished = true
			result = fmt.Errorf("event stream: %w", err)
			break wait
		case <-s.reload:
			if err := s.reapply(ctx, cc); err != nil {
				result = fmt.Errorf("policy reload: %w", err)
				break wait
			}
		}
	}
	s.mu.Lock()
	s.ctrl = nil
	if s.st == stateReady {
		s.setStateLocked(stateConnecting)
	}
	s.mu.Unlock()
	cc.Close()
	cancelEvt()
	if !evtFinished {
		<-evtDone
	}
	return result
}

func (s *Session) dial(ctx context.Context, d transport.Dialer, port uint32) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	return d.Dial(ctx, port)
}

// handshake sends Hello with each supported major until the guest accepts
// one. The guest closes the connection after rejecting a version, so every
// attempt uses a fresh connection.
func (s *Session) handshake(ctx context.Context, d transport.Dialer) (*ctrlConn, *channelv1.HelloReply, error) {
	var lastErr error
	for _, major := range SupportedMajors() {
		nc, err := s.dial(ctx, d, s.cfg.CtrlPort)
		if err != nil {
			return nil, nil, fmt.Errorf("dial control port: %w", err)
		}
		cc := newCtrlConn(nc, s.cfg.Wire, func(rtt time.Duration) { s.cfg.Metrics.ChannelRTT.Observe(rtt.Seconds()) })
		minor := uint32(0)
		if major == channel.ProtoMajor {
			minor = channel.ProtoMinor
		}
		rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		resp, err := cc.Call(rctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_Hello{Hello: &channelv1.Hello{
			ProtoMajor: major, ProtoMinor: minor, AgentVersion: s.cfg.AgentVersion, SandboxId: s.info.SandboxID,
		}}})
		cancel()
		if err != nil {
			cc.Close()
			return nil, nil, fmt.Errorf("hello: %w", err)
		}
		switch b := resp.GetBody().(type) {
		case *channelv1.ControlResponse_HelloReply:
			return cc, b.HelloReply, nil
		case *channelv1.ControlResponse_Error:
			cc.Close()
			if b.Error.GetCode() == channelv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION {
				lastErr = fmt.Errorf("guest rejected protocol %d: %.1024s", major, b.Error.GetMessage())
				continue
			}
			return nil, nil, fmt.Errorf("hello rejected: %s: %.1024s", b.Error.GetCode(), b.Error.GetMessage())
		default:
			cc.Close()
			s.cfg.Metrics.ProtocolErrors.WithLabelValues("ctrl").Inc()
			return nil, nil, &ProtocolError{Msg: fmt.Sprintf("unexpected hello response %T", b)}
		}
	}
	return nil, nil, &ineligibleError{lastErr}
}

func (s *Session) recordHello(r *channelv1.HelloReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hello = r
	s.features = make(map[string]bool, len(r.GetFeatures()))
	for _, f := range r.GetFeatures() {
		s.features[f] = true
	}
	s.info.GuestImageVersion = r.GetGuestImageVersion()
	s.info.KernelRelease = r.GetKernelRelease()
	s.hb.setBaseline(r.GetProgs())
	if !s.countedProgFailures {
		s.countedProgFailures = true
		for _, p := range r.GetProgs() {
			if p.GetState() == channelv1.ProgState_PROG_STATE_FAILED {
				s.cfg.Metrics.ProgramLoadFailures.Inc()
				s.log.Warn("guest program failed to load", "prog", p.GetId(), "attach", p.GetAttach(), "error", p.GetError())
			}
		}
	}
}

func (s *Session) appliedGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appliedGen
}

// applyPolicy sends the policy set. The generation must never go below
// what the guest already applied, or what a restarted guestd adopted from
// its predecessor (it rejects lower ones), so after an agent restart with an
// older clock it continues above the guest's generation.
func (s *Session) applyPolicy(ctx context.Context, cc *ctrlConn, applied, adopted uint64) error {
	set := s.policies()
	gen := nextGeneration(set.Generation, applied, adopted)
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	resp, err := cc.Call(rctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_ApplyPolicy{ApplyPolicy: &channelv1.ApplyPolicy{
		Generation: gen, Bundles: set.Bundles(),
	}}})
	if err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}
	var applyErr error
	switch b := resp.GetBody().(type) {
	case *channelv1.ControlResponse_Ack:
		if err := validateAck(b.Ack); err != nil {
			s.cfg.Metrics.ProtocolErrors.WithLabelValues("ctrl").Inc()
			return &ProtocolError{Msg: err.Error()}
		}
		for _, w := range b.Ack.GetWarnings() {
			s.log.Warn("policy warning from guest", "warning", w)
		}
		if !b.Ack.GetOk() || b.Ack.GetGeneration() != gen {
			applyErr = fmt.Errorf("guest did not apply policy generation %d (acked %d): %s", gen, b.Ack.GetGeneration(), b.Ack.GetError())
		}
	case *channelv1.ControlResponse_Error:
		applyErr = fmt.Errorf("guest rejected policy: %s: %.1024s", b.Error.GetCode(), b.Error.GetMessage())
	default:
		s.cfg.Metrics.ProtocolErrors.WithLabelValues("ctrl").Inc()
		return &ProtocolError{Msg: fmt.Sprintf("unexpected apply response %T", b)}
	}
	if applyErr != nil {
		s.log.Error("policy not applied; policy-bound containers fall back to their failure policy", "err", applyErr)
	}
	s.mu.Lock()
	s.applyErr = applyErr
	if applyErr == nil {
		s.appliedGen = gen
		s.appliedSet = set
	}
	lag := 0.0
	if applyErr != nil {
		lag = 1
	}
	s.mu.Unlock()
	s.cfg.Metrics.PolicyGenerationLag.WithLabelValues(s.metricLabels()...).Set(lag)
	return nil
}

func (s *Session) syncMode(ctx context.Context, cc *ctrlConn, r *channelv1.HelloReply) error {
	want := s.cfg.GlobalMode
	if want == channelv1.GlobalMode_GLOBAL_MODE_UNSPECIFIED {
		want = channelv1.GlobalMode_GLOBAL_MODE_NORMAL
	}
	have := r.GetGlobalMode()
	if have == channelv1.GlobalMode_GLOBAL_MODE_UNSPECIFIED {
		have = channelv1.GlobalMode_GLOBAL_MODE_NORMAL
	}
	if want == have {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	resp, err := cc.Call(rctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_SetMode{SetMode: &channelv1.SetMode{Mode: want}}})
	if err != nil {
		return fmt.Errorf("set mode: %w", err)
	}
	if a := resp.GetAck(); a == nil || !a.GetOk() {
		s.log.Error("guest did not accept global mode", "mode", want.String())
	}
	return nil
}

// policyUse counts containers per policy id, and reports whether set is the
// one in force on the guest.
func (s *Session) policyUse(set *policy.Set) (map[uint32]int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	use := map[uint32]int{}
	for _, c := range s.containers {
		if c.policy != 0 {
			use[c.policy]++
		}
	}
	return use, s.st == stateReady && s.appliedSet == set && s.applyErr == nil
}

// policies returns the current policy set.
func (s *Session) policies() *policy.Set {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

// setPolicies swaps the policy set; a ready session re-applies it on its own
// goroutine, a connecting one picks it up in its handshake.
func (s *Session) setPolicies(set *policy.Set) {
	s.mu.Lock()
	s.set = set
	s.mu.Unlock()
	select {
	case s.reload <- struct{}{}:
	default:
	}
}

// reapply pushes a changed policy set over a live channel: ApplyPolicy, the
// sandbox default, then every known container re-bound with its re-resolved
// policy. Policy ids are stable across reloads (policy.CompileWith), so
// between the ApplyPolicy and the re-binds an existing binding keeps its own
// policy's new rules, or becomes monitor-only if that policy was removed.
func (s *Session) reapply(ctx context.Context, cc *ctrlConn) error {
	if err := s.applyPolicy(ctx, cc, s.appliedGeneration(), 0); err != nil {
		return err
	}
	if err := s.syncSandboxDefault(ctx, cc); err != nil {
		return err
	}
	set := s.policies()
	s.mu.Lock()
	info := s.info
	rebind := make([]*boundContainer, 0, len(s.containers))
	changed := 0
	for _, c := range s.containers {
		m := set.Resolve(info.PodNamespace, info.PodLabels, c.Info.Name)
		var id uint32
		if m.Policy != nil {
			id = m.Policy.ID
		}
		if id != c.policy {
			changed++
		}
		c.Policy, c.policy = m.Policy, id
		rebind = append(rebind, c)
	}
	gen := s.appliedGen
	s.mu.Unlock()
	for _, c := range rebind {
		rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		err := s.sendBind(rctx, cc, c)
		cancel()
		if err != nil {
			s.log.Warn("re-bind after policy reload failed", "container", c.Info.ID, "err", err)
		}
	}
	s.log.Info("policy set reloaded", "generation", gen, "containers", len(rebind), "policy_changed", changed)
	return nil
}

// syncSandboxDefault installs (or clears) the guest's default entry for this
// pod's unbound container cgroups. It is sent on every connect, so it also
// replaces whatever a restarted guestd adopted. A guest that cannot install
// it does not fail the session: the NRI start gate still enforces Closed for
// every container vesta sees.
func (s *Session) syncSandboxDefault(ctx context.Context, cc *ctrlConn) error {
	mode, failure := s.policies().SandboxDefault(s.info.PodNamespace, s.info.PodLabels)
	parent := s.info.CgroupParent
	if parent == "" || len(parent) > maxCgroupParent {
		if failure == v1alpha1.FailureClosed {
			s.log.Warn("no usable pod cgroup parent from the runtime; unbound container cgroups are not covered by a sandbox default",
				"cgroup_parent_len", len(parent))
		}
		return nil
	}
	req := &channelv1.SetSandboxDefault{CgroupParent: parent, Mode: modeProto(mode), Failure: failureProto(failure)}
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	resp, err := cc.Call(rctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_SetSandboxDefault{SetSandboxDefault: req}})
	if err != nil {
		return fmt.Errorf("set sandbox default: %w", err)
	}
	switch b := resp.GetBody().(type) {
	case *channelv1.ControlResponse_Ack:
		if !b.Ack.GetOk() {
			s.log.Error("guest did not install the sandbox default", "failure", failure, "error", fmt.Sprintf("%.1024s", b.Ack.GetError()))
		} else if failure == v1alpha1.FailureClosed {
			s.log.Info("sandbox default installed: unbound container cgroups are denied exec and connect")
		}
	case *channelv1.ControlResponse_Error:
		s.log.Error("guest rejected the sandbox default", "failure", failure, "code", b.Error.GetCode().String(), "error", fmt.Sprintf("%.1024s", b.Error.GetMessage()))
	default:
		s.cfg.Metrics.ProtocolErrors.WithLabelValues("ctrl").Inc()
		return &ProtocolError{Msg: fmt.Sprintf("unexpected sandbox default response %T", b)}
	}
	return nil
}

// maxCgroupParent is SetSandboxDefault.cgroup_parent's limit.
const maxCgroupParent = 4096

func modeProto(m v1alpha1.Mode) channelv1.Mode {
	if m == v1alpha1.ModeEnforce {
		return channelv1.Mode_MODE_ENFORCE
	}
	return channelv1.Mode_MODE_AUDIT
}

func failureProto(f v1alpha1.FailurePolicy) channelv1.FailurePolicy {
	if f == v1alpha1.FailureClosed {
		return channelv1.FailurePolicy_FAILURE_POLICY_CLOSED
	}
	return channelv1.FailurePolicy_FAILURE_POLICY_OPEN
}

// Bind registers a container and, once the channel is ready, sends its
// BindContainer. It waits for readiness within ctx but not for the ack:
// the guest acks only after kata-agent has created the cgroup, which
// happens after the NRI CreateContainer hook returns. Use WaitBound for the
// ack.
func (s *Session) Bind(ctx context.Context, c Container) error {
	if !events.ValidContainerID(c.Info.ID) {
		return fmt.Errorf("invalid container id %q", c.Info.ID)
	}
	bc := &boundContainer{Container: c, done: make(chan struct{})}
	if c.Policy != nil {
		bc.policy = c.Policy.ID
	}
	s.mu.Lock()
	if old, ok := s.containers[c.Info.ID]; ok {
		old.finish(errors.New("superseded by a new bind"))
	}
	s.containers[c.Info.ID] = bc
	s.mu.Unlock()

	cc, err := s.waitReady(ctx)
	if err != nil {
		bc.finish(err)
		return err
	}
	if err := s.checkPolicyUsable(c.Policy); err != nil {
		bc.finish(err)
		return err
	}
	if err := s.sendBind(ctx, cc, bc); err != nil {
		bc.finish(err)
		return err
	}
	return nil
}

func (s *Session) checkPolicyUsable(p *policy.Policy) error {
	if p == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyErr != nil {
		return s.applyErr
	}
	if p.Bundle.GetMode() == channelv1.Mode_MODE_ENFORCE && (!s.features[FeatureEnforce] || !s.features[FeatureBPFLSM]) {
		return fmt.Errorf("%w: policy %s/%s enforces but the guest does not report %q and %q", ErrIneligible, p.Namespace, p.Name, FeatureEnforce, FeatureBPFLSM)
	}
	return nil
}

func (s *Session) waitReady(ctx context.Context) (*ctrlConn, error) {
	for {
		s.mu.Lock()
		st, cc, ch, ierr := s.st, s.ctrl, s.changed, s.ineligErr
		s.mu.Unlock()
		switch st {
		case stateReady:
			if cc != nil {
				return cc, nil
			}
		case stateIneligible:
			return nil, fmt.Errorf("%w: %w", ErrIneligible, ierr)
		case stateStopped:
			return nil, ErrStopped
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, fmt.Errorf("channel not ready: %w", ctx.Err())
		}
	}
}

// sendBind sends a BindContainer within ctx (an NRI hook's gate context must
// bound the write, not only the wait) and waits for the ack in the background.
func (s *Session) sendBind(ctx context.Context, cc *ctrlConn, bc *boundContainer) error {
	s.mu.Lock()
	gen, policyID := s.appliedGen, bc.policy
	s.mu.Unlock()
	id, ch, err := cc.Start(ctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_BindContainer{BindContainer: &channelv1.BindContainer{
		ContainerId: bc.Info.ID, CgroupPath: bc.CgroupPath, PolicyId: policyID,
		Rootfs: channelv1.RootfsType_ROOTFS_TYPE_UNKNOWN, Generation: gen,
	}}})
	if err != nil {
		return fmt.Errorf("send bind: %w", err)
	}
	go s.awaitBind(cc, id, ch, bc, gen)
	return nil
}

func (s *Session) awaitBind(cc *ctrlConn, id uint64, ch <-chan *channelv1.ControlResponse, bc *boundContainer, gen uint64) {
	t := time.NewTimer(s.cfg.BindTimeout)
	defer t.Stop()
	var err error
	select {
	case resp, ok := <-ch:
		switch {
		case !ok:
			err = errors.New("channel closed before bind ack")
		case resp.GetAck() != nil:
			a := resp.GetAck()
			if verr := validateAck(a); verr != nil {
				err = fmt.Errorf("bind ack: %w", verr)
			} else if !a.GetOk() {
				err = fmt.Errorf("guest refused bind: %s", a.GetError())
			} else if a.GetGeneration() != gen {
				err = fmt.Errorf("bind acked at generation %d, want %d", a.GetGeneration(), gen)
			}
		case resp.GetError() != nil:
			err = fmt.Errorf("guest refused bind: %s: %.1024s", resp.GetError().GetCode(), resp.GetError().GetMessage())
		default:
			err = errors.New("unexpected bind response")
		}
	case <-t.C:
		cc.forget(id)
		err = errors.New("bind not acked in time")
	case <-s.done:
		err = ErrStopped
	}
	s.mu.Lock()
	bc.bound = err == nil
	s.mu.Unlock()
	bc.finish(err)
	if err != nil {
		s.log.Warn("container bind failed", "container", bc.Info.ID, "err", err)
	}
}

// WaitBound waits for the container's bind ack within ctx.
func (s *Session) WaitBound(ctx context.Context, containerID string) error {
	s.mu.Lock()
	bc, ok := s.containers[containerID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("container %s was never bound", containerID)
	}
	select {
	case <-bc.done:
		return bc.err
	case <-ctx.Done():
		return fmt.Errorf("waiting for bind ack: %w", ctx.Err())
	}
}

// Unbind forgets a container and tells the guest, best effort. It never
// blocks: the request is sent from a goroutine bounded by RequestTimeout.
func (s *Session) Unbind(containerID string) {
	s.mu.Lock()
	bc, ok := s.containers[containerID]
	delete(s.containers, containerID)
	cc := s.ctrl
	s.mu.Unlock()
	if !ok {
		return
	}
	bc.finish(errors.New("container removed"))
	if cc == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
		defer cancel()
		id, ch, err := cc.Start(ctx, &channelv1.ControlRequest{Body: &channelv1.ControlRequest_Unbind{Unbind: &channelv1.Unbind{ContainerId: containerID}}})
		if err != nil {
			s.log.Debug("unbind not sent", "container", containerID, "err", err)
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			cc.forget(id)
		case <-s.done:
		}
	}()
}

// Container implements events.Lookup.
func (s *Session) Container(id string) (events.ContainerInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bc, ok := s.containers[id]
	if !ok {
		return events.ContainerInfo{}, false
	}
	return bc.Info, true
}

// Policy implements events.Lookup.
func (s *Session) Policy(generation uint64, id uint32) (events.PolicyInfo, bool) {
	s.mu.Lock()
	gen, set := s.appliedGen, s.appliedSet
	s.mu.Unlock()
	if generation != gen {
		return events.PolicyInfo{}, false
	}
	p, ok := set.ByID(id)
	if !ok {
		return events.PolicyInfo{}, false
	}
	return events.PolicyInfo{Name: p.Name, Namespace: p.Namespace, UID: p.UID}, true
}

func (s *Session) sandboxInfo() events.SandboxInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// checkHeartbeat updates the age gauge and raises the missing alert.
func (s *Session) checkHeartbeat(now time.Time) {
	s.mu.Lock()
	if s.st != stateReady {
		s.mu.Unlock()
		return
	}
	age, alert := s.hb.check(now)
	s.mu.Unlock()
	s.cfg.Metrics.HeartbeatAge.WithLabelValues(s.metricLabels()...).Set(age.Seconds())
	if alert != nil {
		s.alert(*alert)
	}
}

func (s *Session) alert(a Alert) {
	s.cfg.Metrics.TamperAlerts.WithLabelValues(a.Reason).Inc()
	now := time.Now()
	s.mu.Lock()
	st, ok := s.alertLog[a.Reason]
	if !ok {
		st = &alertLogState{}
		s.alertLog[a.Reason] = st
	}
	logIt := st.last.IsZero() || now.Sub(st.last) >= alertLogInterval
	suppressed := st.suppressed
	if logIt {
		st.last, st.suppressed = now, 0
	} else {
		st.suppressed++
	}
	s.mu.Unlock()
	if logIt {
		s.log.Error("vesta tamper alert", "reason", a.Reason, "detail", a.Detail, "suppressed_since_last", suppressed)
	}
}

func (s *Session) metricLabels() []string {
	return []string{s.info.PodNamespace, s.info.PodName, s.info.SandboxID}
}

func (s *Session) forgetMetrics() {
	s.cfg.Metrics.HeartbeatAge.DeleteLabelValues(s.metricLabels()...)
	s.cfg.Metrics.PolicyGenerationLag.DeleteLabelValues(s.metricLabels()...)
}

// nextGeneration picks the ApplyPolicy generation. An equal applied
// generation is a no-op on the guest (same policy set after a reconnect).
// An adopted generation equal to ours is applied again; a higher one came
// from a different policy set, so ours goes above it.
func nextGeneration(want, applied, adopted uint64) uint64 {
	switch {
	case applied > want:
		return applied + 1
	case applied == 0 && adopted > want:
		return adopted + 1
	}
	return want
}
