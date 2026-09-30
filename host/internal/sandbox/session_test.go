// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dbcrit/vesta/api/channel"
	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/transport"
	"github.com/dbcrit/vesta/host/internal/wire"
)

// fakeGuest plays vesta-guestd on both ports over net.Pipe.
type fakeGuest struct {
	t     *testing.T
	hello func() *channelv1.HelloReply
	// ackBind decides the reply to a bind; nil means never answer.
	ackBind func(*channelv1.BindContainer, uint64) *channelv1.ControlResponse
	// stall makes the guest stop reading CTRL after a bind until closed.
	stall chan struct{}

	mu       sync.Mutex
	applies  []*channelv1.ApplyPolicy
	binds    []*channelv1.BindContainer
	setModes []channelv1.GlobalMode
	defaults []*channelv1.SetSandboxDefault
	subs     []*channelv1.Subscribe
	ctrlDial int
	evt      chan *wire.Conn
}

func newFakeGuest(t *testing.T) *fakeGuest {
	return &fakeGuest{
		t: t,
		hello: func() *channelv1.HelloReply {
			return &channelv1.HelloReply{
				ProtoMajor: channel.ProtoMajor, ProtoMinor: channel.ProtoMinor, GuestImageVersion: "0.1.0",
				KernelRelease: "6.18.35", ActiveLsms: []string{"lockdown", "bpf"}, CgroupV2: true,
				Features: []string{FeatureExecAudit, FeatureExecLSM, FeatureBPFLSM}, AbiVersion: channel.ABIVersion,
				Progs: []*channelv1.ProgStatus{{Id: "P1", Attach: "tp/sched/sched_process_exec", State: channelv1.ProgState_PROG_STATE_ATTACHED, ProgId: 10, Tag: make([]byte, 8), LinkId: 3}},
			}
		},
		ackBind: func(b *channelv1.BindContainer, id uint64) *channelv1.ControlResponse {
			return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true, Generation: b.GetGeneration()}}}
		},
		evt: make(chan *wire.Conn, 4),
	}
}

func (g *fakeGuest) Dial(_ context.Context, port uint32) (net.Conn, error) {
	host, guest := net.Pipe()
	switch port {
	case channel.DefaultCtrlPort:
		g.mu.Lock()
		g.ctrlDial++
		g.mu.Unlock()
		go g.serveCtrl(wire.NewConn(guest, wire.Options{}))
	case channel.DefaultEvtPort:
		go g.serveEvt(wire.NewConn(guest, wire.Options{}))
	default:
		return nil, errors.New("no such port")
	}
	return host, nil
}

func (g *fakeGuest) serveCtrl(c *wire.Conn) {
	defer c.Close()
	for {
		var req channelv1.ControlRequest
		if err := c.Recv(&req, 0); err != nil {
			return
		}
		id := req.GetRequestId()
		var resp *channelv1.ControlResponse
		switch b := req.GetBody().(type) {
		case *channelv1.ControlRequest_Hello:
			resp = &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_HelloReply{HelloReply: g.hello()}}
		case *channelv1.ControlRequest_ApplyPolicy:
			g.mu.Lock()
			g.applies = append(g.applies, b.ApplyPolicy)
			g.mu.Unlock()
			resp = &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true, Generation: b.ApplyPolicy.GetGeneration()}}}
		case *channelv1.ControlRequest_BindContainer:
			g.mu.Lock()
			g.binds = append(g.binds, b.BindContainer)
			g.mu.Unlock()
			if g.stall != nil {
				<-g.stall
				return
			}
			if g.ackBind != nil {
				resp = g.ackBind(b.BindContainer, id)
			}
		case *channelv1.ControlRequest_SetSandboxDefault:
			g.mu.Lock()
			g.defaults = append(g.defaults, b.SetSandboxDefault)
			g.mu.Unlock()
			resp = &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true}}}
		case *channelv1.ControlRequest_SetMode:
			g.mu.Lock()
			g.setModes = append(g.setModes, b.SetMode.GetMode())
			g.mu.Unlock()
			resp = &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true}}}
		default:
			resp = &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true}}}
		}
		if resp != nil {
			if err := c.Send(resp); err != nil {
				return
			}
		}
	}
}

func (g *fakeGuest) serveEvt(c *wire.Conn) {
	var m channelv1.EventStreamMessage
	if err := c.Recv(&m, time.Second); err != nil || m.GetSubscribe() == nil {
		c.Close()
		return
	}
	g.mu.Lock()
	g.subs = append(g.subs, m.GetSubscribe())
	g.mu.Unlock()
	g.evt <- c
}

type captureExporter struct {
	mu   sync.Mutex
	recs []events.Record
}

func (c *captureExporter) Export(r events.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
	return nil
}
func (c *captureExporter) Flush() error { return nil }
func (c *captureExporter) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.recs)
}

type harness struct {
	reg  *Registry
	m    *metrics.Metrics
	g    *fakeGuest
	exp  *captureExporter
	stop func()
}

func newHarness(t *testing.T, g *fakeGuest, set *policy.Set, mode channelv1.GlobalMode) *harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	exp := &captureExporter{}
	pl := events.NewPipeline(events.PipelineConfig{FlushInterval: 10 * time.Millisecond}, exp, m, log)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); pl.Run(ctx) }()
	if set == nil {
		var err error
		if set, err = policy.Compile(nil, 100); err != nil {
			t.Fatal(err)
		}
	}
	reg := NewRegistry(ctx, Config{
		Node: "node1", AgentVersion: "0.1.0", GlobalMode: mode,
		Discover: func(context.Context, string) (transport.Endpoint, error) {
			return transport.Endpoint{Kind: transport.KindVsock, CID: 3}, nil
		},
		DialerFor:  func(transport.Endpoint) (transport.Dialer, error) { return g, nil },
		BackoffMin: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
		RequestTimeout: time.Second, BindTimeout: 200 * time.Millisecond,
		Metrics: m, Log: log, Pipeline: pl,
	}, set)
	h := &harness{reg: reg, m: m, g: g, exp: exp}
	h.stop = func() {
		reg.Close()
		cancel()
		wg.Wait()
	}
	t.Cleanup(h.stop)
	return h
}

func info() events.SandboxInfo {
	return events.SandboxInfo{SandboxID: "sb1", PodName: "pod", PodNamespace: "ns", PodUID: "uid", RuntimeHandler: "kata-qemu-vesta"}
}

func container(id string, p *policy.Policy) Container {
	return Container{Info: events.ContainerInfo{ID: id, Name: "app", Image: "img"}, CgroupPath: "kubepods.slice:cri-containerd:" + id, Policy: p}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSessionBindAndWait(t *testing.T) {
	pols, _ := policy.Parse([]byte("apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p, namespace: ns}\nspec: {selector: {}}"))
	set, err := policy.Compile(pols, 100)
	if err != nil {
		t.Fatal(err)
	}
	g := newFakeGuest(t)
	h := newHarness(t, g, set, channelv1.GlobalMode_GLOBAL_MODE_NORMAL)
	s, ok := h.reg.Ensure(info())
	if !ok {
		t.Fatal("ensure failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", set.Policies[0])); err != nil {
		t.Fatal(err)
	}
	if err := s.WaitBound(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.applies) != 1 || g.applies[0].GetGeneration() != 100 || len(g.applies[0].GetBundles()) != 1 {
		t.Fatalf("applies %v", g.applies)
	}
	b := g.binds[0]
	if b.GetContainerId() != "c1" || b.GetPolicyId() != 1 || b.GetGeneration() != 100 || b.GetCgroupPath() != "kubepods.slice:cri-containerd:c1" {
		t.Fatalf("bind %v", b)
	}
	if len(g.setModes) != 0 {
		t.Fatalf("unexpected SetMode %v", g.setModes)
	}
	if s.State() != metrics.StateMonitored {
		t.Fatalf("state %s", s.State())
	}
}

func TestSessionBindFailures(t *testing.T) {
	g := newFakeGuest(t)
	g.ackBind = func(b *channelv1.BindContainer, id uint64) *channelv1.ControlResponse {
		switch b.GetContainerId() {
		case "refused":
			return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: false, Error: "no cgroup"}}}
		case "error":
			return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Error{Error: &channelv1.Error{Code: channelv1.ErrorCode_ERROR_CODE_NOT_FOUND}}}
		case "wronggen":
			return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true, Generation: 1}}}
		}
		return nil // "silent": never acked
	}
	h := newHarness(t, g, nil, 0)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, id := range []string{"refused", "error", "wronggen", "silent"} {
		if err := s.Bind(ctx, container(id, nil)); err != nil {
			t.Fatalf("%s: bind send: %v", id, err)
		}
		if err := s.WaitBound(ctx, id); err == nil {
			t.Errorf("%s: WaitBound succeeded", id)
		}
	}
	if err := s.WaitBound(ctx, "never-bound"); err == nil {
		t.Error("WaitBound on an unknown container succeeded")
	}
	if err := s.Bind(ctx, container("bad/id", nil)); err == nil {
		t.Error("invalid container id accepted")
	}
}

func TestSessionIneligible(t *testing.T) {
	tests := map[string]func(*channelv1.HelloReply){
		"cgroup v1":   func(r *channelv1.HelloReply) { r.CgroupV2 = false },
		"abi":         func(r *channelv1.HelloReply) { r.AbiVersion = 99 },
		"proto major": func(r *channelv1.HelloReply) { r.ProtoMajor = 7 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			g := newFakeGuest(t)
			base := g.hello
			g.hello = func() *channelv1.HelloReply { r := base(); mutate(r); return r }
			h := newHarness(t, g, nil, 0)
			s, _ := h.reg.Ensure(info())
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := s.Bind(ctx, container("c1", nil))
			if !errors.Is(err, ErrIneligible) {
				t.Fatalf("err = %v, want ErrIneligible", err)
			}
			if s.State() != metrics.StateIneligible {
				t.Fatalf("state %s", s.State())
			}
		})
	}
}

func TestSessionEnforceNeedsGuestSupport(t *testing.T) {
	pols, _ := policy.Parse([]byte("apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p, namespace: ns}\nspec: {selector: {}, mode: Enforce}"))
	set, err := policy.Compile(pols, 100)
	if err != nil {
		t.Fatal(err)
	}
	if set.Policies[0].Mode != v1alpha1.ModeEnforce {
		t.Fatal("policy not enforce")
	}
	g := newFakeGuest(t) // no "enforce" feature
	h := newHarness(t, g, set, 0)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", set.Policies[0])); !errors.Is(err, ErrIneligible) {
		t.Fatalf("err = %v, want ErrIneligible", err)
	}
	if err := s.Bind(ctx, container("c2", nil)); err != nil {
		t.Fatalf("monitor-only bind failed: %v", err)
	}
}

func TestSessionSandboxDefault(t *testing.T) {
	const doc = "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p, namespace: ns}\nspec: {selector: {matchLabels: {app: web}}, mode: Enforce, failurePolicy: %s}"
	for _, tc := range []struct {
		name    string
		failure string
		labels  map[string]string
		parent  string
		want    channelv1.FailurePolicy // UNSPECIFIED = nothing sent
		mode    channelv1.Mode
	}{
		{"closed enforce policy selects the pod", "Closed", map[string]string{"app": "web"}, "kubepods-pod1.slice",
			channelv1.FailurePolicy_FAILURE_POLICY_CLOSED, channelv1.Mode_MODE_ENFORCE},
		{"open policy", "Open", map[string]string{"app": "web"}, "kubepods-pod1.slice",
			channelv1.FailurePolicy_FAILURE_POLICY_OPEN, channelv1.Mode_MODE_AUDIT},
		{"closed policy does not select the pod", "Closed", map[string]string{"app": "db"}, "kubepods-pod1.slice",
			channelv1.FailurePolicy_FAILURE_POLICY_OPEN, channelv1.Mode_MODE_AUDIT},
		{"no cgroup parent from the runtime", "Closed", map[string]string{"app": "web"}, "",
			channelv1.FailurePolicy_FAILURE_POLICY_UNSPECIFIED, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pols, err := policy.Parse([]byte(fmt.Sprintf(doc, tc.failure)))
			if err != nil {
				t.Fatal(err)
			}
			set, err := policy.Compile(pols, 100)
			if err != nil {
				t.Fatal(err)
			}
			g := newFakeGuest(t)
			base := g.hello
			g.hello = func() *channelv1.HelloReply { r := base(); r.Features = append(r.Features, "enforce"); return r }
			g.ackBind = func(b *channelv1.BindContainer, id uint64) *channelv1.ControlResponse {
				return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true, Generation: b.GetGeneration()}}}
			}
			h := newHarness(t, g, set, channelv1.GlobalMode_GLOBAL_MODE_NORMAL)
			in := info()
			in.PodLabels, in.CgroupParent = tc.labels, tc.parent
			s, _ := h.reg.Ensure(in)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.Bind(ctx, container("c1", nil)); err != nil {
				t.Fatal(err)
			}
			if err := s.WaitBound(ctx, "c1"); err != nil {
				t.Fatal(err)
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			if tc.want == channelv1.FailurePolicy_FAILURE_POLICY_UNSPECIFIED {
				if len(g.defaults) != 0 {
					t.Fatalf("sent %v without a cgroup parent", g.defaults)
				}
				return
			}
			if len(g.defaults) != 1 {
				t.Fatalf("sandbox defaults sent: %d", len(g.defaults))
			}
			d := g.defaults[0]
			if d.GetFailure() != tc.want || d.GetMode() != tc.mode || d.GetCgroupParent() != tc.parent {
				t.Fatalf("got %v", d)
			}
		})
	}
}

func TestSessionGenerationFollowsGuest(t *testing.T) {
	g := newFakeGuest(t)
	base := g.hello
	g.hello = func() *channelv1.HelloReply { r := base(); r.AppliedGeneration = 500; return r }
	h := newHarness(t, g, nil, channelv1.GlobalMode_GLOBAL_MODE_AUDIT_ONLY)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", nil)); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.applies[0].GetGeneration() != 501 {
		t.Fatalf("generation %d, want 501", g.applies[0].GetGeneration())
	}
	if len(g.setModes) != 1 || g.setModes[0] != channelv1.GlobalMode_GLOBAL_MODE_AUDIT_ONLY {
		t.Fatalf("SetMode %v", g.setModes)
	}
}

func TestSessionGenerationAboveAdopted(t *testing.T) {
	g := newFakeGuest(t)
	base := g.hello
	g.hello = func() *channelv1.HelloReply { r := base(); r.AdoptedGeneration = 700; return r }
	h := newHarness(t, g, nil, channelv1.GlobalMode_GLOBAL_MODE_NORMAL)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", nil)); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if got := g.applies[0].GetGeneration(); got != 701 {
		t.Fatalf("generation %d, want 701", got)
	}
}

func TestNextGeneration(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		want, applied, adopted uint64
		out                    uint64
	}{
		{"fresh guest", 10, 0, 0, 10},
		{"reconnect, same set", 10, 10, 0, 10},
		{"guest ahead", 10, 12, 0, 13},
		{"agent ahead", 10, 5, 0, 10},
		{"restarted guestd, same set", 10, 0, 10, 10},
		{"restarted guestd, older agent clock", 10, 0, 40, 41},
		{"restarted guestd, newer agent", 50, 0, 40, 50},
		{"applied wins over adopted", 10, 12, 40, 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextGeneration(tc.want, tc.applied, tc.adopted); got != tc.out {
				t.Fatalf("nextGeneration(%d, %d, %d) = %d, want %d", tc.want, tc.applied, tc.adopted, got, tc.out)
			}
		})
	}
}

func batch(seqs ...uint64) *channelv1.EventStreamMessage {
	b := &channelv1.EventBatch{FirstSeq: seqs[0]}
	for _, s := range seqs {
		b.Events = append(b.Events, &eventv1.Event{
			Seq: s, Type: eventv1.EventType_EVENT_TYPE_EXEC, Action: eventv1.Action_ACTION_AUDITED,
			ContainerId: "c1", Process: &eventv1.Process{Comm: "sh"}, Detail: &eventv1.Event_Exec{Exec: &eventv1.Exec{}},
			Host: &eventv1.Host{PodName: "forged"},
		})
	}
	return &channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_EventBatch{EventBatch: b}}
}

func recvAck(t *testing.T, c *wire.Conn) uint64 {
	t.Helper()
	var m channelv1.EventStreamMessage
	if err := c.Recv(&m, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if m.GetEventAck() == nil {
		t.Fatalf("expected ack, got %v", &m)
	}
	return m.GetEventAck().GetAckedSeq()
}

func TestSessionEventStream(t *testing.T) {
	g := newFakeGuest(t)
	h := newHarness(t, g, nil, 0)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", nil)); err != nil {
		t.Fatal(err)
	}
	var evt *wire.Conn
	select {
	case evt = <-g.evt:
	case <-ctx.Done():
		t.Fatal("no EVT subscription")
	}
	g.mu.Lock()
	if sub := g.subs[0]; sub.GetFromSeq() != 0 || sub.GetProtoMajor() != channel.ProtoMajor {
		t.Fatalf("subscribe %v", sub)
	}
	g.mu.Unlock()

	bad := batch(1, 2)
	bad.GetEventBatch().Events[1].Type = 99 // invalid, dropped
	if err := evt.Send(bad); err != nil {
		t.Fatal(err)
	}
	if got := recvAck(t, evt); got != 2 {
		t.Fatalf("ack %d", got)
	}
	// Seq 3 and 4 were evicted by the guest: a gap of 2.
	if err := evt.Send(batch(5)); err != nil {
		t.Fatal(err)
	}
	if got := recvAck(t, evt); got != 5 {
		t.Fatalf("ack %d", got)
	}
	waitFor(t, "export", func() bool { return h.exp.len() == 2 })
	h.exp.mu.Lock()
	r := h.exp.recs[0]
	h.exp.mu.Unlock()
	if r.Event.GetHost().GetPodName() != "pod" || r.ContainerID != "c1" || r.Event.GetHost().GetContainerName() != "app" {
		t.Fatalf("enrichment: %v %+v", r.Event.GetHost(), r)
	}
	if got := testutil.ToFloat64(h.m.EventSeqGaps); got != 2 {
		t.Fatalf("gaps %v", got)
	}
	if got := testutil.ToFloat64(h.m.EventsDropped.WithLabelValues(events.DropInvalid)); got != 1 {
		t.Fatalf("invalid drops %v", got)
	}

	// A structurally broken batch closes the stream; the session
	// resubscribes from the last seen seq.
	broken := batch(7, 6)
	if err := evt.Send(broken); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.evt:
	case <-time.After(3 * time.Second):
		t.Fatal("no resubscribe after protocol error")
	}
	g.mu.Lock()
	last := g.subs[len(g.subs)-1]
	g.mu.Unlock()
	if last.GetFromSeq() != 6 {
		t.Fatalf("resubscribed from %d, want 6", last.GetFromSeq())
	}
	if testutil.ToFloat64(h.m.ProtocolErrors.WithLabelValues("evt")) < 1 {
		t.Fatal("protocol error not counted")
	}
}

func TestSessionRejectsWrongDirectionMessages(t *testing.T) {
	g := newFakeGuest(t)
	h := newHarness(t, g, nil, 0)
	h.reg.Ensure(info())
	evt := <-g.evt
	if err := evt.Send(&channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_Subscribe{Subscribe: &channelv1.Subscribe{}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.evt:
	case <-time.After(3 * time.Second):
		t.Fatal("stream not re-established after a wrong-direction message")
	}
	if testutil.ToFloat64(h.m.ProtocolErrors.WithLabelValues("evt")) < 1 {
		t.Fatal("protocol error not counted")
	}
}

func TestSessionHeartbeatAlerts(t *testing.T) {
	g := newFakeGuest(t)
	h := newHarness(t, g, nil, 0)
	s, _ := h.reg.Ensure(info())
	evt := <-g.evt
	hb := func(seq uint64, tagByte byte) *channelv1.EventStreamMessage {
		tag := make([]byte, 8)
		tag[0] = tagByte
		return &channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_Heartbeat{Heartbeat: &channelv1.Heartbeat{
			Seq: seq, IntervalMs: 1000, AppliedGeneration: 100,
			Progs:        []*channelv1.ProgStatus{{Id: "P1", State: channelv1.ProgState_PROG_STATE_ATTACHED, ProgId: 10, Tag: tag, LinkId: 3}},
			RingbufDrops: []*channelv1.DropCount{{EventType: 1, Count: 4}}, ChannelDrops: 2,
		}}}
	}
	for _, m := range []*channelv1.EventStreamMessage{hb(1, 0), hb(3, 0), hb(4, 9)} {
		if err := evt.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "alerts", func() bool {
		return testutil.ToFloat64(h.m.TamperAlerts.WithLabelValues(AlertProgramChanged)) == 1 &&
			testutil.ToFloat64(h.m.TamperAlerts.WithLabelValues(AlertHeartbeatSeqGap)) == 1
	})
	if got := testutil.ToFloat64(h.m.RingbufDrops.WithLabelValues("exec")); got != 4 {
		t.Fatalf("ringbuf drops %v", got)
	}
	if got := testutil.ToFloat64(h.m.ChannelDrops); got != 2 {
		t.Fatalf("channel drops %v", got)
	}
	// Missing heartbeat: 2 x 1s interval.
	s.checkHeartbeat(time.Now().Add(3 * time.Second))
	if testutil.ToFloat64(h.m.TamperAlerts.WithLabelValues(AlertHeartbeatMissing)) != 1 {
		t.Fatal("missing heartbeat not alerted")
	}
	if s.State() != metrics.StateUnmonitored {
		t.Fatalf("state %s", s.State())
	}
}

func TestRegistryRejectsBadSandboxID(t *testing.T) {
	h := newHarness(t, newFakeGuest(t), nil, 0)
	if _, ok := h.reg.Ensure(events.SandboxInfo{SandboxID: "../x"}); ok {
		t.Fatal("invalid sandbox id accepted")
	}
}

func TestRegistryRemoveStopsSession(t *testing.T) {
	g := newFakeGuest(t)
	g.ackBind = nil
	h := newHarness(t, g, nil, 0)
	s, _ := h.reg.Ensure(info())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", nil)); err != nil {
		t.Fatal(err)
	}
	h.reg.Remove("sb1")
	if err := s.WaitBound(ctx, "c1"); err == nil {
		t.Fatal("bind still pending after remove")
	}
	if _, ok := h.reg.Get("sb1"); ok {
		t.Fatal("session still registered")
	}
	if err := s.Bind(ctx, container("c2", nil)); !errors.Is(err, ErrStopped) {
		t.Fatalf("bind after stop: %v", err)
	}
}

// A guest that stops reading must not stall NRI hooks beyond their gate
// context (NRI kills plugins at its 2 s request timeout).
func TestSessionStalledGuestDoesNotBlockHooks(t *testing.T) {
	g := newFakeGuest(t)
	g.stall = make(chan struct{})
	defer close(g.stall)
	h := newHarness(t, g, nil, 0)
	s, _ := h.reg.Ensure(info())
	// Bind only once connected, or the connect-time rebind would stall first.
	waitFor(t, "channel ready", func() bool { return s.State() == metrics.StateMonitored })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", nil)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"c2", "c3"} {
		gctx, gcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		_ = s.Bind(gctx, container(id, nil))
		gcancel()
		if d := time.Since(start); d > time.Second {
			t.Fatalf("bind %s blocked for %s behind a stalled guest", id, d)
		}
	}
	start := time.Now()
	s.Unbind("c1")
	h.reg.Remove("sb1")
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("unbind+remove blocked for %s", d)
	}
}

func TestSessionAlertLogIsRateLimited(t *testing.T) {
	h := newHarness(t, newFakeGuest(t), nil, 0)
	s, _ := h.reg.Ensure(info())
	for range 100 {
		s.alert(Alert{AlertProgramAdded, "x"})
	}
	if got := testutil.ToFloat64(h.m.TamperAlerts.WithLabelValues(AlertProgramAdded)); got != 100 {
		t.Fatalf("alerts counted %v, want 100", got)
	}
	s.mu.Lock()
	st := s.alertLog[AlertProgramAdded]
	s.mu.Unlock()
	if st == nil || st.suppressed != 99 {
		t.Fatalf("log state %+v, want 99 suppressed", st)
	}
}

func TestSessionPolicyReload(t *testing.T) {
	parse := func(doc string) []v1alpha1.VestaPolicy {
		pols, err := policy.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return pols
	}
	const podWide = "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: pod-wide, namespace: ns}\nspec: {selector: {}}\n"
	const appOnly = "---\napiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: a-app-only, namespace: ns}\nspec: {selector: {}, containerSelector: {names: [app]}}\n"
	set1, err := policy.Compile(parse(podWide), 100)
	if err != nil {
		t.Fatal(err)
	}
	g := newFakeGuest(t)
	g.ackBind = func(b *channelv1.BindContainer, id uint64) *channelv1.ControlResponse {
		return &channelv1.ControlResponse{RequestId: id, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{Ok: true, Generation: b.GetGeneration()}}}
	}
	h := newHarness(t, g, set1, channelv1.GlobalMode_GLOBAL_MODE_NORMAL)
	in := info()
	in.CgroupParent = "kubepods-pod1.slice"
	s, _ := h.reg.Ensure(in)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Bind(ctx, container("c1", set1.Policies[0])); err != nil {
		t.Fatal(err)
	}
	if err := s.WaitBound(ctx, "c1"); err != nil {
		t.Fatal(err)
	}

	// "a-app-only" sorts before "pod-wide" but must not take its id, and it
	// is more specific for container "app", so c1 moves to it.
	set2, rej, err := policy.CompileWith(parse(podWide+appOnly), 200, set1)
	if err != nil || len(rej) != 0 {
		t.Fatal(err, rej)
	}
	h.reg.SetPolicies(set2)
	if h.reg.Policies() != set2 {
		t.Fatal("registry did not swap the set")
	}
	appID := set2.Policies[0].ID
	if set2.Policies[0].Name != "a-app-only" || appID == set1.Policies[0].ID {
		t.Fatalf("ids: %v", set2.Policies)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		applies, binds, defaults := len(g.applies), append([]*channelv1.BindContainer(nil), g.binds...), len(g.defaults)
		var lastGen uint64
		if applies > 0 {
			lastGen = g.applies[applies-1].GetGeneration()
		}
		g.mu.Unlock()
		last := binds[len(binds)-1]
		if applies == 2 && lastGen == 200 && last.GetPolicyId() == appID && last.GetGeneration() == 200 && defaults == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after reload: applies=%d gen=%d last bind=%v defaults=%d", applies, lastGen, last, defaults)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pi, ok := s.Policy(200, appID); !ok || pi.Name != "a-app-only" {
		t.Fatalf("event enrichment lookup %v %v", pi, ok)
	}
	if _, ok := s.Policy(100, appID); ok {
		t.Fatal("stale generation must not resolve")
	}
}
