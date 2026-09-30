// SPDX-License-Identifier: Apache-2.0

// Package nriplugin is vesta-agent's NRI plugin (ARCHITECTURE §2.2, §2.9).
// It acts only on pods whose runtime handler is a vesta handler and returns
// immediately for every other pod. Every wait is bounded well below the NRI
// plugin request timeout (2 s by default), because NRI serializes all plugin
// calls node-wide.
package nriplugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	nriplugin "github.com/containerd/nri/pkg/plugin"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
)

// maxCgroupPath is BindContainer.cgroup_path's limit.
const maxCgroupPath = 4096

// resyncBindTimeout bounds binds issued for containers found at Synchronize.
const resyncBindTimeout = 30 * time.Second

// Sandbox is the per-sandbox channel as the plugin uses it.
type Sandbox interface {
	Bind(ctx context.Context, c sandbox.Container) error
	WaitBound(ctx context.Context, containerID string) error
	Unbind(containerID string)
}

// Manager is the sandbox registry as the plugin uses it.
type Manager interface {
	Ensure(info events.SandboxInfo) (Sandbox, bool)
	Get(id string) (Sandbox, bool)
	Remove(id string)
	Retain(keep map[string]bool)
	Policies() *policy.Set
}

// Config configures the plugin.
type Config struct {
	// Handlers are the runtime handlers vesta acts on.
	Handlers []string
	// GateTimeout bounds each hook's wait. It must stay below the NRI
	// plugin request timeout.
	GateTimeout time.Duration
	// DefaultFailure applies to containers no policy selects.
	DefaultFailure v1alpha1.FailurePolicy
	// PluginName is this plugin's NRI name, as listed in the
	// required-plugins annotation.
	PluginName string
}

type ctrState struct {
	podID       string
	failure     v1alpha1.FailurePolicy
	unmonitored bool
}

// Plugin implements the NRI stub interfaces it needs.
type Plugin struct {
	cfg      Config
	handlers map[string]bool
	mgr      Manager
	m        *metrics.Metrics
	log      *slog.Logger

	configured atomic.Bool

	mu     sync.Mutex
	ctrs   map[string]*ctrState
	warned map[string]bool // pods warned about a missing required-plugins annotation
}

// New returns a plugin.
func New(cfg Config, mgr Manager, m *metrics.Metrics, log *slog.Logger) (*Plugin, error) {
	if len(cfg.Handlers) == 0 {
		return nil, errors.New("no vesta runtime handlers configured")
	}
	if cfg.GateTimeout <= 0 {
		cfg.GateTimeout = 1500 * time.Millisecond
	}
	switch cfg.DefaultFailure {
	case "":
		cfg.DefaultFailure = v1alpha1.FailureOpen
	case v1alpha1.FailureOpen, v1alpha1.FailureClosed:
	default:
		return nil, fmt.Errorf("default failure policy %q: want Open or Closed", cfg.DefaultFailure)
	}
	h := make(map[string]bool, len(cfg.Handlers))
	for _, n := range cfg.Handlers {
		h[n] = true
	}
	if cfg.PluginName == "" {
		cfg.PluginName = "vesta"
	}
	return &Plugin{cfg: cfg, handlers: h, mgr: mgr, m: m, log: log, ctrs: make(map[string]*ctrState), warned: make(map[string]bool)}, nil
}

// Registered reports whether the runtime has configured the plugin on the
// current connection.
func (p *Plugin) Registered() bool { return p.configured.Load() }

func (p *Plugin) setRegistered(v bool) {
	p.configured.Store(v)
	if v {
		p.m.NRIConnected.Set(1)
	} else {
		p.m.NRIConnected.Set(0)
	}
}

func (p *Plugin) isVesta(pod *api.PodSandbox) bool {
	return pod != nil && p.handlers[pod.GetRuntimeHandler()]
}

func sandboxInfo(pod *api.PodSandbox) events.SandboxInfo {
	return events.SandboxInfo{
		SandboxID:      pod.GetId(),
		PodName:        pod.GetName(),
		PodNamespace:   pod.GetNamespace(),
		PodUID:         pod.GetUid(),
		RuntimeHandler: pod.GetRuntimeHandler(),
		PodLabels:      pod.GetLabels(),
		CgroupParent:   pod.GetLinux().GetCgroupParent(),
	}
}

// Configure implements stub.ConfigureInterface.
func (p *Plugin) Configure(_ context.Context, _, runtime, version string) (api.EventMask, error) {
	p.log.Info("NRI plugin configured", "runtime", runtime, "runtime_version", version)
	p.setRegistered(true)
	return 0, nil
}

// Synchronize implements stub.SynchronizeInterface. It runs on every
// (re)connection to the runtime, including after an agent or containerd
// restart, and rebuilds the registry from the runtime's view.
func (p *Plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	keep := make(map[string]bool)
	byID := make(map[string]*api.PodSandbox)
	for _, pod := range pods {
		if !p.isVesta(pod) {
			continue
		}
		if _, ok := p.mgr.Ensure(sandboxInfo(pod)); !ok {
			p.log.Warn("ignoring vesta pod with invalid sandbox id", "namespace", pod.GetNamespace(), "pod", pod.GetName())
			continue
		}
		keep[pod.GetId()] = true
		byID[pod.GetId()] = pod
	}
	p.mgr.Retain(keep)

	p.mu.Lock()
	for id, st := range p.ctrs {
		if !keep[st.podID] {
			delete(p.ctrs, id)
		}
	}
	p.mu.Unlock()

	n := 0
	for _, ctr := range ctrs {
		pod, ok := byID[ctr.GetPodSandboxId()]
		if !ok {
			continue
		}
		switch ctr.GetState() {
		case api.ContainerState_CONTAINER_CREATED, api.ContainerState_CONTAINER_RUNNING, api.ContainerState_CONTAINER_PAUSED:
		default:
			continue
		}
		sb, ok := p.mgr.Get(pod.GetId())
		if !ok {
			continue
		}
		c, failure, err := p.containerSpec(pod, ctr)
		if err != nil {
			p.log.Warn("cannot bind existing container", "container", ctr.GetId(), "err", err)
			continue
		}
		p.remember(ctr.GetId(), pod.GetId(), failure, false)
		n++
		// Running containers are not gated; bind them in the background so
		// Synchronize returns promptly.
		go func() {
			// Outlives the Synchronize call, so not cancelled with it.
			bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resyncBindTimeout)
			defer cancel()
			if err := sb.Bind(bctx, c); err != nil {
				p.log.Warn("rebind of existing container failed", "container", c.Info.ID, "err", err)
			}
		}()
	}
	p.log.Info("synchronized with runtime", "vesta_pods", len(keep), "vesta_containers", n)
	return nil, nil
}

// Shutdown implements stub.ShutdownInterface.
func (p *Plugin) Shutdown(context.Context) {
	p.log.Info("runtime is shutting down NRI plugin")
	p.setRegistered(false)
}

// RunPodSandbox implements stub.RunPodInterface. The VM is already running
// at this point; the session connects asynchronously so the hook returns at
// once.
func (p *Plugin) RunPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	if !p.isVesta(pod) {
		return nil
	}
	if _, ok := p.mgr.Ensure(sandboxInfo(pod)); !ok {
		p.log.Warn("vesta pod has an invalid sandbox id; not monitored", "namespace", pod.GetNamespace(), "pod", pod.GetName())
		return nil
	}
	p.log.Info("vesta sandbox started", "sandbox", pod.GetId(), "namespace", pod.GetNamespace(), "pod", pod.GetName())
	return nil
}

// StopPodSandbox implements stub.StopPodInterface.
func (p *Plugin) StopPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	if p.isVesta(pod) {
		p.forgetPod(pod.GetId())
	}
	return nil
}

// RemovePodSandbox implements stub.RemovePodInterface.
func (p *Plugin) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error {
	if p.isVesta(pod) {
		p.forgetPod(pod.GetId())
	}
	return nil
}

func (p *Plugin) forgetPod(id string) {
	p.mgr.Remove(id)
	p.mu.Lock()
	delete(p.warned, id)
	for cid, st := range p.ctrs {
		if st.podID == id {
			delete(p.ctrs, cid)
		}
	}
	p.mu.Unlock()
}

func (p *Plugin) containerSpec(pod *api.PodSandbox, ctr *api.Container) (sandbox.Container, v1alpha1.FailurePolicy, error) {
	failure := p.cfg.DefaultFailure
	match := p.mgr.Policies().Resolve(pod.GetNamespace(), pod.GetLabels(), ctr.GetName())
	if match.Policy != nil {
		failure = match.Policy.Failure
	}
	if match.Conflicts > 0 {
		p.log.Warn("several policies select this container; using the most specific",
			"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(),
			"policy", match.Policy.Name, "ignored", match.Conflicts)
	}
	cg := ctr.GetLinux().GetCgroupsPath()
	if len(cg) > maxCgroupPath {
		return sandbox.Container{}, failure, fmt.Errorf("cgroups path of %d bytes exceeds %d", len(cg), maxCgroupPath)
	}
	if !events.ValidContainerID(ctr.GetId()) {
		return sandbox.Container{}, failure, fmt.Errorf("invalid container id %q", ctr.GetId())
	}
	return sandbox.Container{
		Info: events.ContainerInfo{
			ID: ctr.GetId(), Name: ctr.GetName(),
			Image: ctr.GetImage().GetName(), ImageDigest: ctr.GetImage().GetDigest(),
		},
		CgroupPath: cg,
		Policy:     match.Policy,
	}, failure, nil
}

func (p *Plugin) remember(ctrID, podID string, f v1alpha1.FailurePolicy, unmonitored bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctrs[ctrID] = &ctrState{podID: podID, failure: f, unmonitored: unmonitored}
}

// gate applies the failure policy to err (ARCHITECTURE §2.9): Closed fails
// the CRI call, Open lets the container run unmonitored.
func (p *Plugin) gate(hook string, pod *api.PodSandbox, ctr *api.Container, failure v1alpha1.FailurePolicy, err error) error {
	if failure == v1alpha1.FailureClosed {
		p.m.GateDecisions.WithLabelValues(hook, "denied").Inc()
		p.log.Error("blocking container: vesta policy not confirmed (failurePolicy Closed)",
			"hook", hook, "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "err", err)
		return fmt.Errorf("vesta: policy for container %s not confirmed (failurePolicy Closed): %w", ctr.GetName(), err)
	}
	p.m.GateDecisions.WithLabelValues(hook, "unmonitored").Inc()
	p.log.Warn("container runs unmonitored: vesta policy not confirmed (failurePolicy Open)",
		"hook", hook, "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "err", err)
	p.mu.Lock()
	if st, ok := p.ctrs[ctr.GetId()]; ok {
		st.unmonitored = true
	}
	p.mu.Unlock()
	return nil
}

// RequiresPlugin reports whether the pod's NRI required-plugins annotation
// (pod- or container-scoped) lists name. With containerd's NRI default
// validator enabled, such a container cannot be created while the plugin is
// not registered.
func RequiresPlugin(pod *api.PodSandbox, container, name string) bool {
	v, ok := nriplugin.GetEffectiveAnnotation(pod, nriplugin.RequiredPluginsAnnotation, container)
	if !ok {
		return false
	}
	var names []string
	if err := yaml.Unmarshal([]byte(v), &names); err != nil {
		return false
	}
	return slices.Contains(names, name)
}

// warnUnrequired logs, once per pod, that a Closed policy is enforced only
// while this plugin is registered: NRI skips unregistered plugins, so an
// agent restart would let the container start ungated.
func (p *Plugin) warnUnrequired(pod *api.PodSandbox, ctr *api.Container, failure v1alpha1.FailurePolicy) {
	if failure != v1alpha1.FailureClosed || RequiresPlugin(pod, ctr.GetName(), p.cfg.PluginName) {
		return
	}
	p.mu.Lock()
	seen := p.warned[pod.GetId()]
	p.warned[pod.GetId()] = true
	p.mu.Unlock()
	if !seen {
		p.log.Warn("failurePolicy Closed is not guaranteed while vesta-agent is down: the pod lacks the NRI required-plugins annotation",
			"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(),
			"annotation", nriplugin.RequiredPluginsAnnotation+"/pod", "want", `["`+p.cfg.PluginName+`"]`)
	}
}

func (p *Plugin) gateCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.cfg.GateTimeout)
}

// CreateContainer implements stub.CreateContainerInterface. It sends the
// bind once the channel is ready but does not wait for the ack: the guest
// acks after kata-agent creates the container cgroup, which happens after
// this hook returns. StartContainer waits for the ack.
func (p *Plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if !p.isVesta(pod) {
		return nil, nil, nil
	}
	c, failure, err := p.containerSpec(pod, ctr)
	p.remember(ctr.GetId(), pod.GetId(), failure, false)
	p.warnUnrequired(pod, ctr, failure)
	if err != nil {
		return nil, nil, p.gate("create", pod, ctr, failure, err)
	}
	sb, ok := p.mgr.Ensure(sandboxInfo(pod))
	if !ok {
		return nil, nil, p.gate("create", pod, ctr, failure, errors.New("invalid sandbox id"))
	}
	gctx, cancel := p.gateCtx(ctx)
	defer cancel()
	if err := sb.Bind(gctx, c); err != nil {
		return nil, nil, p.gate("create", pod, ctr, failure, err)
	}
	p.m.GateDecisions.WithLabelValues("create", "ok").Inc()
	return nil, nil, nil
}

// StartContainer implements stub.StartContainerInterface: the container
// starts only once the guest acked its bind, or per failure policy.
func (p *Plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if !p.isVesta(pod) {
		return nil
	}
	p.mu.Lock()
	st, ok := p.ctrs[ctr.GetId()]
	var failure v1alpha1.FailurePolicy
	var unmonitored bool
	if ok {
		failure, unmonitored = st.failure, st.unmonitored
	}
	p.mu.Unlock()
	if !ok {
		// CreateContainer was not seen (e.g. the agent restarted in
		// between); the policy cannot have been bound.
		_, failure, _ = p.containerSpec(pod, ctr)
		p.remember(ctr.GetId(), pod.GetId(), failure, false)
		return p.gate("start", pod, ctr, failure, errors.New("container was created before vesta saw it"))
	}
	if unmonitored {
		p.m.GateDecisions.WithLabelValues("start", "unmonitored").Inc()
		return nil
	}
	sb, ok := p.mgr.Get(pod.GetId())
	if !ok {
		return p.gate("start", pod, ctr, failure, errors.New("sandbox not registered"))
	}
	gctx, cancel := p.gateCtx(ctx)
	defer cancel()
	if err := sb.WaitBound(gctx, ctr.GetId()); err != nil {
		return p.gate("start", pod, ctr, failure, err)
	}
	p.m.GateDecisions.WithLabelValues("start", "ok").Inc()
	return nil
}

// RemoveContainer implements stub.RemoveContainerInterface.
func (p *Plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if !p.isVesta(pod) {
		return nil
	}
	p.mu.Lock()
	delete(p.ctrs, ctr.GetId())
	p.mu.Unlock()
	if sb, ok := p.mgr.Get(pod.GetId()); ok {
		sb.Unbind(ctr.GetId())
	}
	return nil
}
