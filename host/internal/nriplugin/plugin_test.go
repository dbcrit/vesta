// SPDX-License-Identifier: Apache-2.0

package nriplugin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/prometheus/client_golang/prometheus/testutil"

	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
)

// sbBehavior configures a fakeSandbox.
type sbBehavior struct {
	bindErr   error
	waitErr   error
	waitDelay time.Duration
}

type fakeSandbox struct {
	sbBehavior
	mu      sync.Mutex
	binds   []sandbox.Container
	unbinds []string
}

func (f *fakeSandbox) Bind(_ context.Context, c sandbox.Container) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds = append(f.binds, c)
	return f.bindErr
}

func (f *fakeSandbox) WaitBound(ctx context.Context, _ string) error {
	if f.waitDelay > 0 {
		select {
		case <-time.After(f.waitDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.waitErr
}

func (f *fakeSandbox) Unbind(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbinds = append(f.unbinds, id)
}

type fakeManager struct {
	mu      sync.Mutex
	set     *policy.Set
	sb      map[string]*fakeSandbox
	ensured []events.SandboxInfo
	removed []string
	proto   sbBehavior
}

func (m *fakeManager) Ensure(info events.SandboxInfo) (Sandbox, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensured = append(m.ensured, info)
	if s, ok := m.sb[info.SandboxID]; ok {
		return s, true
	}
	s := &fakeSandbox{sbBehavior: m.proto}
	m.sb[info.SandboxID] = s
	return s, true
}

func (m *fakeManager) Get(id string) (Sandbox, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sb[id]
	if !ok {
		return nil, false
	}
	return s, true
}

func (m *fakeManager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sb, id)
	m.removed = append(m.removed, id)
}

func (m *fakeManager) Retain(keep map[string]bool) {
	m.mu.Lock()
	var drop []string
	for id := range m.sb {
		if !keep[id] {
			drop = append(drop, id)
		}
	}
	m.mu.Unlock()
	for _, id := range drop {
		m.Remove(id)
	}
}

func (m *fakeManager) Policies() *policy.Set { return m.set }

func newPlugin(t *testing.T, proto sbBehavior, dflt v1alpha1.FailurePolicy) (*Plugin, *fakeManager, *metrics.Metrics) {
	t.Helper()
	pols, err := policy.Parse([]byte(`
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: strict, namespace: ns}
spec: {selector: {matchLabels: {tier: strict}}, failurePolicy: Closed}
`))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile(pols, 1)
	if err != nil {
		t.Fatal(err)
	}
	mgr := &fakeManager{set: set, sb: map[string]*fakeSandbox{}, proto: proto}
	m := metrics.New()
	p, err := New(Config{Handlers: []string{"kata-qemu-vesta"}, GateTimeout: 100 * time.Millisecond, DefaultFailure: dflt}, mgr, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return p, mgr, m
}

func pod(id, handler string, labels map[string]string) *api.PodSandbox {
	return &api.PodSandbox{Id: id, Name: "p-" + id, Namespace: "ns", Uid: "uid-" + id, RuntimeHandler: handler, Labels: labels}
}

func ctr(id, podID string) *api.Container {
	return &api.Container{
		Id: id, PodSandboxId: podID, Name: "app", State: api.ContainerState_CONTAINER_RUNNING,
		Linux: &api.LinuxContainer{CgroupsPath: "kubepods.slice:cri-containerd:" + id},
		Image: &api.Image{Name: "registry.example/app:1", Digest: "sha256:abc"},
	}
}

func TestNonVestaPodsUntouched(t *testing.T) {
	p, mgr, _ := newPlugin(t, sbBehavior{bindErr: errors.New("boom"), waitErr: errors.New("boom")}, v1alpha1.FailureClosed)
	ctx := context.Background()
	for _, h := range []string{"", "runc", "kata-qemu", "kata-qemu-runtime-rs", "kata-qemu-coco-dev"} {
		po := pod("s1", h, nil)
		if err := p.RunPodSandbox(ctx, po); err != nil {
			t.Fatal(err)
		}
		if adj, upd, err := p.CreateContainer(ctx, po, ctr("c1", "s1")); adj != nil || upd != nil || err != nil {
			t.Fatal(adj, upd, err)
		}
		if err := p.StartContainer(ctx, po, ctr("c1", "s1")); err != nil {
			t.Fatal(err)
		}
		if err := p.RemoveContainer(ctx, po, ctr("c1", "s1")); err != nil {
			t.Fatal(err)
		}
		if err := p.StopPodSandbox(ctx, po); err != nil {
			t.Fatal(err)
		}
		if err := p.RemovePodSandbox(ctx, po); err != nil {
			t.Fatal(err)
		}
	}
	if len(mgr.ensured) != 0 || len(mgr.removed) != 0 {
		t.Fatalf("manager touched for non-vesta pods: %v %v", mgr.ensured, mgr.removed)
	}
}

func TestGate(t *testing.T) {
	boom := errors.New("not acked")
	tests := []struct {
		name      string
		proto     sbBehavior
		labels    map[string]string
		dflt      v1alpha1.FailurePolicy
		createErr bool
		startErr  bool
		result    string
	}{
		{name: "ok", result: "ok"},
		{name: "open default, bind fails", proto: sbBehavior{bindErr: boom}, result: "unmonitored"},
		{name: "open default, ack fails", proto: sbBehavior{waitErr: boom}, result: "unmonitored"},
		{name: "closed default, bind fails", proto: sbBehavior{bindErr: boom}, dflt: v1alpha1.FailureClosed, createErr: true, result: "denied"},
		{name: "closed policy, ack fails", proto: sbBehavior{waitErr: boom}, labels: map[string]string{"tier": "strict"}, startErr: true, result: "denied"},
		{name: "closed policy, ack times out", proto: sbBehavior{waitDelay: time.Second}, labels: map[string]string{"tier": "strict"}, startErr: true, result: "denied"},
		{name: "open, ack times out", proto: sbBehavior{waitDelay: time.Second}, result: "unmonitored"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dflt := tc.dflt
			if dflt == "" {
				dflt = v1alpha1.FailureOpen
			}
			p, mgr, m := newPlugin(t, tc.proto, dflt)
			ctx := context.Background()
			po := pod("s1", "kata-qemu-vesta", tc.labels)
			if err := p.RunPodSandbox(ctx, po); err != nil {
				t.Fatal(err)
			}
			c := ctr("c1", "s1")
			_, _, err := p.CreateContainer(ctx, po, c)
			if (err != nil) != tc.createErr {
				t.Fatalf("create err = %v, want error=%v", err, tc.createErr)
			}
			if tc.createErr {
				if testutil.ToFloat64(m.GateDecisions.WithLabelValues("create", tc.result)) != 1 {
					t.Fatal("create decision not counted")
				}
				return
			}
			start := time.Now()
			err = p.StartContainer(ctx, po, c)
			if (err != nil) != tc.startErr {
				t.Fatalf("start err = %v, want error=%v", err, tc.startErr)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatal("start gate exceeded its timeout")
			}
			if testutil.ToFloat64(m.GateDecisions.WithLabelValues("start", tc.result)) != 1 {
				t.Fatalf("start decision %q not counted", tc.result)
			}
			sb := mgr.sb["s1"]
			if tc.proto.bindErr == nil {
				b := sb.binds[0]
				if b.CgroupPath != "kubepods.slice:cri-containerd:c1" || b.Info.ImageDigest != "sha256:abc" || b.Info.Name != "app" {
					t.Fatalf("bind %+v", b)
				}
				if (tc.labels != nil) != (b.Policy != nil) {
					t.Fatalf("policy selection %+v", b.Policy)
				}
			}
		})
	}
}

func TestStartWithoutCreateFollowsFailurePolicy(t *testing.T) {
	p, _, _ := newPlugin(t, sbBehavior{}, v1alpha1.FailureOpen)
	ctx := context.Background()
	if err := p.StartContainer(ctx, pod("s1", "kata-qemu-vesta", nil), ctr("c1", "s1")); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := p.StartContainer(ctx, pod("s1", "kata-qemu-vesta", map[string]string{"tier": "strict"}), ctr("c2", "s1")); err == nil {
		t.Fatal("closed policy container started without a bind")
	}
}

func TestLifecycleCleanup(t *testing.T) {
	p, mgr, _ := newPlugin(t, sbBehavior{}, v1alpha1.FailureOpen)
	ctx := context.Background()
	po := pod("s1", "kata-qemu-vesta", nil)
	_ = p.RunPodSandbox(ctx, po)
	_, _, _ = p.CreateContainer(ctx, po, ctr("c1", "s1"))
	sb := mgr.sb["s1"]
	if err := p.RemoveContainer(ctx, po, ctr("c1", "s1")); err != nil {
		t.Fatal(err)
	}
	if len(sb.unbinds) != 1 || sb.unbinds[0] != "c1" {
		t.Fatalf("unbinds %v", sb.unbinds)
	}
	if err := p.StopPodSandbox(ctx, po); err != nil {
		t.Fatal(err)
	}
	if len(mgr.removed) != 1 || len(p.ctrs) != 0 {
		t.Fatalf("removed %v ctrs %v", mgr.removed, p.ctrs)
	}
}

func TestSynchronize(t *testing.T) {
	p, mgr, _ := newPlugin(t, sbBehavior{}, v1alpha1.FailureOpen)
	// A stale sandbox from before the reconnect.
	mgr.Ensure(events.SandboxInfo{SandboxID: "gone"})
	pods := []*api.PodSandbox{pod("s1", "kata-qemu-vesta", nil), pod("s2", "runc", nil)}
	stopped := ctr("c3", "s1")
	stopped.State = api.ContainerState_CONTAINER_STOPPED
	ctrs := []*api.Container{ctr("c1", "s1"), ctr("c2", "s2"), stopped}
	upd, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil || upd != nil {
		t.Fatal(upd, err)
	}
	if _, ok := mgr.sb["gone"]; ok {
		t.Fatal("stale sandbox kept")
	}
	if _, ok := mgr.sb["s2"]; ok {
		t.Fatal("non-vesta pod registered")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		sb := mgr.sb["s1"]
		sb.mu.Lock()
		n := len(sb.binds)
		sb.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("running container not rebound (binds %d)", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Containers found at sync start without a new gate.
	if err := p.StartContainer(context.Background(), pods[0], ctr("c1", "s1")); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidates(t *testing.T) {
	m := metrics.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(Config{}, &fakeManager{}, m, log); err == nil {
		t.Fatal("no handlers accepted")
	}
	if _, err := New(Config{Handlers: []string{"x"}, DefaultFailure: "Sometimes"}, &fakeManager{}, m, log); err == nil {
		t.Fatal("bad failure policy accepted")
	}
}

func TestRequiresPlugin(t *testing.T) {
	pod := func(ann map[string]string) *api.PodSandbox { return &api.PodSandbox{Annotations: ann} }
	cases := []struct {
		ann  map[string]string
		want bool
	}{
		{nil, false},
		{map[string]string{"required-plugins.noderesource.dev/pod": `["vesta"]`}, true},
		{map[string]string{"required-plugins.noderesource.dev": "[ vesta, other ]"}, true},
		{map[string]string{"required-plugins.noderesource.dev/container.app": `["vesta"]`}, true},
		{map[string]string{"required-plugins.noderesource.dev/container.other": `["vesta"]`}, false},
		{map[string]string{"required-plugins.noderesource.dev/pod": `["other"]`}, false},
		{map[string]string{"required-plugins.noderesource.dev/pod": `not: [a list`}, false},
	}
	for _, c := range cases {
		if got := RequiresPlugin(pod(c.ann), "app", "vesta"); got != c.want {
			t.Errorf("%v: got %v, want %v", c.ann, got, c.want)
		}
	}
}
