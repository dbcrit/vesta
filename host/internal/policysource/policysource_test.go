// SPDX-License-Identifier: Apache-2.0

package policysource

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type sink struct {
	mu   sync.Mutex
	set  *policy.Set
	sets int
}

func (s *sink) Policies() *policy.Set {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

func (s *sink) SetPolicies(set *policy.Set) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set = set
	s.sets++
}

func (s *sink) snapshot() (*policy.Set, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set, s.sets
}

// writeAtomic replaces path through a rename, as a ConfigMap update does, so
// the polling reloader never reads a half-written file.
func writeAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

const polA = "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: a, namespace: ns}\nspec: {selector: {}}\n"
const polB = "---\napiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: b, namespace: ns}\nspec: {selector: {}}\n"

func TestFileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(path, []byte(polB), 0o600); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	f := &File{Path: path, Interval: 10 * time.Millisecond, Metrics: m, Log: discard}
	set, digest, err := f.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{set: set}
	idB := set.Policies[0].ID
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx, s, digest)

	// Unchanged content is not re-published.
	time.Sleep(50 * time.Millisecond)
	if _, n := s.snapshot(); n != 0 {
		t.Fatalf("unchanged file published %d times", n)
	}

	// "a" sorts first but b keeps its id.
	if err := writeAtomic(path, polA+polB); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reload", func() bool { _, n := s.snapshot(); return n == 1 })
	got, _ := s.snapshot()
	if len(got.Policies) != 2 || got.Policies[1].Name != "b" || got.Policies[1].ID != idB || got.Generation <= set.Generation {
		t.Fatalf("reloaded set %+v", got.Policies)
	}

	// An invalid file keeps the current set and is not retried every tick.
	if err := writeAtomic(path, polA+"---\napiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: c, namespace: ns}\nspec: {mode: Sometimes, selector: {}}\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rejection", func() bool {
		return testutil.ToFloat64(m.PolicyReloads.WithLabelValues("file", resultRejected)) == 1
	})
	time.Sleep(50 * time.Millisecond)
	if _, n := s.snapshot(); n != 1 {
		t.Fatal("invalid file replaced the set")
	}
	if v := testutil.ToFloat64(m.PolicyReloads.WithLabelValues("file", resultRejected)); v != 1 {
		t.Fatalf("rejected %v times", v)
	}

	// A missing file (ConfigMap swap in progress) is an error, not an empty set.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "read error", func() bool {
		return testutil.ToFloat64(m.PolicyReloads.WithLabelValues("file", resultError)) >= 1
	})
	if got, _ := s.snapshot(); len(got.Policies) != 2 {
		t.Fatal("missing file changed the set")
	}
}

type statusRec struct {
	mu      sync.Mutex
	entries map[string][]NodeStatus
}

func (r *statusRec) ApplyNodeStatus(_ context.Context, ns, name string, st NodeStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string][]NodeStatus{}
	}
	r.entries[ns+"/"+name] = append(r.entries[ns+"/"+name], st)
	return nil
}

func (r *statusRec) last(key string) (NodeStatus, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[key]
	if len(e) == 0 {
		return NodeStatus{}, 0
	}
	return e[len(e)-1], len(e)
}

type fixedStats map[string]sandbox.PolicyStats

func (f fixedStats) PolicyStats(set *policy.Set) map[uint32]sandbox.PolicyStats {
	out := map[uint32]sandbox.PolicyStats{}
	for _, p := range set.Policies {
		if s, ok := f[p.Key()]; ok {
			out[p.ID] = s
		}
	}
	return out
}

func vpObj(name string, gen int64, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "vesta.dev/v1alpha1",
		"kind":       "VestaPolicy",
		"metadata":   map[string]any{"name": name, "namespace": "ns"},
		"spec":       spec,
	}}
	u.SetGeneration(gen)
	u.SetUID(types.UID("uid-" + name))
	return u
}

func TestKubeSource(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{GVR: "VestaPolicyList"},
		vpObj("good", 1, map[string]any{"selector": map[string]any{}, "mode": "Enforce", "failurePolicy": "Closed"}),
		vpObj("bad", 1, map[string]any{"selector": map[string]any{}, "mode": "Sometimes"}),
	)
	m := metrics.New()
	rec := &statusRec{}
	k := &Kube{
		Client: client, Status: rec, Node: "node1", Metrics: m, Log: discard,
		Debounce: 10 * time.Millisecond, StatusInterval: 20 * time.Millisecond,
		Stats: fixedStats{"ns/good": {Sandboxes: 2, Programmed: 1, Containers: 3}},
	}
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	synced := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- k.Run(ctx, s, synced) }()
	select {
	case <-synced:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("no initial sync")
	}
	set, n := s.snapshot()
	if n != 1 || len(set.Policies) != 1 || set.Policies[0].Name != "good" {
		t.Fatalf("initial set %v (published %d)", set.Policies, n)
	}
	if v := testutil.ToFloat64(m.PoliciesRejected); v != 1 {
		t.Fatalf("rejected gauge %v", v)
	}
	waitFor(t, "status for both objects", func() bool {
		_, a := rec.last("ns/good")
		_, b := rec.last("ns/bad")
		return a > 0 && b > 0
	})
	good, _ := rec.last("ns/good")
	if !good.Accepted || good.Node != "node1" || good.Sandboxes != 2 || good.Programmed != 1 || good.Containers != 3 || good.ObservedGeneration != 1 {
		t.Fatalf("good status %+v", good)
	}
	bad, _ := rec.last("ns/bad")
	if bad.Accepted || !strings.Contains(bad.Message, "Sometimes") {
		t.Fatalf("bad status %+v", bad)
	}

	// Unchanged counts are not rewritten on the status tick.
	_, before := rec.last("ns/good")
	time.Sleep(80 * time.Millisecond)
	if _, after := rec.last("ns/good"); after != before {
		t.Fatalf("status rewritten without change: %d -> %d", before, after)
	}

	// A status-only update (same generation) does not rebuild.
	res := client.Resource(GVR).Namespace("ns")
	cur, err := res.Get(ctx, "good", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedSlice(cur.Object, []any{map[string]any{"node": "other"}}, "status", "nodes")
	if _, err := res.Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, n := s.snapshot(); n != 1 {
		t.Fatalf("status update caused %d publishes", n)
	}

	// A spec change (new generation) publishes a new set; fixing "bad" adds it.
	fixed := vpObj("bad", 2, map[string]any{"selector": map[string]any{}})
	if _, err := res.Update(ctx, fixed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second publish", func() bool { _, n := s.snapshot(); return n == 2 })
	set2, _ := s.snapshot()
	if len(set2.Policies) != 2 || set2.Generation <= set.Generation {
		t.Fatalf("after fix %v", set2.Policies)
	}
	if id, _ := set2.ByID(set.Policies[0].ID); id == nil || id.Name != "good" {
		t.Fatal("good lost its id")
	}
	waitFor(t, "bad accepted", func() bool { st, _ := rec.last("ns/bad"); return st.Accepted && st.ObservedGeneration == 2 })

	// Deleting a policy publishes a set without it.
	if err := res.Delete(ctx, "good", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "delete", func() bool { set, _ := s.snapshot(); return len(set.Policies) == 1 && set.Policies[0].Name == "bad" })
	if v := testutil.ToFloat64(m.PoliciesRejected); v != 0 {
		t.Fatalf("rejected gauge %v", v)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	u := vpObj("x", 1, map[string]any{"selector": map[string]any{}, "unknownField": true})
	if _, err := decode(u); err == nil {
		t.Fatal("unknown spec field accepted")
	}
	u = vpObj("x", 1, map[string]any{"selector": map[string]any{}})
	u.Object["status"] = map[string]any{"nodes": []any{}}
	if _, err := decode(u); err != nil {
		t.Fatalf("status must be ignored: %v", err)
	}
}

func TestFieldManager(t *testing.T) {
	if got := FieldManager("Node-A"); got != "vesta-agent-node-a" {
		t.Fatal(got)
	}
	if got := FieldManager(strings.Repeat("n", 300)); len(got) != 128 {
		t.Fatal(len(got))
	}
	if got := truncate("héllo", 2); got != "h" {
		t.Fatalf("%q", got)
	}
}
