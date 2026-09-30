// SPDX-License-Identifier: Apache-2.0

package policysource

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
)

// GVR is the VestaPolicy resource.
var GVR = schema.GroupVersionResource{Group: "vesta.dev", Version: "v1alpha1", Resource: "vestapolicies"}

// maxStatusMessage bounds status.nodes[].message.
const maxStatusMessage = 1024

// NodeStatus is this agent's entry in a VestaPolicy's status.nodes, keyed by
// node. Each agent writes only its own entry, with server-side apply and a
// per-node field manager, so DaemonSet pods never overwrite each other.
type NodeStatus struct {
	Node string `json:"node"`
	// ObservedGeneration is the metadata.generation this entry describes.
	ObservedGeneration int64 `json:"observedGeneration"`
	// Accepted is false when the policy failed validation; Message says why.
	Accepted bool   `json:"accepted"`
	Message  string `json:"message,omitempty"`
	// Sandboxes on this node with at least one container the policy
	// selects; Programmed of them have the current set applied by the guest.
	Sandboxes  int64 `json:"sandboxes"`
	Programmed int64 `json:"programmed"`
	Containers int64 `json:"containers"`
}

// StatusWriter applies one node's status entry to a VestaPolicy.
type StatusWriter interface {
	ApplyNodeStatus(ctx context.Context, namespace, name string, st NodeStatus) error
}

// Stats is what the status needs from the sandbox registry.
type Stats interface {
	PolicyStats(set *policy.Set) map[uint32]sandbox.PolicyStats
}

// Kube watches VestaPolicy objects in all namespaces and publishes a policy
// set on every spec change. Unlike a policy file, an invalid object is left
// out (and reported in its status) instead of rejecting the whole set.
type Kube struct {
	Client  dynamic.Interface
	Status  StatusWriter // nil disables status updates
	Stats   Stats
	Node    string
	Metrics *metrics.Metrics
	Log     *slog.Logger
	// Debounce coalesces bursts of changes (default 250ms).
	Debounce time.Duration
	// StatusInterval re-evaluates status counts (default 30s). Entries are
	// written only when they change.
	StatusInterval time.Duration
	// Now is the clock for generations; nil means time.Now.
	Now func() time.Time

	digest  [32]byte
	objs    map[string]objMeta // namespace/name -> meta of the last build
	rejects map[string]error
	written map[string]NodeStatus
}

type objMeta struct {
	namespace, name string
	generation      int64
}

func (k *Kube) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// Run starts the informer, publishes the first set once the cache has
// synced (then closes synced), and keeps publishing until ctx ends.
func (k *Kube) Run(ctx context.Context, sink Sink, synced chan<- struct{}) error {
	if k.Debounce <= 0 {
		k.Debounce = 250 * time.Millisecond
	}
	if k.StatusInterval <= 0 {
		k.StatusInterval = 30 * time.Second
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(k.Client, 0)
	inf := factory.ForResource(GVR).Informer()
	changed := make(chan struct{}, 1)
	notify := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { notify() },
		DeleteFunc: func(any) { notify() },
		UpdateFunc: func(oldObj, newObj any) {
			// Status writes (ours included) do not bump metadata.generation.
			o, ok1 := oldObj.(*unstructured.Unstructured)
			n, ok2 := newObj.(*unstructured.Unstructured)
			if ok1 && ok2 && o.GetGeneration() == n.GetGeneration() && o.GetUID() == n.GetUID() {
				return
			}
			notify()
		},
	}); err != nil {
		return fmt.Errorf("vestapolicy informer: %w", err)
	}
	factory.Start(ctx.Done())
	defer factory.Shutdown()
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return ctx.Err()
	}
	k.rebuild(sink, inf.GetStore().List(), true)
	close(synced)
	k.writeStatus(ctx, sink.Policies())

	statusTick := time.NewTicker(k.StatusInterval)
	defer statusTick.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			if debounce == nil {
				debounce = time.After(k.Debounce)
			}
		case <-debounce:
			debounce = nil
			if k.rebuild(sink, inf.GetStore().List(), false) {
				k.writeStatus(ctx, sink.Policies())
			}
		case <-statusTick.C:
			k.writeStatus(ctx, sink.Policies())
		}
	}
}

// rebuild compiles the listed objects and publishes the set if their
// identity or spec generation changed. It reports whether it published.
func (k *Kube) rebuild(sink Sink, list []any, force bool) bool {
	pols := make([]v1alpha1.VestaPolicy, 0, len(list))
	objs := make(map[string]objMeta, len(list))
	rejects := map[string]error{}
	h := sha256.New()
	keys := make([]string, 0, len(list))
	byKey := map[string]*unstructured.Unstructured{}
	for _, o := range list {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		key := u.GetNamespace() + "/" + u.GetName()
		keys = append(keys, key)
		byKey[key] = u
	}
	slices.Sort(keys)
	for _, key := range keys {
		u := byKey[key]
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00", key, u.GetUID(), u.GetGeneration())
		objs[key] = objMeta{namespace: u.GetNamespace(), name: u.GetName(), generation: u.GetGeneration()}
		vp, err := decode(u)
		if err != nil {
			rejects[key] = err
			continue
		}
		pols = append(pols, vp)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if !force && digest == k.digest {
		return false
	}
	prev := sink.Policies()
	var prevGen uint64
	if prev != nil {
		prevGen = prev.Generation
	}
	set, rejected, err := policy.CompileWith(pols, policy.NextGeneration(prevGen, k.now()), prev)
	if err != nil {
		// Only the policy count limit fails the whole set; keep the current one.
		k.Metrics.PolicyReloads.WithLabelValues("kubernetes", resultError).Inc()
		k.Log.Error("VestaPolicy set rejected; keeping the current policies", "err", err)
		k.digest, k.objs = digest, objs
		k.rejects = map[string]error{}
		for key := range objs {
			k.rejects[key] = err
		}
		return true
	}
	for key, e := range rejected {
		rejects[key] = e
	}
	k.digest, k.objs, k.rejects = digest, objs, rejects
	publish(sink, set, len(rejects), k.Metrics)
	result := resultApplied
	if len(rejects) > 0 {
		result = resultRejected
		k.Log.Warn("invalid VestaPolicy objects left out", "err", policy.RejectedError(rejects))
	}
	k.Metrics.PolicyReloads.WithLabelValues("kubernetes", result).Inc()
	k.Log.Info("VestaPolicy set updated", "policies", len(set.Policies), "rejected", len(rejects), "generation", set.Generation)
	return true
}

// decode strictly converts an object into a VestaPolicy. The status is not
// part of the input and is dropped first.
func decode(u *unstructured.Unstructured) (v1alpha1.VestaPolicy, error) {
	var vp v1alpha1.VestaPolicy
	if u.GetAPIVersion() != v1alpha1.GroupVersion || u.GetKind() != v1alpha1.KindVestaPolicy {
		return vp, fmt.Errorf("unexpected %s %s", u.GetAPIVersion(), u.GetKind())
	}
	obj := make(map[string]any, len(u.Object))
	for k, v := range u.Object {
		if k != "status" {
			obj[k] = v
		}
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return vp, fmt.Errorf("encode: %w", err)
	}
	if err := yaml.UnmarshalStrict(data, &vp); err != nil {
		return vp, fmt.Errorf("decode: %w", err)
	}
	return vp, nil
}

// writeStatus applies this node's entry to every known VestaPolicy whose
// entry changed since the last successful write.
func (k *Kube) writeStatus(ctx context.Context, set *policy.Set) {
	if k.Status == nil {
		return
	}
	if k.written == nil {
		k.written = map[string]NodeStatus{}
	}
	var stats map[uint32]sandbox.PolicyStats
	if k.Stats != nil {
		stats = k.Stats.PolicyStats(set)
	}
	ids := map[string]uint32{}
	for _, p := range set.Policies {
		ids[p.Key()] = p.ID
	}
	for key, m := range k.objs {
		st := NodeStatus{Node: k.Node, ObservedGeneration: m.generation, Accepted: true}
		if err := k.rejects[key]; err != nil {
			st.Accepted = false
			st.Message = truncate(err.Error(), maxStatusMessage)
		} else if s, ok := stats[ids[key]]; ok {
			st.Sandboxes, st.Programmed, st.Containers = int64(s.Sandboxes), int64(s.Programmed), int64(s.Containers)
		}
		if prev, ok := k.written[key]; ok && prev == st {
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := k.Status.ApplyNodeStatus(wctx, m.namespace, m.name, st)
		cancel()
		if err != nil {
			k.Log.Warn("updating VestaPolicy status failed", "policy", key, "err", err)
			continue
		}
		k.written[key] = st
	}
	for key := range k.written {
		if _, ok := k.objs[key]; !ok {
			delete(k.written, key)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// DynamicStatus writes status entries with server-side apply through the
// status subresource.
type DynamicStatus struct {
	Client dynamic.Interface
	Node   string
}

// FieldManager is the per-node server-side apply manager name.
func FieldManager(node string) string {
	fm := "vesta-agent-" + node
	if len(fm) > 128 {
		fm = fm[:128]
	}
	return strings.ToLower(fm)
}

// ApplyNodeStatus implements StatusWriter.
func (d DynamicStatus) ApplyNodeStatus(ctx context.Context, namespace, name string, st NodeStatus) error {
	entry := map[string]any{
		"node":               st.Node,
		"observedGeneration": st.ObservedGeneration,
		"accepted":           st.Accepted,
		"sandboxes":          st.Sandboxes,
		"programmed":         st.Programmed,
		"containers":         st.Containers,
	}
	if st.Message != "" {
		entry["message"] = st.Message
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion,
		"kind":       v1alpha1.KindVestaPolicy,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"status":     map[string]any{"nodes": []any{entry}},
	}}
	if _, err := d.Client.Resource(GVR).Namespace(namespace).ApplyStatus(ctx, name, u,
		metav1.ApplyOptions{FieldManager: FieldManager(d.Node), Force: true}); err != nil {
		return fmt.Errorf("apply status: %w", err)
	}
	return nil
}
