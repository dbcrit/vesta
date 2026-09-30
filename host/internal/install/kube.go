// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// GuestReadyLabel marks nodes with the vesta runtime installed; the
// RuntimeClass nodeSelector matches on it.
const GuestReadyLabel = "vesta.dev/guest-ready"

// NodeAPI is the Kubernetes access the installer needs: get and patch its
// own node, list pods on it, list RuntimeClasses.
type NodeAPI interface {
	ContainerRuntimeVersion(ctx context.Context, node string) (string, error)
	// SetLabel sets key=value on node; an empty value removes the label.
	SetLabel(ctx context.Context, node, key, value string) error
	// PodsUsingHandler lists running or pending pods on node whose
	// RuntimeClass uses handler, as "namespace/name".
	PodsUsingHandler(ctx context.Context, node, handler string) ([]string, error)
}

// KubeAPI implements NodeAPI with client-go.
type KubeAPI struct {
	Client kubernetes.Interface
}

// ContainerRuntimeVersion implements NodeAPI.
func (k KubeAPI) ContainerRuntimeVersion(ctx context.Context, node string) (string, error) {
	n, err := k.Client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get node %s: %w", node, err)
	}
	return n.Status.NodeInfo.ContainerRuntimeVersion, nil
}

// SetLabel implements NodeAPI with a JSON merge patch touching only key.
func (k KubeAPI) SetLabel(ctx context.Context, node, key, value string) error {
	var v any = value
	if value == "" {
		v = nil
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{key: v}}})
	if err != nil {
		return fmt.Errorf("encode label patch: %w", err)
	}
	if _, err := k.Client.CoreV1().Nodes().Patch(ctx, node, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("label node %s: %w", node, err)
	}
	return nil
}

// PodsUsingHandler implements NodeAPI.
func (k KubeAPI) PodsUsingHandler(ctx context.Context, node, handler string) ([]string, error) {
	rcs, err := k.Client.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list runtime classes: %w", err)
	}
	var classes []string
	for _, rc := range rcs.Items {
		if rc.Handler == handler {
			classes = append(classes, rc.Name)
		}
	}
	if len(classes) == 0 {
		// No RuntimeClass maps to the handler; fall back to its name.
		classes = []string{handler}
	}
	pods, err := k.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods on %s: %w", node, err)
	}
	var out []string
	for _, p := range pods.Items {
		if p.Spec.RuntimeClassName == nil || !slices.Contains(classes, *p.Spec.RuntimeClassName) {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		out = append(out, p.Namespace+"/"+p.Name)
	}
	return out, nil
}
