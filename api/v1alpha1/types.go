// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 holds the vesta.dev/v1alpha1 policy types (ARCHITECTURE
// §2.8). Phase 1 loads them from a static file; the CRD controllers arrive in
// Phase 2. The types are intentionally minimal: fields that later phases add
// (file rules, DNS audit, rollout, drift prevention) are absent or rejected,
// so a strict decoder refuses policies that ask for them.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GroupVersion is the apiVersion of every object in this package.
const GroupVersion = "vesta.dev/v1alpha1"

// KindVestaPolicy is the kind of a namespaced policy.
const KindVestaPolicy = "VestaPolicy"

// Mode selects audit or enforce semantics.
type Mode string

const (
	ModeAudit   Mode = "Audit"
	ModeEnforce Mode = "Enforce"
)

// FailurePolicy decides what happens when vesta cannot confirm a policy is in
// force before a container starts (ARCHITECTURE §2.9).
type FailurePolicy string

const (
	FailureOpen   FailurePolicy = "Open"
	FailureClosed FailurePolicy = "Closed"
)

// Action is a rule or default verdict.
type Action string

const (
	ActionAllow Action = "Allow"
	ActionDeny  Action = "Deny"
)

// Protocol is an L4 protocol for egress rules.
type Protocol string

const (
	ProtocolAny Protocol = ""
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// VestaPolicy is a namespaced policy that applies to Kata pods selected by
// Spec.Selector in its namespace.
type VestaPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              VestaPolicySpec `json:"spec"`
}

// VestaPolicySpec is the desired policy.
type VestaPolicySpec struct {
	// Selector picks pods in the policy's namespace. Required; an empty
	// selector matches every vesta pod in the namespace.
	Selector *metav1.LabelSelector `json:"selector"`
	// ContainerSelector narrows the policy to named containers. Empty means
	// all containers.
	ContainerSelector *ContainerSelector `json:"containerSelector,omitempty"`
	// Mode defaults to Audit.
	Mode Mode `json:"mode,omitempty"`
	// FailurePolicy defaults to Open.
	FailurePolicy FailurePolicy `json:"failurePolicy,omitempty"`
	Process       *ProcessRules `json:"process,omitempty"`
	Network       *NetworkRules `json:"network,omitempty"`
}

// ContainerSelector selects containers by name.
type ContainerSelector struct {
	Names []string `json:"names"`
}

// ProcessRules are exec allow/deny rules. Paths are resolved to (dev, ino)
// inside the guest.
type ProcessRules struct {
	// Default applies when no rule matches. It defaults to Deny when Allow
	// is non-empty, and to Allow otherwise.
	Default Action     `json:"default,omitempty"`
	Allow   []PathRule `json:"allow,omitempty"`
	Deny    []PathRule `json:"deny,omitempty"`
	// DenyNonImageExec is drift prevention (Phase 3). Setting it to true is
	// rejected in this version.
	DenyNonImageExec bool `json:"denyNonImageExec,omitempty"`
}

// PathRule names an executable by absolute path.
type PathRule struct {
	Path string `json:"path"`
}

// NetworkRules are egress rules.
type NetworkRules struct {
	// EgressDefault applies when no rule matches. It defaults to Deny when
	// any Allow rule exists, and to Allow otherwise.
	EgressDefault Action       `json:"egressDefault,omitempty"`
	Egress        []EgressRule `json:"egress,omitempty"`
}

// EgressRule matches a destination CIDR, optional ports and protocol.
type EgressRule struct {
	CIDR     string   `json:"cidr"`
	Ports    []int32  `json:"ports,omitempty"`
	Protocol Protocol `json:"protocol,omitempty"`
	// Action defaults to Allow.
	Action Action `json:"action,omitempty"`
}

// VestaPolicyList is the file format of a static policy file.
type VestaPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	Items           []VestaPolicy `json:"items"`
}
