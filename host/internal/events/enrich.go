// SPDX-License-Identifier: Apache-2.0

package events

import (
	"time"

	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
)

// SandboxInfo is trusted sandbox metadata from NRI and the handshake.
type SandboxInfo struct {
	Node           string
	SandboxID      string
	PodName        string
	PodNamespace   string
	PodUID         string
	RuntimeHandler string
	// PodLabels and CgroupParent (NRI PodSandbox.linux.cgroup_parent) select
	// policies and the pod cgroup for the sandbox default. Not exported.
	PodLabels    map[string]string
	CgroupParent string
	// GuestImageVersion and KernelRelease come from the guest's HelloReply
	// and are guest-asserted; they are length-checked at the handshake.
	GuestImageVersion string
	KernelRelease     string
}

// ContainerInfo is trusted container metadata from NRI.
type ContainerInfo struct {
	ID          string
	Name        string
	Image       string
	ImageDigest string
}

// PolicyInfo names a compiled policy.
type PolicyInfo struct {
	Name      string
	Namespace string
	UID       string
}

// Lookup resolves guest-reported keys against host-side state of one
// sandbox. A guest can only select among its own sandbox's entries.
type Lookup interface {
	Container(id string) (ContainerInfo, bool)
	Policy(generation uint64, id uint32) (PolicyInfo, bool)
}

// Record is an enriched event ready for export.
type Record struct {
	Event *eventv1.Event
	// ContainerID is set only when the guest-reported ID matched a
	// container NRI reported for this sandbox.
	ContainerID string
	// GuestContainerID is the guest-asserted container ID, kept apart from
	// the host-verified one.
	GuestContainerID string
}

// Enrich sets e.Host from trusted sources only. The guest-reported
// container_id and policy_id are used purely as lookup keys; the values
// written come from NRI and the host's own policy table.
func Enrich(e *eventv1.Event, sb SandboxInfo, lk Lookup, now time.Time) Record {
	h := &eventv1.Host{
		Node:              sb.Node,
		SandboxId:         sb.SandboxID,
		PodName:           sb.PodName,
		PodNamespace:      sb.PodNamespace,
		PodUid:            sb.PodUID,
		RuntimeClass:      sb.RuntimeHandler,
		GuestImageVersion: sb.GuestImageVersion,
		KernelRelease:     sb.KernelRelease,
		ReceivedUnixNs:    now.UnixNano(),
	}
	rec := Record{Event: e, GuestContainerID: e.GetContainerId()}
	if lk != nil {
		if id := e.GetContainerId(); id != "" {
			if c, ok := lk.Container(id); ok {
				rec.ContainerID = c.ID
				h.ContainerName = c.Name
				h.Image = c.Image
				h.ImageDigest = c.ImageDigest
			}
		}
		if p := e.GetPolicy(); p != nil {
			p.Name, p.Namespace, p.Uid = "", "", ""
			if p.GetPolicyId() != 0 {
				if pi, ok := lk.Policy(p.GetGeneration(), p.GetPolicyId()); ok {
					p.Name, p.Namespace, p.Uid = pi.Name, pi.Namespace, pi.UID
				}
			}
		}
	}
	e.Host = h
	return rec
}
