// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"slices"

	"github.com/dbcrit/vesta/api/channel"
	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
)

// Limits from api/proto/vesta/channel/v1/{control,events}.proto.
const (
	maxImageVersion = 63
	maxKernelRel    = 128
	maxLSMs         = 32
	maxLSMLen       = 32
	maxFeatures     = 64
	maxFeatureLen   = 64
	maxGuestdVer    = 64
	maxProgs        = 64
	maxProgID       = 32
	maxAttach       = 128
	maxErrText      = 1024
	maxVerifierLog  = 65536
	maxWarnings     = 64
	maxWarningLen   = 256
	maxDrops        = 16
	tagSize         = 8
	policyHashSize  = 32
	maxBatchEvents  = 512
	eventTypeMax    = 16 // VESTA_EVENT_TYPE_MAX
)

// Feature strings from control.proto.
const (
	FeatureExecAudit  = "exec_audit"
	FeatureExecLSM    = "exec_lsm"
	FeatureNetEgress4 = "net_egress4"
	FeatureNetEgress6 = "net_egress6"
	FeatureBPFLSM     = "bpf_lsm"
	FeatureEnforce    = "enforce"
)

// SupportedMajors are the protocol majors the host speaks: N and N-1.
func SupportedMajors() []uint32 {
	if channel.ProtoMajor > 1 {
		return []uint32{channel.ProtoMajor, channel.ProtoMajor - 1}
	}
	return []uint32{channel.ProtoMajor}
}

func enumOK[T ~int32](v T, names map[int32]string) bool {
	_, ok := names[int32(v)]
	return ok
}

func validateProgs(progs []*channelv1.ProgStatus) error {
	if len(progs) > maxProgs {
		return fmt.Errorf("%d programs", len(progs))
	}
	for _, p := range progs {
		switch {
		case len(p.GetId()) == 0 || len(p.GetId()) > maxProgID:
			return fmt.Errorf("program id of %d bytes", len(p.GetId()))
		case len(p.GetAttach()) > maxAttach:
			return fmt.Errorf("program %s: attach too long", p.GetId())
		case !enumOK(p.GetState(), channelv1.ProgState_name):
			return fmt.Errorf("program %s: unknown state %d", p.GetId(), p.GetState())
		case len(p.GetTag()) != 0 && len(p.GetTag()) != tagSize:
			return fmt.Errorf("program %s: tag of %d bytes", p.GetId(), len(p.GetTag()))
		case len(p.GetError()) > maxErrText || len(p.GetVerifierLog()) > maxVerifierLog:
			return fmt.Errorf("program %s: error or verifier log too long", p.GetId())
		}
	}
	return nil
}

func validateDrops(d []*channelv1.DropCount) error {
	if len(d) > maxDrops {
		return fmt.Errorf("%d drop counters", len(d))
	}
	for _, c := range d {
		if c.GetEventType() >= eventTypeMax {
			return fmt.Errorf("drop counter for event type %d", c.GetEventType())
		}
	}
	return nil
}

// validateHelloReply enforces the documented limits on a guest HelloReply.
func validateHelloReply(r *channelv1.HelloReply) error {
	switch {
	case r == nil:
		return fmt.Errorf("missing hello reply")
	case len(r.GetGuestImageVersion()) > maxImageVersion:
		return fmt.Errorf("guest_image_version too long")
	case len(r.GetKernelRelease()) > maxKernelRel:
		return fmt.Errorf("kernel_release too long")
	case len(r.GetGuestdVersion()) > maxGuestdVer:
		return fmt.Errorf("guestd_version too long")
	case len(r.GetActiveLsms()) > maxLSMs:
		return fmt.Errorf("%d active LSMs", len(r.GetActiveLsms()))
	case len(r.GetFeatures()) > maxFeatures:
		return fmt.Errorf("%d features", len(r.GetFeatures()))
	case !enumOK(r.GetGlobalMode(), channelv1.GlobalMode_name):
		return fmt.Errorf("unknown global mode %d", r.GetGlobalMode())
	}
	for _, l := range r.GetActiveLsms() {
		if len(l) > maxLSMLen {
			return fmt.Errorf("LSM name too long")
		}
	}
	for _, f := range r.GetFeatures() {
		if len(f) > maxFeatureLen {
			return fmt.Errorf("feature name too long")
		}
	}
	return validateProgs(r.GetProgs())
}

// eligibility returns why a guest cannot be monitored, or nil.
func eligibility(r *channelv1.HelloReply) error {
	if !slices.Contains(SupportedMajors(), r.GetProtoMajor()) {
		return fmt.Errorf("guest protocol %d.%d not supported (host supports majors %v)", r.GetProtoMajor(), r.GetProtoMinor(), SupportedMajors())
	}
	if r.GetAbiVersion() != channel.ABIVersion {
		return fmt.Errorf("guest BPF ABI version %d, host expects %d", r.GetAbiVersion(), channel.ABIVersion)
	}
	if !r.GetCgroupV2() {
		return fmt.Errorf("guest has no cgroup v2")
	}
	return nil
}

func validateAck(a *channelv1.Ack) error {
	switch {
	case a == nil:
		return fmt.Errorf("missing ack")
	case len(a.GetError()) > maxErrText:
		return fmt.Errorf("ack error too long")
	case len(a.GetVerifierLog()) > maxVerifierLog:
		return fmt.Errorf("ack verifier log too long")
	case len(a.GetWarnings()) > maxWarnings:
		return fmt.Errorf("%d ack warnings", len(a.GetWarnings()))
	}
	for _, w := range a.GetWarnings() {
		if len(w) > maxWarningLen {
			return fmt.Errorf("ack warning too long")
		}
	}
	return nil
}

func validateHeartbeat(h *channelv1.Heartbeat) error {
	switch {
	case len(h.GetPolicyHash()) != 0 && len(h.GetPolicyHash()) != policyHashSize:
		return fmt.Errorf("policy hash of %d bytes", len(h.GetPolicyHash()))
	case !enumOK(h.GetGlobalMode(), channelv1.GlobalMode_name):
		return fmt.Errorf("unknown global mode %d", h.GetGlobalMode())
	}
	if err := validateProgs(h.GetProgs()); err != nil {
		return err
	}
	return validateDrops(h.GetRingbufDrops())
}
