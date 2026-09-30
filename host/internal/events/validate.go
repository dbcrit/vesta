// SPDX-License-Identifier: Apache-2.0

// Package events validates guest events, enriches them with host metadata
// and exports them (ARCHITECTURE §2.7, §1.4.3). Every field of an incoming
// event is guest-asserted and untrusted.
package events

import (
	"errors"
	"fmt"
	"regexp"

	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
)

// Limits from api/proto/vesta/event/v1/event.proto.
const (
	MaxChain       = 8
	MaxComm        = 16
	MaxPath        = 4096
	MaxContainerID = 128
	MaxFlags       = 16
	MaxArgv        = 256
	MaxArgvBytes   = 4096
	MaxPort        = 65535
	MaxIPProto     = 255
)

var containerIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ValidContainerID reports whether id has the CRI container ID shape.
func ValidContainerID(id string) bool { return containerIDRe.MatchString(id) }

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid event")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func definedEnum[T ~int32](v T, names map[int32]string, allowZero bool) bool {
	if v == 0 {
		return allowZero
	}
	_, ok := names[int32(v)]
	return ok
}

// Validate checks e against the documented limits and enum ranges. It
// discards a guest-supplied Host (only vesta-agent sets it). Proto3 decoding
// already rejected invalid UTF-8 in string fields.
func Validate(e *eventv1.Event) error {
	if e == nil {
		return invalid("nil event")
	}
	e.Host = nil
	if e.GetSeq() == 0 {
		return invalid("seq 0")
	}
	if !definedEnum(e.GetType(), eventv1.EventType_name, false) {
		return invalid("unknown type %d", e.GetType())
	}
	if !definedEnum(e.GetAction(), eventv1.Action_name, false) {
		return invalid("unknown action %d", e.GetAction())
	}
	if !definedEnum(e.GetHook(), eventv1.Hook_name, true) {
		return invalid("unknown hook %d", e.GetHook())
	}
	if n := len(e.GetContainerId()); n > 0 && !ValidContainerID(e.GetContainerId()) {
		return invalid("container_id (%d bytes) malformed", n)
	}
	if n := len(e.GetFlags()); n > MaxFlags {
		return invalid("%d flags", n)
	}
	seen := make(map[eventv1.EventFlag]bool, len(e.GetFlags()))
	for _, f := range e.GetFlags() {
		if !definedEnum(f, eventv1.EventFlag_name, false) {
			return invalid("unknown flag %d", f)
		}
		if seen[f] {
			return invalid("duplicate flag %d", f)
		}
		seen[f] = true
	}
	if err := validateProcess(e.GetProcess()); err != nil {
		return err
	}
	if n := len(e.GetChain()); n > MaxChain {
		return invalid("chain of %d", n)
	}
	for _, a := range e.GetChain() {
		if len(a.GetComm()) > MaxComm || len(a.GetExePath()) > MaxPath {
			return invalid("ancestor field too long")
		}
	}
	switch e.GetType() {
	case eventv1.EventType_EVENT_TYPE_EXEC:
		if e.GetExec() == nil {
			return invalid("exec event without exec detail")
		}
	case eventv1.EventType_EVENT_TYPE_CONNECT:
		if err := validateNet(e.GetNet()); err != nil {
			return err
		}
	default:
		// Types reserved for later phases carry details this protocol
		// version does not define.
		return invalid("event type %s not supported by protocol 1.0", e.GetType())
	}
	return nil
}

func validateProcess(p *eventv1.Process) error {
	if p == nil {
		return invalid("missing process")
	}
	if len(p.GetComm()) > MaxComm {
		return invalid("comm too long")
	}
	if len(p.GetExePath()) > MaxPath {
		return invalid("exe_path too long")
	}
	if n := len(p.GetArgv()); n > MaxArgv {
		return invalid("argv has %d entries", n)
	}
	total := 0
	for _, a := range p.GetArgv() {
		total += len(a)
		if total > MaxArgvBytes {
			return invalid("argv exceeds %d bytes", MaxArgvBytes)
		}
	}
	return nil
}

func validateNet(n *eventv1.Net) error {
	if n == nil {
		return invalid("connect event without net detail")
	}
	if !definedEnum(n.GetDirection(), eventv1.Direction_name, false) {
		return invalid("unknown direction %d", n.GetDirection())
	}
	if !definedEnum(n.GetMatchedVerdict(), eventv1.RuleVerdict_name, true) {
		return invalid("unknown verdict %d", n.GetMatchedVerdict())
	}
	switch n.GetFamily() {
	case eventv1.AddressFamily_ADDRESS_FAMILY_INET:
		if len(n.GetRemoteAddr()) != 4 {
			return invalid("inet address of %d bytes", len(n.GetRemoteAddr()))
		}
	case eventv1.AddressFamily_ADDRESS_FAMILY_INET6:
		if len(n.GetRemoteAddr()) != 16 {
			return invalid("inet6 address of %d bytes", len(n.GetRemoteAddr()))
		}
	default:
		return invalid("unknown family %d", n.GetFamily())
	}
	if n.GetRemotePort() > MaxPort {
		return invalid("port %d", n.GetRemotePort())
	}
	if n.GetProtocol() > MaxIPProto {
		return invalid("protocol %d", n.GetProtocol())
	}
	return nil
}
