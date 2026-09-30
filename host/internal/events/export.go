// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
)

// Exporter sends records to a sink. Export is called from one goroutine.
type Exporter interface {
	Export(r Record) error
	Flush() error
}

// JSONLines writes one JSON object per record, shaped like an OpenTelemetry
// log record with semantic-convention attribute names.
//
// Trust: only k8s.*, container.*, vesta.sandbox.id, vesta.runtime_handler,
// vesta.policy.name and vesta.policy.namespace are host-set (from NRI and
// the agent's own state). Every other attribute, including process.*,
// network.*, vesta.action, vesta.hook, vesta.flags and the policy, rule and
// cgroup ids, is reported by the guest and only bounds- and enum-checked by
// the host, so it is guest-asserted. The vesta.guest.* prefix marks
// guest-asserted fields that have no host-side counterpart at all.
type JSONLines struct {
	mu sync.Mutex
	w  *bufio.Writer
}

// NewJSONLines writes to w.
func NewJSONLines(w io.Writer) *JSONLines {
	return &JSONLines{w: bufio.NewWriterSize(w, 64<<10)}
}

type logLine struct {
	Timestamp         string         `json:"timestamp"`
	ObservedTimestamp string         `json:"observed_timestamp"`
	SeverityText      string         `json:"severity_text"`
	EventName         string         `json:"event_name"`
	Attributes        map[string]any `json:"attributes"`
}

// Export implements Exporter.
func (j *JSONLines) Export(r Record) error {
	b, err := json.Marshal(toLogLine(r))
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

// Flush implements Exporter.
func (j *JSONLines) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.w.Flush(); err != nil {
		return fmt.Errorf("flush events: %w", err)
	}
	return nil
}

func enumName(s string, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(s, prefix))
}

func toLogLine(r Record) logLine {
	e := r.Event
	h := e.GetHost()
	received := time.Unix(0, h.GetReceivedUnixNs()).UTC()
	a := map[string]any{
		"k8s.node.name":                 h.GetNode(),
		"k8s.namespace.name":            h.GetPodNamespace(),
		"k8s.pod.name":                  h.GetPodName(),
		"k8s.pod.uid":                   h.GetPodUid(),
		"vesta.sandbox.id":              h.GetSandboxId(),
		"vesta.runtime_handler":         h.GetRuntimeClass(),
		"vesta.guest.image_version":     h.GetGuestImageVersion(),
		"vesta.guest.kernel_release":    h.GetKernelRelease(),
		"vesta.event.seq":               e.GetSeq(),
		"vesta.event.type":              enumName(e.GetType().String(), "EVENT_TYPE_"),
		"vesta.action":                  enumName(e.GetAction().String(), "ACTION_"),
		"vesta.hook":                    enumName(e.GetHook().String(), "HOOK_"),
		"vesta.cgroup.id":               e.GetCgroupId(),
		"vesta.guest.ktime_boot_ns":     e.GetKtimeBootNs(),
		"vesta.guest.wall_time_unix_ns": e.GetGuestWallUnixNs(),
	}
	if r.ContainerID != "" {
		a["container.id"] = r.ContainerID
		a["k8s.container.name"] = h.GetContainerName()
		a["container.image.name"] = h.GetImage()
		if d := h.GetImageDigest(); d != "" {
			a["container.image.repo_digests"] = []string{d}
		}
	}
	if r.GuestContainerID != "" {
		a["vesta.guest.container_id"] = r.GuestContainerID
	}
	if len(e.GetFlags()) > 0 {
		fl := make([]string, 0, len(e.GetFlags()))
		for _, f := range e.GetFlags() {
			fl = append(fl, enumName(f.String(), "EVENT_FLAG_"))
		}
		a["vesta.flags"] = fl
	}
	if p := e.GetPolicy(); p != nil && p.GetPolicyId() != 0 {
		a["vesta.policy.id"] = p.GetPolicyId()
		a["vesta.policy.generation"] = p.GetGeneration()
		a["vesta.rule.id"] = p.GetRuleId()
		if p.GetName() != "" {
			a["vesta.policy.name"] = p.GetName()
			a["vesta.policy.namespace"] = p.GetNamespace()
		}
	}
	if p := e.GetProcess(); p != nil {
		a["process.pid"] = p.GetTgid()
		a["process.parent_pid"] = p.GetPpid()
		a["process.vpid"] = p.GetNsPid()
		a["process.user.id"] = p.GetUid()
		a["process.group.id"] = p.GetGid()
		a["process.command"] = p.GetComm()
		if p.GetExePath() != "" {
			a["process.executable.path"] = p.GetExePath()
		}
		if len(p.GetArgv()) > 0 {
			a["process.command_args"] = p.GetArgv()
		}
		if p.GetArgvTruncated() {
			a["vesta.process.argv_truncated"] = true
		}
		if x := p.GetExe(); x != nil {
			a["vesta.process.exe.dev"] = x.GetDev()
			a["vesta.process.exe.ino"] = x.GetIno()
		}
	}
	if len(e.GetChain()) > 0 {
		chain := make([]map[string]any, 0, len(e.GetChain()))
		for _, c := range e.GetChain() {
			chain = append(chain, map[string]any{"pid": c.GetPid(), "command": c.GetComm(), "executable.path": c.GetExePath()})
		}
		a["vesta.process.chain"] = chain
	}
	switch d := e.GetDetail().(type) {
	case *eventv1.Event_Exec:
		a["vesta.exec.argc"] = d.Exec.GetArgc()
		if d.Exec.GetPathTruncated() {
			a["vesta.exec.path_truncated"] = true
		}
	case *eventv1.Event_Net:
		n := d.Net
		if addr, ok := netip.AddrFromSlice(n.GetRemoteAddr()); ok {
			a["network.peer.address"] = addr.String()
		}
		a["network.peer.port"] = n.GetRemotePort()
		switch n.GetProtocol() {
		case 6:
			a["network.transport"] = "tcp"
		case 17:
			a["network.transport"] = "udp"
		default:
			a["vesta.network.protocol"] = n.GetProtocol()
		}
		if n.GetFamily() == eventv1.AddressFamily_ADDRESS_FAMILY_INET6 {
			a["network.type"] = "ipv6"
		} else {
			a["network.type"] = "ipv4"
		}
		a["vesta.network.direction"] = enumName(n.GetDirection().String(), "DIRECTION_")
		a["vesta.network.socket_cookie"] = n.GetSocketCookie()
		a["vesta.rule.verdict"] = enumName(n.GetMatchedVerdict().String(), "RULE_VERDICT_")
	}
	sev := "INFO"
	if e.GetAction() == eventv1.Action_ACTION_DENIED {
		sev = "WARN"
	}
	return logLine{
		// The guest wall clock is informational only; the record time is
		// when the host received the event.
		Timestamp:         received.Format(time.RFC3339Nano),
		ObservedTimestamp: received.Format(time.RFC3339Nano),
		SeverityText:      sev,
		EventName:         "vesta." + enumName(e.GetType().String(), "EVENT_TYPE_"),
		Attributes:        a,
	}
}
