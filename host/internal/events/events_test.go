// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/proto"

	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
	"github.com/dbcrit/vesta/host/internal/metrics"
)

func execEvent() *eventv1.Event {
	return &eventv1.Event{
		Seq: 1, Type: eventv1.EventType_EVENT_TYPE_EXEC, Action: eventv1.Action_ACTION_AUDITED,
		Hook: eventv1.Hook_HOOK_SCHED_PROCESS_EXEC, CgroupId: 77, ContainerId: "c1",
		Policy:  &eventv1.PolicyRef{PolicyId: 1, Generation: 5, RuleId: 2, Name: "guest-lie"},
		Process: &eventv1.Process{Pid: 10, Tgid: 10, Ppid: 1, Comm: "sh", ExePath: "/bin/sh", Argv: []string{"sh", "-c", "id"}},
		Chain:   []*eventv1.Ancestor{{Pid: 1, Comm: "init"}},
		Detail:  &eventv1.Event_Exec{Exec: &eventv1.Exec{Argc: 3}},
	}
}

func connectEvent() *eventv1.Event {
	return &eventv1.Event{
		Seq: 2, Type: eventv1.EventType_EVENT_TYPE_CONNECT, Action: eventv1.Action_ACTION_DENIED,
		Hook:    eventv1.Hook_HOOK_CGROUP_CONNECT4,
		Process: &eventv1.Process{Pid: 11, Tgid: 11, Comm: "curl"},
		Detail: &eventv1.Event_Net{Net: &eventv1.Net{
			Direction: eventv1.Direction_DIRECTION_EGRESS, Family: eventv1.AddressFamily_ADDRESS_FAMILY_INET,
			Protocol: 6, RemoteAddr: []byte{10, 0, 0, 1}, RemotePort: 443, MatchedVerdict: eventv1.RuleVerdict_RULE_VERDICT_DENY,
		}},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*eventv1.Event)
		base   func() *eventv1.Event
		ok     bool
	}{
		{name: "exec ok", base: execEvent, ok: true},
		{name: "connect ok", base: connectEvent, ok: true},
		{name: "seq zero", base: execEvent, mutate: func(e *eventv1.Event) { e.Seq = 0 }},
		{name: "unknown type", base: execEvent, mutate: func(e *eventv1.Event) { e.Type = 99 }},
		{name: "reserved type", base: execEvent, mutate: func(e *eventv1.Event) { e.Type = eventv1.EventType_EVENT_TYPE_PTRACE }},
		{name: "unspecified action", base: execEvent, mutate: func(e *eventv1.Event) { e.Action = 0 }},
		{name: "unknown hook", base: execEvent, mutate: func(e *eventv1.Event) { e.Hook = 42 }},
		{name: "container id with slash", base: execEvent, mutate: func(e *eventv1.Event) { e.ContainerId = "../x" }},
		{name: "container id too long", base: execEvent, mutate: func(e *eventv1.Event) { e.ContainerId = strings.Repeat("a", 129) }},
		{name: "duplicate flag", base: execEvent, mutate: func(e *eventv1.Event) {
			e.Flags = []eventv1.EventFlag{eventv1.EventFlag_EVENT_FLAG_WOULD_DENY, eventv1.EventFlag_EVENT_FLAG_WOULD_DENY}
		}},
		{name: "unknown flag", base: execEvent, mutate: func(e *eventv1.Event) { e.Flags = []eventv1.EventFlag{77} }},
		{name: "too many flags", base: execEvent, mutate: func(e *eventv1.Event) { e.Flags = make([]eventv1.EventFlag, 17) }},
		{name: "long comm", base: execEvent, mutate: func(e *eventv1.Event) { e.Process.Comm = strings.Repeat("c", 17) }},
		{name: "long path", base: execEvent, mutate: func(e *eventv1.Event) { e.Process.ExePath = strings.Repeat("p", 4097) }},
		{name: "argv entries", base: execEvent, mutate: func(e *eventv1.Event) { e.Process.Argv = make([]string, 257) }},
		{name: "argv bytes", base: execEvent, mutate: func(e *eventv1.Event) { e.Process.Argv = []string{strings.Repeat("a", 4000), strings.Repeat("b", 97)} }},
		{name: "chain too long", base: execEvent, mutate: func(e *eventv1.Event) { e.Chain = make([]*eventv1.Ancestor, 9) }},
		{name: "missing process", base: execEvent, mutate: func(e *eventv1.Event) { e.Process = nil }},
		{name: "exec without detail", base: execEvent, mutate: func(e *eventv1.Event) { e.Detail = nil }},
		{name: "connect with exec detail", base: connectEvent, mutate: func(e *eventv1.Event) { e.Detail = &eventv1.Event_Exec{Exec: &eventv1.Exec{}} }},
		{name: "inet with 16 bytes", base: connectEvent, mutate: func(e *eventv1.Event) { e.GetNet().RemoteAddr = make([]byte, 16) }},
		{name: "inet6 ok", base: connectEvent, ok: true, mutate: func(e *eventv1.Event) {
			e.GetNet().Family = eventv1.AddressFamily_ADDRESS_FAMILY_INET6
			e.GetNet().RemoteAddr = make([]byte, 16)
		}},
		{name: "port too big", base: connectEvent, mutate: func(e *eventv1.Event) { e.GetNet().RemotePort = 70000 }},
		{name: "protocol too big", base: connectEvent, mutate: func(e *eventv1.Event) { e.GetNet().Protocol = 300 }},
		{name: "unknown family", base: connectEvent, mutate: func(e *eventv1.Event) { e.GetNet().Family = 9 }},
		{name: "guest host is discarded", base: execEvent, ok: true, mutate: func(e *eventv1.Event) { e.Host = &eventv1.Host{PodName: "evil"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.base()
			if tc.mutate != nil {
				tc.mutate(e)
			}
			err := Validate(e)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			if e.Host != nil {
				t.Fatal("guest-supplied host survived validation")
			}
		})
	}
}

func TestValidateRejectsInvalidUTF8OnDecode(t *testing.T) {
	e := execEvent()
	b, err := proto.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the comm string "sh" into invalid UTF-8.
	i := bytes.Index(b, []byte("sh"))
	b[i] = 0xff
	var got eventv1.Event
	if err := proto.Unmarshal(b, &got); err == nil {
		t.Fatal("proto3 decode accepted invalid UTF-8")
	}
}

type lookup struct{}

func (lookup) Container(id string) (ContainerInfo, bool) {
	if id == "c1" {
		return ContainerInfo{ID: "c1", Name: "app", Image: "registry.example/app:1", ImageDigest: "sha256:abc"}, true
	}
	return ContainerInfo{}, false
}

func (lookup) Policy(gen uint64, id uint32) (PolicyInfo, bool) {
	if gen == 5 && id == 1 {
		return PolicyInfo{Name: "baseline", Namespace: "payments", UID: "u1"}, true
	}
	return PolicyInfo{}, false
}

func TestEnrichUsesOnlyTrustedSources(t *testing.T) {
	sb := SandboxInfo{Node: "n1", SandboxID: "sb1", PodName: "p", PodNamespace: "payments", PodUID: "uid", RuntimeHandler: "kata-qemu-vesta"}
	now := time.Unix(100, 5)

	e := execEvent()
	rec := Enrich(e, sb, lookup{}, now)
	h := e.GetHost()
	if h.GetPodName() != "p" || h.GetNode() != "n1" || h.GetContainerName() != "app" || h.GetImageDigest() != "sha256:abc" || h.GetReceivedUnixNs() != now.UnixNano() {
		t.Fatalf("host = %v", h)
	}
	if rec.ContainerID != "c1" || rec.GuestContainerID != "c1" {
		t.Fatalf("record = %+v", rec)
	}
	if p := e.GetPolicy(); p.GetName() != "baseline" || p.GetNamespace() != "payments" || p.GetUid() != "u1" {
		t.Fatalf("policy = %v", p)
	}

	// Unknown container and policy: nothing guest-supplied is echoed as
	// host data.
	e = execEvent()
	e.ContainerId = "other"
	e.Policy.Generation = 4
	rec = Enrich(e, sb, lookup{}, now)
	if rec.ContainerID != "" || e.GetHost().GetContainerName() != "" || e.GetPolicy().GetName() != "" {
		t.Fatalf("unmatched lookups leaked data: %+v %v", rec, e)
	}
	if rec.GuestContainerID != "other" {
		t.Fatalf("guest container id = %q", rec.GuestContainerID)
	}
}

func TestJSONLinesOTelAttributes(t *testing.T) {
	var buf bytes.Buffer
	j := NewJSONLines(&buf)
	sb := SandboxInfo{Node: "n1", SandboxID: "sb1", PodName: "p", PodNamespace: "ns", PodUID: "uid"}
	for _, e := range []*eventv1.Event{execEvent(), connectEvent()} {
		if err := j.Export(Enrich(e, sb, lookup{}, time.Unix(1, 0))); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Flush(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	var exec, conn logLine
	if err := json.Unmarshal([]byte(lines[0]), &exec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &conn); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"k8s.pod.name": "p", "k8s.namespace.name": "ns", "k8s.node.name": "n1", "container.id": "c1",
		"k8s.container.name": "app", "process.executable.path": "/bin/sh", "vesta.action": "audited",
		"vesta.policy.name": "baseline",
	} {
		if exec.Attributes[k] != want {
			t.Errorf("exec %s = %v, want %v", k, exec.Attributes[k], want)
		}
	}
	if exec.EventName != "vesta.exec" || exec.SeverityText != "INFO" {
		t.Errorf("exec header %+v", exec)
	}
	for k, want := range map[string]any{"network.peer.address": "10.0.0.1", "network.peer.port": float64(443), "network.transport": "tcp", "network.type": "ipv4"} {
		if conn.Attributes[k] != want {
			t.Errorf("connect %s = %v, want %v", k, conn.Attributes[k], want)
		}
	}
	if conn.SeverityText != "WARN" {
		t.Errorf("denied event severity %s", conn.SeverityText)
	}
	if _, ok := conn.Attributes["container.id"]; ok {
		t.Error("container.id set for an event without a matched container")
	}
}

type countingExporter struct {
	mu sync.Mutex
	n  int
}

func (c *countingExporter) Export(Record) error { c.mu.Lock(); c.n++; c.mu.Unlock(); return nil }
func (c *countingExporter) Flush() error        { return nil }

func TestPipelineRateLimitAndShare(t *testing.T) {
	m := metrics.New()
	exp := &countingExporter{}
	p := NewPipeline(PipelineConfig{QueueSize: 100, PerSandboxRate: 1, PerSandboxBurst: 10, PerSandboxInflight: 5}, exp, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	flood, calm := p.NewSource(), p.NewSource()
	accepted := 0
	for range 50 {
		if flood.Submit(Enrich(execEvent(), SandboxInfo{}, nil, time.Now())) {
			accepted++
		}
	}
	// Nothing drains yet: the flooding sandbox is capped by its share.
	if accepted != 5 {
		t.Fatalf("flooding source accepted %d, want 5 (its inflight share)", accepted)
	}
	if !calm.Submit(Enrich(execEvent(), SandboxInfo{}, nil, time.Now())) {
		t.Fatal("a flooding sandbox starved another sandbox")
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues(DropQueueFull)); got < 5 {
		t.Fatalf("queue_full drops = %v, want >= 5", got)
	}
	if testutil.ToFloat64(m.EventsDropped.WithLabelValues(DropRateLimited)) == 0 {
		t.Fatal("rate limit never applied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		exp.mu.Lock()
		n := exp.n
		exp.mu.Unlock()
		if n == 6 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if exp.n != 6 {
		t.Fatalf("exported %d, want 6", exp.n)
	}
	if testutil.ToFloat64(m.EventsTotal.WithLabelValues("exec", "audited")) != 6 {
		t.Fatal("events_total not counted")
	}
}
