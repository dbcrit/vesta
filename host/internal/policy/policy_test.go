// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
)

const good = `
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: payments-baseline, namespace: payments}
spec:
  selector: {matchLabels: {app: payments}}
  mode: Audit
  failurePolicy: Closed
  process:
    allow: [{path: /usr/bin/app}]
    deny: [{path: /usr/bin/curl}]
  network:
    egress:
      - {cidr: 10.1.2.3/8, ports: [443, 80], protocol: TCP}
      - {cidr: "2001:db8::/32", action: Deny}
---
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: api-only, namespace: payments}
spec:
  selector: {}
  containerSelector: {names: [api]}
`

func TestParseAndCompile(t *testing.T) {
	pols, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	set, err := Compile(pols, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Policies) != 2 || set.Generation != 7 {
		t.Fatalf("set = %+v", set)
	}
	// Sorted by namespace/name: api-only gets id 1.
	api, base := set.Policies[0], set.Policies[1]
	if api.Name != "api-only" || api.ID != 1 || base.ID != 2 {
		t.Fatalf("ids: %s=%d %s=%d", api.Name, api.ID, base.Name, base.ID)
	}
	b := base.Bundle
	if b.GetName() != "payments/payments-baseline" || b.GetMode() != channelv1.Mode_MODE_AUDIT ||
		b.GetFailure() != channelv1.FailurePolicy_FAILURE_POLICY_CLOSED || b.GetSchemaVersion() != 1 {
		t.Fatalf("bundle header %v", b)
	}
	if b.GetExec().GetDefaultVerdict() != channelv1.Verdict_VERDICT_DENY || len(b.GetExec().GetRules()) != 2 ||
		b.GetExec().GetRules()[1].GetRuleId() != 2 || b.GetExec().GetRules()[1].GetVerdict() != channelv1.Verdict_VERDICT_DENY {
		t.Fatalf("exec %v", b.GetExec())
	}
	n := b.GetNet()
	if n.GetDefaultEgress() != channelv1.Verdict_VERDICT_DENY || n.GetEgress()[0].GetCidr() != "10.0.0.0/8" ||
		n.GetEgress()[0].GetPorts()[0] != 80 || n.GetEgress()[0].GetProtocol() != channelv1.Protocol_PROTOCOL_TCP ||
		n.GetEgress()[1].GetVerdict() != channelv1.Verdict_VERDICT_DENY {
		t.Fatalf("net %v", n)
	}
	if api.Bundle.GetMode() != channelv1.Mode_MODE_AUDIT || api.Bundle.GetFailure() != channelv1.FailurePolicy_FAILURE_POLICY_OPEN {
		t.Fatalf("defaults %v", api.Bundle)
	}
	if got := len(set.Bundles()); got != 2 {
		t.Fatalf("bundles %d", got)
	}
}

func TestResolve(t *testing.T) {
	pols, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	set, err := Compile(pols, 1)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ns, ctr   string
		labels    map[string]string
		want      string
		conflicts int
	}{
		{ns: "payments", ctr: "api", labels: map[string]string{"app": "payments"}, want: "api-only", conflicts: 1},
		{ns: "payments", ctr: "worker", labels: map[string]string{"app": "payments"}, want: "payments-baseline"},
		{ns: "payments", ctr: "api", labels: map[string]string{"app": "other"}, want: "api-only"},
		{ns: "payments", ctr: "worker", labels: nil, want: ""},
		{ns: "other", ctr: "api", labels: map[string]string{"app": "payments"}, want: ""},
	}
	for _, tc := range tests {
		m := set.Resolve(tc.ns, tc.labels, tc.ctr)
		got := ""
		if m.Policy != nil {
			got = m.Policy.Name
		}
		if got != tc.want || m.Conflicts != tc.conflicts {
			t.Errorf("%s/%s %v: got %q (%d conflicts), want %q (%d)", tc.ns, tc.ctr, tc.labels, got, m.Conflicts, tc.want, tc.conflicts)
		}
	}
	var nilSet *Set
	if m := nilSet.Resolve("a", nil, "b"); m.Policy != nil {
		t.Fatal("nil set matched")
	}
}

func TestValidationErrors(t *testing.T) {
	head := "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p, namespace: ns}\n"
	tests := map[string]string{
		"unknown field":         head + "spec: {selector: {}, bogus: 1}",
		"sha256 not supported":  head + "spec: {selector: {}, process: {allow: [{path: /a, sha256: x}]}}",
		"missing selector":      head + "spec: {}",
		"bad mode":              head + "spec: {selector: {}, mode: Block}",
		"bad failure":           head + "spec: {selector: {}, failurePolicy: Maybe}",
		"relative path":         head + "spec: {selector: {}, process: {deny: [{path: bin/sh}]}}",
		"dotdot path":           head + "spec: {selector: {}, process: {deny: [{path: /usr/../bin/sh}]}}",
		"duplicate path":        head + "spec: {selector: {}, process: {allow: [{path: /a}], deny: [{path: /a}]}}",
		"drift not supported":   head + "spec: {selector: {}, process: {denyNonImageExec: true}}",
		"bad cidr":              head + "spec: {selector: {}, network: {egress: [{cidr: 10.0.0.0/33}]}}",
		"mapped cidr":           head + "spec: {selector: {}, network: {egress: [{cidr: '::ffff:10.0.0.0/104'}]}}",
		"port zero":             head + "spec: {selector: {}, network: {egress: [{cidr: 10.0.0.0/8, ports: [0]}]}}",
		"port repeated":         head + "spec: {selector: {}, network: {egress: [{cidr: 10.0.0.0/8, ports: [1, 1]}]}}",
		"bad protocol":          head + "spec: {selector: {}, network: {egress: [{cidr: 10.0.0.0/8, protocol: SCTP}]}}",
		"bad action":            head + "spec: {selector: {}, network: {egress: [{cidr: 10.0.0.0/8, action: Drop}]}}",
		"bad selector":          head + "spec: {selector: {matchExpressions: [{key: a, operator: Bogus}]}}",
		"empty container names": head + "spec: {selector: {}, containerSelector: {names: []}}",
		"bad namespace":         "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p, namespace: NS_1}\nspec: {selector: {}}",
		"missing namespace":     "apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicy\nmetadata: {name: p}\nspec: {selector: {}}",
		"wrong apiVersion":      "apiVersion: v1\nkind: VestaPolicy\nmetadata: {name: p, namespace: ns}\nspec: {selector: {}}",
		"cluster kind":          "apiVersion: vesta.dev/v1alpha1\nkind: ClusterVestaPolicy\nmetadata: {name: p}\nspec: {selector: {}}",
		"duplicate":             head + "spec: {selector: {}}\n---\n" + head + "spec: {selector: {}}",
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			pols, err := Parse([]byte(doc))
			if err == nil {
				_, err = Compile(pols, 1)
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestListKindAndLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("apiVersion: vesta.dev/v1alpha1\nkind: VestaPolicyList\nitems:\n")
	for i := range MaxPolicies + 1 {
		b.WriteString("- apiVersion: vesta.dev/v1alpha1\n  kind: VestaPolicy\n  metadata: {name: p-" + strconv.Itoa(i) + ", namespace: ns}\n  spec: {selector: {}}\n")
	}
	pols, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != MaxPolicies+1 {
		t.Fatalf("parsed %d", len(pols))
	}
	if _, err := Compile(pols, 1); err == nil {
		t.Fatal("more than MaxPolicies accepted")
	}
	if _, err := Compile(pols[:MaxPolicies], 1); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFileGenerationAndSize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000)
	set, err := LoadFile(p, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if set.Generation != uint64(now.UnixMilli()) {
		t.Fatalf("generation %d", set.Generation)
	}
	// A clock that went backwards still yields a strictly larger generation.
	set2, err := LoadFile(p, set.Generation, now.Add(-time.Hour))
	if err != nil || set2.Generation != set.Generation+1 {
		t.Fatalf("generation %d, %v", set2.Generation, err)
	}
	if err := os.WriteFile(p, make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p, 0, now); err == nil {
		t.Fatal("oversized file accepted")
	}
}
