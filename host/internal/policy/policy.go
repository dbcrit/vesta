// SPDX-License-Identifier: Apache-2.0

// Package policy loads the Phase 1 static policy file (VestaPolicy-shaped
// YAML, ARCHITECTURE §2.8), validates it strictly and compiles it into the
// channel's PolicyBundle messages. It is a pure transformation: no I/O
// beyond reading the file, no Kubernetes API.
package policy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
)

// Limits from api/proto/vesta/channel/v1/control.proto.
const (
	MaxFileSize   = 4 << 20
	MaxPolicies   = 256 // ApplyPolicy.bundles max
	MaxNameLen    = 253 // PolicyBundle.name
	MaxExecRules  = 4096
	MaxNetRules   = 1024
	MaxPorts      = 64
	MaxPathLen    = 4096
	SchemaVersion = 1
	listKind      = "VestaPolicyList"
)

// Policy is one compiled policy.
type Policy struct {
	ID         uint32
	Namespace  string
	Name       string
	UID        string
	Mode       v1alpha1.Mode
	Failure    v1alpha1.FailurePolicy
	selector   labels.Selector
	containers []string // empty = all
	Bundle     *channelv1.PolicyBundle
}

// Set is an immutable compiled policy set.
type Set struct {
	// Generation is the ApplyPolicy generation this set is sent as.
	Generation uint64
	Policies   []*Policy // sorted by namespace/name; Policies[i].ID == i+1
}

// Bundles returns the PolicyBundle list for ApplyPolicy.
func (s *Set) Bundles() []*channelv1.PolicyBundle {
	if s == nil {
		return nil
	}
	out := make([]*channelv1.PolicyBundle, 0, len(s.Policies))
	for _, p := range s.Policies {
		out = append(out, p.Bundle)
	}
	return out
}

// ByID returns the policy with id, if any.
func (s *Set) ByID(id uint32) (*Policy, bool) {
	if s == nil || id == 0 || int(id) > len(s.Policies) {
		return nil, false
	}
	return s.Policies[id-1], true
}

// Match is the policy selected for one container.
type Match struct {
	Policy *Policy // nil: no policy matched; the container is monitor-only
	// Conflicts counts further matching policies that lost to Policy.
	Conflicts int
}

// Resolve selects the policy for a container. Policies with a
// containerSelector win over pod-wide ones; ties go to the first by
// namespace/name. Pod labels and names come from NRI.
func (s *Set) Resolve(namespace string, podLabels map[string]string, container string) Match {
	var m Match
	if s == nil {
		return m
	}
	ls := labels.Set(podLabels)
	for _, p := range s.Policies {
		if p.Namespace != namespace || !p.selector.Matches(ls) {
			continue
		}
		if len(p.containers) > 0 && !slices.Contains(p.containers, container) {
			continue
		}
		switch {
		case m.Policy == nil:
			m.Policy = p
		case len(p.containers) > 0 && len(m.Policy.containers) == 0:
			m.Policy = p
			m.Conflicts++
		default:
			m.Conflicts++
		}
	}
	return m
}

// LoadFile reads, validates and compiles a policy file. prevGeneration is
// the generation of the previously loaded set (0 if none); the new set's
// generation is strictly greater and, across restarts, normally greater than
// anything sent before because it is derived from the wall clock.
func LoadFile(p string, prevGeneration uint64, now time.Time) (*Set, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open policy file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("policy file %s exceeds %d bytes", p, MaxFileSize)
	}
	pols, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy file %s: %w", p, err)
	}
	gen := max(prevGeneration+1, uint64(max(now.UnixMilli(), 1)))
	return Compile(pols, gen)
}

// Parse strictly decodes one or more YAML documents, each a VestaPolicy or a
// VestaPolicyList. Unknown fields are errors.
func Parse(data []byte) ([]v1alpha1.VestaPolicy, error) {
	rd := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var out []v1alpha1.VestaPolicy
	for i := 0; ; i++ {
		doc, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var tm metav1.TypeMeta
		if err := yaml.Unmarshal(doc, &tm); err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		if tm.APIVersion != v1alpha1.GroupVersion {
			return nil, fmt.Errorf("document %d: apiVersion %q, want %q", i, tm.APIVersion, v1alpha1.GroupVersion)
		}
		switch tm.Kind {
		case v1alpha1.KindVestaPolicy:
			var p v1alpha1.VestaPolicy
			if err := yaml.UnmarshalStrict(doc, &p); err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			out = append(out, p)
		case listKind:
			var l v1alpha1.VestaPolicyList
			if err := yaml.UnmarshalStrict(doc, &l); err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			for j, p := range l.Items {
				if p.APIVersion != v1alpha1.GroupVersion || p.Kind != v1alpha1.KindVestaPolicy {
					return nil, fmt.Errorf("document %d item %d: want %s %s", i, j, v1alpha1.GroupVersion, v1alpha1.KindVestaPolicy)
				}
			}
			out = append(out, l.Items...)
		default:
			return nil, fmt.Errorf("document %d: unsupported kind %q", i, tm.Kind)
		}
	}
	return out, nil
}

// Compile validates pols and turns them into a Set with the given generation.
func Compile(pols []v1alpha1.VestaPolicy, generation uint64) (*Set, error) {
	if generation == 0 {
		return nil, errors.New("generation must be > 0")
	}
	if len(pols) > MaxPolicies {
		return nil, fmt.Errorf("%d policies, at most %d are supported", len(pols), MaxPolicies)
	}
	sorted := slices.Clone(pols)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Name < sorted[j].Name
	})
	set := &Set{Generation: generation}
	var errs []error
	var nextID uint32
	for i := range sorted {
		vp := &sorted[i]
		key := vp.Namespace + "/" + vp.Name
		if i > 0 && sorted[i-1].Namespace == vp.Namespace && sorted[i-1].Name == vp.Name {
			errs = append(errs, fmt.Errorf("%s: duplicate policy", key))
			continue
		}
		nextID++
		p, err := compileOne(vp, nextID)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
			continue
		}
		set.Policies = append(set.Policies, p)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return set, nil
}

func compileOne(vp *v1alpha1.VestaPolicy, id uint32) (*Policy, error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for _, m := range validation.IsDNS1123Subdomain(vp.Name) {
		add("metadata.name: %s", m)
	}
	if vp.Namespace == "" {
		add("metadata.namespace is required")
	}
	for _, m := range validation.IsDNS1123Label(vp.Namespace) {
		add("metadata.namespace: %s", m)
	}
	name := vp.Namespace + "/" + vp.Name
	if len(name) > MaxNameLen {
		add("namespace/name longer than %d bytes", MaxNameLen)
	}

	spec := &vp.Spec
	var sel labels.Selector
	if spec.Selector == nil {
		add("spec.selector is required (use {} to select every pod in the namespace)")
	} else {
		s, err := metav1.LabelSelectorAsSelector(spec.Selector)
		if err != nil {
			add("spec.selector: %v", err)
		}
		sel = s
	}
	var containers []string
	if cs := spec.ContainerSelector; cs != nil {
		if len(cs.Names) == 0 {
			add("spec.containerSelector.names must not be empty")
		}
		for _, n := range cs.Names {
			for _, m := range validation.IsDNS1123Label(n) {
				add("spec.containerSelector.names %q: %s", n, m)
			}
		}
		containers = slices.Clone(cs.Names)
	}

	b := &channelv1.PolicyBundle{PolicyId: id, Name: name, SchemaVersion: SchemaVersion}
	mode := spec.Mode
	switch mode {
	case "", v1alpha1.ModeAudit:
		mode = v1alpha1.ModeAudit
		b.Mode = channelv1.Mode_MODE_AUDIT
	case v1alpha1.ModeEnforce:
		b.Mode = channelv1.Mode_MODE_ENFORCE
	default:
		add("spec.mode %q: want Audit or Enforce", spec.Mode)
	}
	failure := spec.FailurePolicy
	switch failure {
	case "", v1alpha1.FailureOpen:
		failure = v1alpha1.FailureOpen
		b.Failure = channelv1.FailurePolicy_FAILURE_POLICY_OPEN
	case v1alpha1.FailureClosed:
		b.Failure = channelv1.FailurePolicy_FAILURE_POLICY_CLOSED
	default:
		add("spec.failurePolicy %q: want Open or Closed", spec.FailurePolicy)
	}

	if pr := spec.Process; pr != nil {
		exec, err := compileExec(pr)
		if err != nil {
			add("spec.process: %v", err)
		}
		b.Exec = exec
	}
	if nr := spec.Network; nr != nil {
		net, err := compileNet(nr)
		if err != nil {
			add("spec.network: %v", err)
		}
		b.Net = net
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &Policy{
		ID: id, Namespace: vp.Namespace, Name: vp.Name, UID: string(vp.UID),
		Mode: mode, Failure: failure, selector: sel, containers: containers, Bundle: b,
	}, nil
}

func verdict(a v1alpha1.Action, dflt channelv1.Verdict) (channelv1.Verdict, error) {
	switch a {
	case "":
		return dflt, nil
	case v1alpha1.ActionAllow:
		return channelv1.Verdict_VERDICT_ALLOW, nil
	case v1alpha1.ActionDeny:
		return channelv1.Verdict_VERDICT_DENY, nil
	default:
		return 0, fmt.Errorf("action %q: want Allow or Deny", a)
	}
}

// ValidExecPath reports whether p is an absolute, clean path without NUL
// within the protocol's length limit.
func ValidExecPath(p string) bool {
	return p != "" && len(p) <= MaxPathLen && strings.HasPrefix(p, "/") &&
		path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

func compileExec(pr *v1alpha1.ProcessRules) (*channelv1.ExecRules, error) {
	if pr.DenyNonImageExec {
		return nil, errors.New("denyNonImageExec is not supported before Phase 3")
	}
	if n := len(pr.Allow) + len(pr.Deny); n > MaxExecRules {
		return nil, fmt.Errorf("%d rules, at most %d", n, MaxExecRules)
	}
	dflt := channelv1.Verdict_VERDICT_ALLOW
	if len(pr.Allow) > 0 {
		dflt = channelv1.Verdict_VERDICT_DENY
	}
	dv, err := verdict(pr.Default, dflt)
	if err != nil {
		return nil, fmt.Errorf("default: %w", err)
	}
	out := &channelv1.ExecRules{DefaultVerdict: dv}
	seen := map[string]bool{}
	var errs []error
	var ruleID uint32
	addRules := func(rules []v1alpha1.PathRule, v channelv1.Verdict, field string) {
		for i, r := range rules {
			if !ValidExecPath(r.Path) {
				errs = append(errs, fmt.Errorf("%s[%d].path %q must be absolute and clean", field, i, r.Path))
				continue
			}
			if seen[r.Path] {
				errs = append(errs, fmt.Errorf("%s[%d].path %q listed twice", field, i, r.Path))
				continue
			}
			seen[r.Path] = true
			ruleID++
			out.Rules = append(out.Rules, &channelv1.ExecRule{RuleId: ruleID, Path: r.Path, Verdict: v})
		}
	}
	addRules(pr.Allow, channelv1.Verdict_VERDICT_ALLOW, "allow")
	addRules(pr.Deny, channelv1.Verdict_VERDICT_DENY, "deny")
	return out, errors.Join(errs...)
}

func compileNet(nr *v1alpha1.NetworkRules) (*channelv1.NetRules, error) {
	if n := len(nr.Egress); n > MaxNetRules {
		return nil, fmt.Errorf("%d egress rules, at most %d", n, MaxNetRules)
	}
	dflt := channelv1.Verdict_VERDICT_ALLOW
	var errs []error
	out := &channelv1.NetRules{}
	var ruleID uint32
	for i, r := range nr.Egress {
		v, err := verdict(r.Action, channelv1.Verdict_VERDICT_ALLOW)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress[%d]: %w", i, err))
			continue
		}
		if v == channelv1.Verdict_VERDICT_ALLOW {
			dflt = channelv1.Verdict_VERDICT_DENY
		}
		pfx, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress[%d].cidr: %w", i, err))
			continue
		}
		if pfx.Addr().Is4In6() || pfx.Addr().Zone() != "" {
			errs = append(errs, fmt.Errorf("egress[%d].cidr %q: mapped or zoned addresses are not allowed", i, r.CIDR))
			continue
		}
		var proto channelv1.Protocol
		switch r.Protocol {
		case v1alpha1.ProtocolAny:
			proto = channelv1.Protocol_PROTOCOL_ANY
		case v1alpha1.ProtocolTCP:
			proto = channelv1.Protocol_PROTOCOL_TCP
		case v1alpha1.ProtocolUDP:
			proto = channelv1.Protocol_PROTOCOL_UDP
		default:
			errs = append(errs, fmt.Errorf("egress[%d].protocol %q: want TCP or UDP", i, r.Protocol))
			continue
		}
		if len(r.Ports) > MaxPorts {
			errs = append(errs, fmt.Errorf("egress[%d]: %d ports, at most %d", i, len(r.Ports), MaxPorts))
			continue
		}
		ports := make([]uint32, 0, len(r.Ports))
		bad := false
		for _, p := range r.Ports {
			if p < 1 || p > 65535 || slices.Contains(ports, uint32(p)) {
				errs = append(errs, fmt.Errorf("egress[%d]: port %d invalid or repeated", i, p))
				bad = true
				break
			}
			ports = append(ports, uint32(p))
		}
		if bad {
			continue
		}
		slices.Sort(ports)
		ruleID++
		out.Egress = append(out.Egress, &channelv1.NetRule{
			RuleId: ruleID, Cidr: pfx.Masked().String(),
			Ports: ports, Protocol: proto, Verdict: v,
		})
	}
	dv, err := verdict(nr.EgressDefault, dflt)
	if err != nil {
		errs = append(errs, fmt.Errorf("egressDefault: %w", err))
	}
	out.DefaultEgress = dv
	return out, errors.Join(errs...)
}
