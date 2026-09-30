// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// VestaDropInName sorts after every drop-in kata-deploy writes (10- to 50-).
const VestaDropInName = "90-vesta.toml"

// protectedAnnotations must not be overridable per pod under the vesta
// handler, or a pod could boot a non-vesta guest or change its kernel
// command line (docs/compat/kata-4.2.md §7). kernel_verity_params is added
// beyond the contract list: it is part of the kernel command line and is
// enabled by default in Kata 4.2.
var protectedAnnotations = []string{"kernel", "image", "initrd", "kernel_params", "kernel_verity_params", "firmware", "path"}

// vestaKernelParams are appended to the effective kernel_params.
var vestaKernelParams = []string{"lockdown=integrity"}

// KataConfigInput is what GenerateKataConfig needs.
type KataConfigInput struct {
	Base       []byte
	DropIns    []NamedFile
	KernelPath string
	ImagePath  string
	Version    string
}

// GeneratedKataConfig is the vesta runtime config: the node's base config
// and drop-ins copied verbatim, plus vesta's own drop-in.
type GeneratedKataConfig struct {
	Config  []byte
	DropIns []NamedFile // includes VestaDropIn last
}

type qemuOverride struct {
	Kernel            string   `toml:"kernel"`
	Image             string   `toml:"image"`
	Initrd            *string  `toml:"initrd,omitempty"`
	KernelParams      string   `toml:"kernel_params"`
	EnableAnnotations []string `toml:"enable_annotations"`
}

type vestaDropIn struct {
	Hypervisor struct {
		Qemu qemuOverride `toml:"qemu"`
	} `toml:"hypervisor"`
}

// mergeTOML merges src into dst like kata-types: tables merge recursively,
// any other value replaces.
func mergeTOML(dst, src map[string]any) {
	for k, v := range src {
		if st, ok := v.(map[string]any); ok {
			if dt, ok := dst[k].(map[string]any); ok {
				mergeTOML(dt, st)
				continue
			}
		}
		dst[k] = v
	}
}

func effective(base []byte, dropIns []NamedFile) (map[string]any, error) {
	var eff map[string]any
	if err := toml.Unmarshal(base, &eff); err != nil {
		return nil, fmt.Errorf("parse base config: %w", err)
	}
	for _, d := range dropIns {
		var m map[string]any
		if err := toml.Unmarshal(d.Data, &m); err != nil {
			return nil, fmt.Errorf("parse drop-in %s: %w", d.Name, err)
		}
		mergeTOML(eff, m)
	}
	return eff, nil
}

func qemuTable(eff map[string]any) (map[string]any, error) {
	hyp, ok := eff["hypervisor"].(map[string]any)
	if !ok {
		return nil, errors.New("config has no [hypervisor] table")
	}
	if len(hyp) != 1 {
		keys := make([]string, 0, len(hyp))
		for k := range hyp {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return nil, fmt.Errorf("config must configure exactly one hypervisor, found %v", keys)
	}
	q, ok := hyp["qemu"].(map[string]any)
	if !ok {
		return nil, errors.New("base config is not a QEMU config ([hypervisor.qemu] missing)")
	}
	return q, nil
}

func stringField(t map[string]any, k string) (string, error) {
	v, ok := t[k]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("hypervisor.qemu.%s is %T, want string", k, v)
	}
	return s, nil
}

func stringList(t map[string]any, k string) ([]string, error) {
	v, ok := t[k]
	if !ok {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("hypervisor.qemu.%s is %T, want array", k, v)
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("hypervisor.qemu.%s has a %T element", k, e)
		}
		out = append(out, s)
	}
	return out, nil
}

// kernelParams appends vesta's params to the effective ones, replacing any
// existing lockdown= setting. An lsm= override without bpf would silently
// disable BPF LSM, so it is an error.
func kernelParams(cur string) (string, error) {
	var out []string
	for _, f := range strings.Fields(cur) {
		if v, ok := strings.CutPrefix(f, "lsm="); ok && !slices.Contains(strings.Split(v, ","), "bpf") {
			return "", fmt.Errorf("kernel_params sets %q without bpf; BPF LSM would be inactive", f)
		}
		if strings.HasPrefix(f, "lockdown=") {
			continue
		}
		out = append(out, f)
	}
	return strings.Join(append(out, vestaKernelParams...), " "), nil
}

// GenerateKataConfig builds the vesta runtime config from the node's Kata
// QEMU config. Only kernel, image, kernel_params and enable_annotations are
// overridden (and initrd cleared if the base used one); everything else is
// the node's own configuration.
func GenerateKataConfig(in KataConfigInput) (*GeneratedKataConfig, error) {
	for _, d := range in.DropIns {
		if d.Name == VestaDropInName {
			return nil, fmt.Errorf("base config.d already contains %s", VestaDropInName)
		}
	}
	eff, err := effective(in.Base, in.DropIns)
	if err != nil {
		return nil, err
	}
	q, err := qemuTable(eff)
	if err != nil {
		return nil, err
	}
	params, err := stringField(q, "kernel_params")
	if err != nil {
		return nil, err
	}
	annotations, err := stringList(q, "enable_annotations")
	if err != nil {
		return nil, err
	}
	initrd, err := stringField(q, "initrd")
	if err != nil {
		return nil, err
	}

	var o vestaDropIn
	o.Hypervisor.Qemu = qemuOverride{
		Kernel:            in.KernelPath,
		Image:             in.ImagePath,
		EnableAnnotations: slices.DeleteFunc(annotations, func(a string) bool { return slices.Contains(protectedAnnotations, a) }),
	}
	if o.Hypervisor.Qemu.EnableAnnotations == nil {
		o.Hypervisor.Qemu.EnableAnnotations = []string{}
	}
	if initrd != "" {
		empty := ""
		o.Hypervisor.Qemu.Initrd = &empty
	}
	if o.Hypervisor.Qemu.KernelParams, err = kernelParams(params); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Generated by vesta-install for guest version %s. Do not edit.\n", in.Version)
	buf.WriteString("# Points this runtime at the vesta guest kernel and image and stops pods from\n")
	buf.WriteString("# overriding them through annotations.\n")
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(false)
	if err := enc.Encode(o); err != nil {
		return nil, fmt.Errorf("render %s: %w", VestaDropInName, err)
	}
	out := &GeneratedKataConfig{Config: in.Base, DropIns: append(slices.Clone(in.DropIns), NamedFile{Name: VestaDropInName, Data: buf.Bytes()})}

	if err := verifyGenerated(out, o.Hypervisor.Qemu); err != nil {
		return nil, err
	}
	return out, nil
}

// verifyGenerated re-merges the result and checks vesta's overrides are
// what the runtime will see.
func verifyGenerated(g *GeneratedKataConfig, want qemuOverride) error {
	eff, err := effective(g.Config, g.DropIns)
	if err != nil {
		return fmt.Errorf("verify generated config: %w", err)
	}
	q, err := qemuTable(eff)
	if err != nil {
		return fmt.Errorf("verify generated config: %w", err)
	}
	for k, v := range map[string]string{"kernel": want.Kernel, "image": want.Image, "kernel_params": want.KernelParams} {
		if got, _ := stringField(q, k); got != v {
			return fmt.Errorf("verify generated config: %s is %q, want %q", k, got, v)
		}
	}
	if got, _ := stringField(q, "initrd"); got != "" {
		return fmt.Errorf("verify generated config: initrd still set")
	}
	ann, _ := stringList(q, "enable_annotations")
	for _, a := range ann {
		if slices.Contains(protectedAnnotations, a) {
			return fmt.Errorf("verify generated config: annotation %q still enabled", a)
		}
	}
	return nil
}
