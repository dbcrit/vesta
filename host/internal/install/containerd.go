// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/dbcrit/vesta/host/internal/hostfs"
)

// Flavor is how containerd is managed on the node.
type Flavor string

const (
	FlavorContainerd Flavor = "containerd"
	FlavorK3s        Flavor = "k3s"
	FlavorRKE2       Flavor = "rke2"
)

// containerd locations (docs/compat/kata-4.2.md §5, mirroring kata-deploy
// config.rs get_containerd_paths).
const (
	containerdConfig  = "/etc/containerd/config.toml"
	containerdConfD   = "/etc/containerd/conf.d"
	vestaImportDropIn = "/opt/vesta/containerd/config.d/vesta.toml"
	dropInFile        = "vesta.toml"
	criRuntimePlugin  = "io.containerd.cri.v1.runtime"
	nriPlugin         = "io.containerd.nri.v1.nri"
	rancherDirFmt     = "/var/lib/rancher/%s/agent/etc/containerd"
	k3sDropInDir      = "config-v3.toml.d"
	backupSuffix      = ".vesta-backup"
)

// ContainerdPlan says where the runtime handler goes on this node.
type ContainerdPlan struct {
	Flavor Flavor
	// DropInPath is the host path of vesta's containerd drop-in.
	DropInPath string
	// ImportsConfig, if set, is the main config whose imports must list
	// DropInPath (containerd < 2.2 or no conf.d import).
	ImportsConfig string
	// Units are the systemd units to restart, in preference order; the
	// first active one is used.
	Units []string
}

var runtimeVersionRe = regexp.MustCompile(`^containerd://v?(\d+)\.(\d+)\.(\d+)`)

// ParseContainerdVersion parses a node's containerRuntimeVersion, e.g.
// "containerd://2.4.1" or "containerd://2.1.5-k3s1".
func ParseContainerdVersion(s string) (major, minor int, err error) {
	m := runtimeVersionRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, fmt.Errorf("container runtime %q is not containerd", s)
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, nil
}

// PlanContainerd decides the drop-in location for this node. containerd
// 2.0 or newer is required.
func PlanContainerd(root *hostfs.Root, runtimeVersion string) (*ContainerdPlan, error) {
	major, minor, err := ParseContainerdVersion(runtimeVersion)
	if err != nil {
		return nil, err
	}
	if major < 2 {
		return nil, fmt.Errorf("containerd %d.%d is not supported (need 2.0 or newer)", major, minor)
	}
	for _, f := range []Flavor{FlavorK3s, FlavorRKE2} {
		dir := fmt.Sprintf(rancherDirFmt, f)
		ok, err := root.Exists(dir + "/config.toml")
		if err != nil {
			return nil, err
		}
		if ok {
			return planRancher(root, f, dir)
		}
	}
	p := &ContainerdPlan{Flavor: FlavorContainerd, Units: []string{"containerd.service"}}
	imports, err := mainImports(root)
	if err != nil {
		return nil, err
	}
	if (major > 2 || minor >= 2) && slices.ContainsFunc(imports, func(s string) bool { return strings.Contains(s, containerdConfD) }) {
		p.DropInPath = containerdConfD + "/" + dropInFile
		return p, nil
	}
	p.DropInPath = vestaImportDropIn
	p.ImportsConfig = containerdConfig
	return p, nil
}

// planRancher uses the drop-in directory next to the k3s/RKE2 template.
// The rendered config must already import it: vesta does not edit the
// template, and edits to the rendered config are lost on restart.
func planRancher(root *hostfs.Root, f Flavor, dir string) (*ContainerdPlan, error) {
	rendered, err := root.ReadFile(dir+"/config.toml", maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("%s: read rendered containerd config: %w", f, err)
	}
	var cfg struct {
		Version int      `toml:"version"`
		Imports []string `toml:"imports"`
	}
	if err := toml.Unmarshal(rendered, &cfg); err != nil {
		return nil, fmt.Errorf("%s: parse rendered containerd config: %w", f, err)
	}
	if cfg.Version < 3 {
		return nil, fmt.Errorf("%s: containerd config version %d is not supported; vesta needs the config v3 template (containerd 2.x)", f, cfg.Version)
	}
	want := dir + "/" + k3sDropInDir
	if !slices.ContainsFunc(cfg.Imports, func(s string) bool { return strings.HasPrefix(s, want+"/") }) {
		return nil, fmt.Errorf("%s: the rendered containerd config does not import %s/*.toml; add that import to %s/config-v3.toml.tmpl and restart %s (vesta does not edit %s templates)", f, want, dir, f, f)
	}
	units := []string{"k3s.service", "k3s-agent.service"}
	if f == FlavorRKE2 {
		units = []string{"rke2-server.service", "rke2-agent.service"}
	}
	return &ContainerdPlan{Flavor: f, DropInPath: want + "/" + dropInFile, Units: units}, nil
}

func mainImports(root *hostfs.Root) ([]string, error) {
	b, err := root.ReadFile(containerdConfig, maxConfigSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read containerd config: %w", err)
	}
	var cfg struct {
		Imports []string `toml:"imports"`
	}
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", containerdConfig, err)
	}
	return cfg.Imports, nil
}

var handlerRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ValidHandler reports whether h is a valid runtime handler / RuntimeClass
// handler name (DNS-1123 label).
func ValidHandler(h string) bool { return handlerRe.MatchString(h) }

// RenderContainerdDropIn renders the runtime handler in the same shape
// kata-deploy writes (runtime/containerd.rs write_containerd_runtime_config).
// The file declares config version 3; containerd migrates each imported
// file from its own version, so it also works when the main config is v2.
//
// With nriValidator it also enables NRI's built-in default validator
// (containerd docs/NRI.md "Default Validator"). It configures no globally
// required plugins, so it changes nothing by itself; it makes the pod
// annotation required-plugins.noderesource.dev/pod: '["vesta"]' effective,
// which fails container creation while the vesta plugin is not registered
// (ARCHITECTURE §2.9).
func RenderContainerdDropIn(handler, shimPath, configPath string, nriValidator bool) ([]byte, error) {
	if !ValidHandler(handler) {
		return nil, fmt.Errorf("invalid runtime handler %q", handler)
	}
	plugins := map[string]any{}
	doc := map[string]any{
		"version": 3,
		"plugins": plugins,
	}
	if nriValidator {
		plugins[nriPlugin] = map[string]any{
			"default_validator": map[string]any{"enable": true},
		}
	}
	maps.Copy(plugins, map[string]any{
		criRuntimePlugin: map[string]any{
			"containerd": map[string]any{
				"runtimes": map[string]any{
					handler: map[string]any{
						"runtime_type":                    "io.containerd." + handler + ".v2",
						"runtime_path":                    shimPath,
						"privileged_without_host_devices": true,
						"pod_annotations":                 []string{"io.katacontainers.*"},
						"container_annotations":           []string{"io.kubernetes.container.terminationMessage*"},
						"options": map[string]any{
							"ConfigPath": configPath,
						},
					},
				},
			},
		},
	})
	var buf bytes.Buffer
	buf.WriteString("# Generated by vesta-install. Registers the " + handler + " runtime handler. Do not edit.\n")
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(true)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("render containerd drop-in: %w", err)
	}
	return buf.Bytes(), nil
}

// EnsureImport adds entry to the imports of the containerd config at p.
// containerd merges imports, so the rest of the config keeps its meaning,
// but re-encoding drops comments; the original is saved once next to it.
func EnsureImport(root *hostfs.Root, p, entry string) (bool, error) {
	return editImports(root, p, func(imports []string) []string {
		if slices.Contains(imports, entry) {
			return nil
		}
		return append(imports, entry)
	})
}

// RemoveImport removes entry from the imports of the containerd config at p.
func RemoveImport(root *hostfs.Root, p, entry string) (bool, error) {
	return editImports(root, p, func(imports []string) []string {
		if !slices.Contains(imports, entry) {
			return nil
		}
		return slices.DeleteFunc(slices.Clone(imports), func(s string) bool { return s == entry })
	})
}

func editImports(root *hostfs.Root, p string, edit func([]string) []string) (bool, error) {
	b, err := root.ReadFile(p, maxConfigSize)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return false, fmt.Errorf("read %s: %w", p, err)
	}
	doc := map[string]any{}
	if !missing {
		if err := toml.Unmarshal(b, &doc); err != nil {
			return false, fmt.Errorf("parse %s: %w", p, err)
		}
	}
	var imports []string
	if raw, ok := doc["imports"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return false, fmt.Errorf("%s: imports is %T, want array", p, raw)
		}
		for _, v := range arr {
			s, ok := v.(string)
			if !ok {
				return false, fmt.Errorf("%s: imports has a %T element", p, v)
			}
			imports = append(imports, s)
		}
	}
	next := edit(imports)
	if next == nil {
		return false, nil
	}
	if missing {
		// No main config: containerd runs on built-in defaults (config
		// version 3 in containerd 2.x); a file with only imports keeps them.
		doc["version"] = 3
	} else if ok, err := root.Exists(p + backupSuffix); err != nil {
		return false, err
	} else if !ok {
		if _, err := root.WriteFile(p+backupSuffix, b, 0o600); err != nil {
			return false, fmt.Errorf("back up %s: %w", p, err)
		}
	}
	if len(next) == 0 {
		delete(doc, "imports")
	} else {
		doc["imports"] = next
	}
	var buf bytes.Buffer
	buf.WriteString("# Edited by vesta-install to register its drop-in; the original is " + path.Base(p) + backupSuffix + ".\n")
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(true)
	if err := enc.Encode(doc); err != nil {
		return false, fmt.Errorf("render %s: %w", p, err)
	}
	perm := fs.FileMode(0o644)
	if !missing {
		if info, err := root.Lstat(p); err == nil {
			perm = info.Mode.Perm()
		}
	}
	return root.WriteFile(p, buf.Bytes(), perm)
}
