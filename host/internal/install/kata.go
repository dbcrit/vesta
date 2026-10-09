// SPDX-License-Identifier: Apache-2.0

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/dbcrit/vesta/host/internal/hostfs"
)

// Kata 4.x runtime-rs layout as installed by kata-deploy (docs/compat/kata-4.2.md §1).
const (
	shimRelPath = "runtime-rs/bin/containerd-shim-kata-v2"
	// kata-deploy's per-shim copy, which containerd's kata-qemu-runtime-rs
	// handler points at, then the pristine shipped config.
	runtimeConfigRel  = "share/defaults/kata-containers/runtime-rs/runtimes/qemu-runtime-rs/configuration-qemu-runtime-rs.toml"
	pristineConfigRel = "share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml"
	versionRel        = "VERSION"

	// SupportedKataMajor is the Kata major vesta supports; TestedKataVersion
	// is the release the installer was validated against.
	SupportedKataMajor = 4
	TestedKataVersion  = "4.2.0"

	maxConfigSize = 1 << 20
	maxDropIns    = 64
)

// KataInstall describes the Kata installation found on the node.
type KataInstall struct {
	Prefix     string // e.g. /opt/kata
	Version    string
	ShimPath   string
	ConfigPath string
	// DropIns are the entries of the base config's config.d in lexical
	// order. kata-types merges every entry there, not only *.toml
	// (src/libs/kata-types/src/config/drop_in.rs update_from_dropins).
	DropIns []NamedFile
	Config  []byte
}

// NamedFile is a file's base name and contents.
type NamedFile struct {
	Name string
	Data []byte
}

var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$`)

// ValidVersion reports whether v is semver without build metadata and at
// most 63 bytes, so it is usable as a Kubernetes label value and a single
// path component.
func ValidVersion(v string) bool {
	return len(v) <= 63 && semverRe.MatchString(v) && !strings.Contains(v, "..")
}

func majorOf(v string) (int, error) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("version %q is not semver", v)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("version %q: %w", v, err)
	}
	return n, nil
}

// DetectKata checks that runtime-rs Kata 4.x is installed under prefix and
// loads its QEMU base config and drop-ins.
func DetectKata(root *hostfs.Root, prefix string) (*KataInstall, error) {
	k := &KataInstall{Prefix: prefix, ShimPath: path.Join(prefix, shimRelPath)}
	info, err := root.Lstat(k.ShimPath)
	if err != nil {
		return nil, fmt.Errorf("kata runtime-rs shim not found at %s (is kata-deploy installed on this node?): %w", k.ShimPath, err)
	}
	if !info.IsRegular() || info.Mode.Perm()&0o111 == 0 {
		return nil, fmt.Errorf("kata shim %s is not an executable regular file", k.ShimPath)
	}
	// kata-deploy 4.2 installs per-component tarballs and no longer writes
	// VERSION; the runtime-rs layout checked below then stands in for the
	// major version check, and Version stays empty.
	vb, err := root.ReadFile(path.Join(prefix, versionRel), 256)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("cannot determine the Kata version: %w", err)
	default:
		k.Version = strings.TrimSpace(string(vb))
		major, err := majorOf(k.Version)
		if err != nil {
			return nil, fmt.Errorf("kata version: %w", err)
		}
		if major != SupportedKataMajor {
			return nil, fmt.Errorf("kata %s is not supported (need %d.x, tested with %s)", k.Version, SupportedKataMajor, TestedKataVersion)
		}
	}
	for _, rel := range []string{runtimeConfigRel, pristineConfigRel} {
		p := path.Join(prefix, rel)
		b, err := root.ReadFile(p, maxConfigSize)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read kata config: %w", err)
		}
		k.ConfigPath, k.Config = p, b
		break
	}
	if k.ConfigPath == "" {
		return nil, fmt.Errorf("no qemu-runtime-rs configuration under %s", prefix)
	}
	dropDir := path.Join(path.Dir(k.ConfigPath), "config.d")
	names, err := root.ReadDir(dropDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read kata drop-ins: %w", err)
	}
	for _, n := range names {
		if len(k.DropIns) == maxDropIns {
			return nil, fmt.Errorf("more than %d drop-ins in %s", maxDropIns, dropDir)
		}
		b, err := root.ReadFile(path.Join(dropDir, n), maxConfigSize)
		if err != nil {
			return nil, fmt.Errorf("read kata drop-in: %w", err)
		}
		k.DropIns = append(k.DropIns, NamedFile{Name: n, Data: b})
	}
	return k, nil
}
