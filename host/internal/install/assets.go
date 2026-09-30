// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dbcrit/vesta/host/internal/hostfs"
)

// Guest asset names, shipped in the installer image's assets directory and
// installed to /opt/vesta/kata/<version>/ on the node.
const (
	KernelName   = "vmlinux-vesta"
	ImageName    = "vesta-guest.img"
	SumsName     = "SHA256SUMS"
	VersionName  = "VERSION"
	maxSumsBytes = 4096
)

var sumLineRe = regexp.MustCompile(`^([0-9a-f]{64})  \*?([A-Za-z0-9._-]+)$`)

// Assets is the verified content of the installer image's assets directory.
type Assets struct {
	Dir     string
	Version string
	SHA256  map[string]string // name -> hex digest, for KernelName and ImageName
}

// LoadAssets reads VERSION and SHA256SUMS from dir. SHA256SUMS must list
// exactly the kernel and the image, in sha256sum(1) format.
func LoadAssets(dir, version string) (*Assets, error) {
	if version == "" {
		b, err := readSmall(filepath.Join(dir, VersionName), 256)
		if err != nil {
			return nil, fmt.Errorf("guest version: %w", err)
		}
		version = strings.TrimSpace(string(b))
	}
	if !ValidVersion(version) {
		return nil, fmt.Errorf("guest version %q must be semver without build metadata (label-safe)", version)
	}
	b, err := readSmall(filepath.Join(dir, SumsName), maxSumsBytes)
	if err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}
	a := &Assets{Dir: dir, Version: version, SHA256: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := sumLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s: malformed line %q", SumsName, line)
		}
		if m[2] != KernelName && m[2] != ImageName {
			return nil, fmt.Errorf("%s: unexpected file %q", SumsName, m[2])
		}
		if _, dup := a.SHA256[m[2]]; dup {
			return nil, fmt.Errorf("%s: %s listed twice", SumsName, m[2])
		}
		a.SHA256[m[2]] = m[1]
	}
	for _, n := range []string{KernelName, ImageName} {
		if _, ok := a.SHA256[n]; !ok {
			return nil, fmt.Errorf("%s does not list %s", SumsName, n)
		}
	}
	return a, nil
}

func readSmall(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", p, max)
	}
	return b, nil
}

// InstallAssets copies the kernel and image into versionDir on the host.
// Files already there with the expected digest are kept (running VMs may
// be using them); a file with a different digest is an error, because a
// version directory is immutable once installed.
func InstallAssets(root *hostfs.Root, a *Assets, versionDir string) (bool, error) {
	changed := false
	for _, n := range []string{KernelName, ImageName} {
		dst := versionDir + "/" + n
		want := a.SHA256[n]
		got, err := root.HashFile(dst)
		switch {
		case err == nil && got == want:
			continue
		case err == nil:
			return changed, fmt.Errorf("%s exists with sha256 %s, expected %s; refusing to replace an installed version (bump the guest version)", dst, got, want)
		case !errors.Is(err, fs.ErrNotExist):
			return changed, err
		}
		src, err := os.Open(filepath.Join(a.Dir, n))
		if err != nil {
			return changed, fmt.Errorf("open asset: %w", err)
		}
		err = root.CopyFile(dst, src, 0o644, want)
		src.Close()
		if err != nil {
			return changed, fmt.Errorf("install %s: %w", n, err)
		}
		changed = true
	}
	return changed, nil
}
