// SPDX-License-Identifier: Apache-2.0

package hostfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRoot(t *testing.T) (*Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func TestWriteFileAtomicAndIdempotent(t *testing.T) {
	r, dir := newRoot(t)
	changed, err := r.WriteFile("/etc/containerd/conf.d/vesta.toml", []byte("a"), 0o644)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "etc/containerd/conf.d/vesta.toml"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatal(fi, err)
	}
	if changed, err = r.WriteFile("/etc/containerd/conf.d/vesta.toml", []byte("a"), 0o644); err != nil || changed {
		t.Fatalf("rewrite of identical content: changed=%v err=%v", changed, err)
	}
	if changed, err = r.WriteFile("/etc/containerd/conf.d/vesta.toml", []byte("b"), 0o644); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, err = r.WriteFile("/etc/containerd/conf.d/vesta.toml", []byte("b"), 0o600); err != nil || !changed {
		t.Fatal("mode change not applied", changed, err)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "etc/containerd/conf.d"))
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestRefusesSymlinks(t *testing.T) {
	r, dir := newRoot(t)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Intermediate directory is a symlink pointing outside the root.
	if err := os.Symlink(outside, filepath.Join(dir, "opt/vesta")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteFile("/opt/vesta/kata/x", []byte("x"), 0o644); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("write through symlinked dir: %v", err)
	}
	if err := r.MkdirAll("/opt/vesta/kata"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("mkdir through symlinked dir: %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("wrote outside the root: %v", ents)
	}
	// Final component is a symlink: reads refuse it.
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "opt/link")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadFile("/opt/link", 100); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read through final symlink: %v", err)
	}
	// Writing over a symlink replaces the link, never the target.
	if _, err := r.WriteFile("/opt/link", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(secret); string(b) != "s" {
		t.Fatal("symlink target modified")
	}
	info, err := r.Lstat("/opt/link")
	if err != nil || !info.IsRegular() {
		t.Fatal(info, err)
	}
}

func TestRejectsBadPaths(t *testing.T) {
	r, _ := newRoot(t)
	for _, p := range []string{"relative", "/a/../b", "/a//b", "/a/", "", "/a\x00b"} {
		if _, err := r.WriteFile(p, []byte("x"), 0o644); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%q: %v", p, err)
		}
	}
	if _, err := r.WriteFile("/", []byte("x"), 0o644); err == nil {
		t.Error("write to / accepted")
	}
}

func TestCopyFileVerifiesChecksum(t *testing.T) {
	r, dir := newRoot(t)
	data := []byte("kernel image")
	sum := sha256.Sum256(data)
	if err := r.CopyFile("/opt/v/k", bytes.NewReader(data), 0o644, strings.Repeat("0", 64)); err == nil {
		t.Fatal("bad checksum accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "opt/v/k")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("file visible after failed copy")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "opt/v")); len(ents) != 0 {
		t.Fatalf("temp left: %v", ents)
	}
	if err := r.CopyFile("/opt/v/k", bytes.NewReader(data), 0o644, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if got, err := r.HashFile("/opt/v/k"); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatal(got, err)
	}
}

func TestSwapSymlinkAndRemoveAll(t *testing.T) {
	r, dir := newRoot(t)
	if err := r.MkdirAll("/opt/vesta/kata/1.0.0"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if _, err := r.SwapSymlink("/opt/vesta/kata/current", v); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.Readlink(filepath.Join(dir, "opt/vesta/kata/current")); got != v {
			t.Fatalf("current -> %s, want %s", got, v)
		}
	}
	if changed, err := r.SwapSymlink("/opt/vesta/kata/current", "1.1.0"); err != nil || changed {
		t.Fatal(changed, err)
	}
	if _, err := r.SwapSymlink("/opt/vesta/kata/1.0.0", "x"); err == nil {
		t.Fatal("replaced a directory with a symlink")
	}

	// RemoveAll must not follow a symlink out of the tree.
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "opt/vesta/kata/1.0.0/escape")); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveAll("/opt/vesta/kata"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("RemoveAll followed a symlink:", err)
	}
	if ok, _ := r.Exists("/opt/vesta/kata"); ok {
		t.Fatal("tree still exists")
	}
	if err := r.RemoveAll("/opt/vesta/missing"); err != nil {
		t.Fatal(err)
	}
	if removed, err := r.Remove("/opt/nothing"); err != nil || removed {
		t.Fatal(removed, err)
	}
}

func TestReadDirAndLimits(t *testing.T) {
	r, _ := newRoot(t)
	for _, n := range []string{"b.toml", "a.toml"} {
		if _, err := r.WriteFile("/d/"+n, []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names, err := r.ReadDir("/d")
	if err != nil || strings.Join(names, ",") != "a.toml,b.toml" {
		t.Fatal(names, err)
	}
	if _, err := r.ReadFile("/d/a.toml", 3); err == nil {
		t.Fatal("size limit not enforced")
	}
	if _, err := r.ReadDir("/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := r.ReadFile("/missing/x", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}
