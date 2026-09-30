// SPDX-License-Identifier: Apache-2.0

// Package hostfs performs file operations on the node's filesystem mounted
// at a root directory (e.g. /host) without following symlinks: every path
// component below the root is opened with O_NOFOLLOW relative to its parent
// directory's descriptor, so a symlink planted anywhere in a path fails the
// operation instead of redirecting it. Writes are atomic (temporary file,
// fsync, rename, fsync of the directory).
package hostfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrUnsafePath reports a symlink or non-directory where a directory was
// expected, or a path that is not absolute and clean.
var ErrUnsafePath = errors.New("unsafe path")

// Root is a host filesystem root.
type Root struct {
	dir string
}

// New returns a Root for dir, which must be an existing absolute directory.
func New(dir string) (*Root, error) {
	if !path.IsAbs(dir) {
		return nil, fmt.Errorf("host root %q must be absolute", dir)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("host root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("host root %s is not a directory", dir)
	}
	return &Root{dir: path.Clean(dir)}, nil
}

// Dir returns the root directory as seen by this process.
func (r *Root) Dir() string { return r.dir }

// split validates an absolute host path and returns its components.
func split(p string) ([]string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return nil, fmt.Errorf("%w: %q must be absolute and clean", ErrUnsafePath, p)
	}
	if p == "/" {
		return nil, nil
	}
	return strings.Split(p[1:], "/"), nil
}

func dirFlags() int { return unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC }

// openDir opens the directory at comps below the root, creating missing
// components with mode 0755 when create is set.
func (r *Root) openDir(comps []string, create bool) (int, error) {
	fd, err := unix.Open(r.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open host root: %w", err)
	}
	for i, c := range comps {
		nfd, err := unix.Openat(fd, c, dirFlags(), 0)
		if errors.Is(err, unix.ENOENT) && create {
			if merr := unix.Mkdirat(fd, c, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
				unix.Close(fd)
				return -1, fmt.Errorf("mkdir /%s: %w", strings.Join(comps[:i+1], "/"), merr)
			}
			nfd, err = unix.Openat(fd, c, dirFlags(), 0)
		}
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, fmt.Errorf("%w: /%s is a symlink or not a directory", ErrUnsafePath, strings.Join(comps[:i+1], "/"))
			}
			return -1, fmt.Errorf("open /%s: %w", strings.Join(comps[:i+1], "/"), err)
		}
		fd = nfd
	}
	return fd, nil
}

// parent opens the parent directory of p and returns it with p's base name.
func (r *Root) parent(p string, create bool) (int, string, error) {
	comps, err := split(p)
	if err != nil {
		return -1, "", err
	}
	if len(comps) == 0 {
		return -1, "", fmt.Errorf("%w: the root itself", ErrUnsafePath)
	}
	fd, err := r.openDir(comps[:len(comps)-1], create)
	if err != nil {
		return -1, "", err
	}
	return fd, comps[len(comps)-1], nil
}

// Info describes a path without following a final symlink.
type Info struct {
	Mode fs.FileMode
	Size int64
}

// IsRegular reports a regular file.
func (i Info) IsRegular() bool { return i.Mode.IsRegular() }

// IsDir reports a directory.
func (i Info) IsDir() bool { return i.Mode.IsDir() }

// IsSymlink reports a symlink.
func (i Info) IsSymlink() bool { return i.Mode&fs.ModeSymlink != 0 }

func infoFromStat(st *unix.Stat_t) Info {
	m := fs.FileMode(st.Mode & 0o777)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFREG:
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	default:
		m |= fs.ModeIrregular
	}
	return Info{Mode: m, Size: st.Size}
}

// Lstat returns information about p. A missing file yields an error
// satisfying errors.Is(err, fs.ErrNotExist).
func (r *Root) Lstat(p string) (Info, error) {
	dfd, base, err := r.parent(p, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Info{}, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		return Info{}, err
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Info{}, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		return Info{}, fmt.Errorf("stat %s: %w", p, err)
	}
	return infoFromStat(&st), nil
}

// Exists reports whether p exists (without following a final symlink).
func (r *Root) Exists(p string) (bool, error) {
	_, err := r.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// openFile opens a regular file for reading.
func (r *Root) openFile(p string) (*os.File, error) {
	dfd, base, err := r.parent(p, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		return nil, err
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		case errors.Is(err, unix.ELOOP):
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, p)
		}
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, p)
	}
	return os.NewFile(uintptr(fd), p), nil
}

// ReadFile reads the regular file p, failing if it exceeds max bytes.
func (r *Root) ReadFile(p string, max int64) ([]byte, error) {
	f, err := r.openFile(p)
	if err != nil {
		return nil, err
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

// HashFile returns the hex SHA-256 of the regular file p.
func (r *Root) HashFile(p string) (string, error) {
	f, err := r.openFile(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReadDir lists the names in directory p, sorted.
func (r *Root) ReadDir(p string) ([]string, error) {
	comps, err := split(p)
	if err != nil {
		return nil, err
	}
	fd, err := r.openDir(comps, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", p, err)
	}
	slices.Sort(names)
	return names, nil
}

// MkdirAll creates directory p and its parents with mode 0755.
func (r *Root) MkdirAll(p string) error {
	comps, err := split(p)
	if err != nil {
		return err
	}
	fd, err := r.openDir(comps, true)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

func tmpName(base string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return "." + base + ".vesta-tmp-" + hex.EncodeToString(b[:]), nil
}

// WriteFile atomically replaces p with data and mode perm, creating parent
// directories. It reports whether anything changed: an identical existing
// file is left untouched.
func (r *Root) WriteFile(p string, data []byte, perm fs.FileMode) (bool, error) {
	if cur, err := r.ReadFile(p, int64(len(data))); err == nil && bytes.Equal(cur, data) {
		if info, err := r.Lstat(p); err == nil && info.Mode.Perm() == perm.Perm() {
			return false, nil
		}
	}
	err := r.writeAtomic(p, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	return err == nil, err
}

// CopyFile atomically writes the contents of src to p with mode perm and
// verifies the written bytes hash to wantSHA256 (hex) before the rename, so
// a partial or corrupted copy never becomes visible.
func (r *Root) CopyFile(p string, src io.Reader, perm fs.FileMode, wantSHA256 string) error {
	return r.writeAtomic(p, perm, func(w io.Writer) error {
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(w, h), src); err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
			return fmt.Errorf("checksum mismatch: got %s, want %s", got, wantSHA256)
		}
		return nil
	})
}

func (r *Root) writeAtomic(p string, perm fs.FileMode, fill func(io.Writer) error) (retErr error) {
	dfd, base, err := r.parent(p, true)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	tmp, err := tmpName(base)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", p, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		if retErr != nil {
			_ = unix.Unlinkat(dfd, tmp, 0)
		}
	}()
	if err := fill(f); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", p, err)
	}
	// The umask may have narrowed the create mode.
	if err := f.Chmod(perm.Perm()); err != nil {
		f.Close()
		return fmt.Errorf("chmod %s: %w", p, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", p, err)
	}
	// rename(2) replaces the directory entry itself; a symlink at the
	// destination is replaced, not followed.
	if err := unix.Renameat(dfd, tmp, dfd, base); err != nil {
		return fmt.Errorf("rename into %s: %w", p, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("fsync dir of %s: %w", p, err)
	}
	return nil
}

// Readlink returns the target of symlink p.
func (r *Root) Readlink(p string) (string, error) {
	dfd, base, err := r.parent(p, false)
	if err != nil {
		return "", err
	}
	defer unix.Close(dfd)
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dfd, base, buf)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		return "", fmt.Errorf("readlink %s: %w", p, err)
	}
	return string(buf[:n]), nil
}

// SwapSymlink atomically points symlink p at target. An existing symlink or
// file at p is replaced; a directory is an error.
func (r *Root) SwapSymlink(p, target string) (bool, error) {
	if cur, err := r.Readlink(p); err == nil && cur == target {
		return false, nil
	}
	dfd, base, err := r.parent(p, true)
	if err != nil {
		return false, err
	}
	defer unix.Close(dfd)
	tmp, err := tmpName(base)
	if err != nil {
		return false, err
	}
	if err := unix.Symlinkat(target, dfd, tmp); err != nil {
		return false, fmt.Errorf("symlink for %s: %w", p, err)
	}
	if err := unix.Renameat(dfd, tmp, dfd, base); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return false, fmt.Errorf("rename symlink into %s: %w", p, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return true, fmt.Errorf("fsync dir of %s: %w", p, err)
	}
	return true, nil
}

// Remove deletes the file or symlink p. A missing p is not an error; it
// reports whether something was removed.
func (r *Root) Remove(p string) (bool, error) {
	dfd, base, err := r.parent(p, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(dfd)
	if err := unix.Unlinkat(dfd, base, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("remove %s: %w", p, err)
	}
	return true, nil
}

// RemoveAll deletes p recursively without following symlinks. A missing p
// is not an error.
func (r *Root) RemoveAll(p string) error {
	dfd, base, err := r.parent(p, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	defer unix.Close(dfd)
	return removeAt(dfd, base, p, 0)
}

const maxRemoveDepth = 64

func removeAt(dfd int, name, display string, depth int) error {
	if depth > maxRemoveDepth {
		return fmt.Errorf("%s: directory tree too deep", display)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", display, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(dfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove %s: %w", display, err)
		}
		return nil
	}
	fd, err := unix.Openat(dfd, name, dirFlags(), 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", display, err)
	}
	f := os.NewFile(uintptr(fd), display)
	names, err := f.Readdirnames(-1)
	if err != nil {
		f.Close()
		return fmt.Errorf("read dir %s: %w", display, err)
	}
	for _, n := range names {
		if err := removeAt(fd, n, display+"/"+n, depth+1); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()
	if err := unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove %s: %w", display, err)
	}
	return nil
}
