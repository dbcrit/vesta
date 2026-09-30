// SPDX-License-Identifier: Apache-2.0
//! Container cgroup lookup (ARCHITECTURE §2.5, docs/compat/kata-4.2.md §4).
//!
//! `BindContainer.cgroup_path` is the OCI `linux.cgroupsPath` verbatim. The
//! guest directory is derived with kata-agent 4.2's rules
//! (rustjail/src/container.rs, cgroups/systemd/cgroups_path.rs):
//! - `slice:prefix:name` (systemd manager, agent not PID 1):
//!   `<expanded slice>/<prefix>-<name>.scope`, `::` = `system.slice:kata_agent:<cid>`;
//! - otherwise (cgroupfs manager): `:` replaced by `/`, empty = `/<cid>`.
//!
//! The result is opened beneath the cgroup2 root with openat2
//! RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV, so neither `..`
//! nor symlinks can escape; the cgroup id is the directory's inode number.

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, ResolveFlags};

pub const MAX_CGROUP_PATH: usize = 4096;
pub const MAX_CONTAINER_ID: usize = 128;
const MAX_DEPTH: usize = 32;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

const DEFAULT_SLICE: &str = "system.slice";
const SLICE_SUFFIX: &str = ".slice";
const SCOPE_SUFFIX: &str = ".scope";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("invalid container id")]
    ContainerId,
    #[error("cgroup path longer than {MAX_CGROUP_PATH} bytes")]
    TooLong,
    #[error("invalid cgroup path: {0}")]
    Invalid(&'static str),
}

/// CRI container ids: `[A-Za-z0-9_.-]{1,128}` (covers the 64-hex form), not `.`/`..`.
pub fn validate_container_id(cid: &str) -> Result<(), PathError> {
    let ok = !cid.is_empty()
        && cid.len() <= MAX_CONTAINER_ID
        && cid != "."
        && cid != ".."
        && cid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(PathError::ContainerId)
    }
}

fn is_systemd_word(s: &str) -> bool {
    // kata: ^[\w\-.]*:[\w\-.]*:[\w\-.]*$ ; restricted to ASCII here.
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn expand_slice(slice: &str) -> Result<String, PathError> {
    if !slice.ends_with(SLICE_SUFFIX) || slice.contains('/') {
        return Err(PathError::Invalid("slice must end in .slice"));
    }
    if slice == "-.slice" {
        return Ok(String::new());
    }
    let mut path = String::new();
    let mut prefix = String::new();
    for sub in slice.trim_end_matches(SLICE_SUFFIX).split('-') {
        if sub.is_empty() {
            return Err(PathError::Invalid("empty slice component"));
        }
        path.push('/');
        path.push_str(&prefix);
        path.push_str(sub);
        path.push_str(SLICE_SUFFIX);
        prefix.push_str(sub);
        prefix.push('-');
    }
    Ok(path)
}

/// Maps an OCI cgroupsPath to a path relative to the cgroup2 root.
pub fn guest_cgroup_path(cgroups_path: &str, container_id: &str) -> Result<PathBuf, PathError> {
    validate_container_id(container_id)?;
    if cgroups_path.len() > MAX_CGROUP_PATH {
        return Err(PathError::TooLong);
    }
    let parts: Vec<&str> = cgroups_path.split(':').collect();
    let systemd = parts.len() == 3 && parts.iter().all(|p| is_systemd_word(p));
    let cpath = if systemd {
        let (slice, prefix, name) = if cgroups_path == "::" {
            (DEFAULT_SLICE, "kata_agent", container_id)
        } else {
            (
                if parts[0].is_empty() {
                    DEFAULT_SLICE
                } else {
                    parts[0]
                },
                parts[1],
                parts[2],
            )
        };
        let unit = if name.ends_with(SLICE_SUFFIX) {
            name.to_string()
        } else if prefix.is_empty() {
            format!("{name}{SCOPE_SUFFIX}")
        } else {
            format!("{prefix}-{name}{SCOPE_SUFFIX}")
        };
        format!("{}/{unit}", expand_slice(slice)?)
    } else if cgroups_path.is_empty() {
        format!("/{container_id}")
    } else {
        cgroups_path.replace(':', "/")
    };
    relative_components(&cpath)
}

fn relative_components(cpath: &str) -> Result<PathBuf, PathError> {
    if cpath.contains('\0') {
        return Err(PathError::Invalid("NUL byte"));
    }
    let mut out = PathBuf::new();
    let mut depth = 0;
    for c in cpath.split('/').filter(|c| !c.is_empty()) {
        if c == "." || c == ".." {
            return Err(PathError::Invalid("'.' or '..' component"));
        }
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(PathError::Invalid("too deep"));
        }
        out.push(c);
    }
    if depth == 0 {
        return Err(PathError::Invalid("resolves to the cgroup root"));
    }
    Ok(out)
}

/// Maps a pod's cgroup parent (NRI `PodSandbox.linux.cgroup_parent`) to a
/// path relative to the cgroup2 root, by the same rules as container paths:
/// a systemd slice is expanded (its containers are `<slice>/<prefix>-<id>.scope`),
/// anything else is a cgroupfs path (its containers are `<parent>/<id>`).
pub fn pod_cgroup_path(cgroup_parent: &str) -> Result<PathBuf, PathError> {
    if cgroup_parent.len() > MAX_CGROUP_PATH {
        return Err(PathError::TooLong);
    }
    if cgroup_parent.ends_with(SLICE_SUFFIX) && !cgroup_parent.contains('/') {
        if !is_systemd_word(cgroup_parent) {
            return Err(PathError::Invalid("invalid slice name"));
        }
        return relative_components(&expand_slice(cgroup_parent)?);
    }
    relative_components(cgroup_parent)
}

/// Parses a configured protected cgroup path (relative to the cgroup root).
pub fn protected_path(p: &str) -> Result<PathBuf, PathError> {
    if p.len() > MAX_CGROUP_PATH {
        return Err(PathError::TooLong);
    }
    relative_components(p)
}

/// Opens `rel` beneath `root` (an O_PATH directory fd of the cgroup2 mount)
/// and returns the cgroup id. `Ok(None)` if it does not exist yet.
pub fn lookup_cgroup_id(root: &impl AsFd, rel: &Path) -> std::io::Result<Option<u64>> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV;
    let fd = match rustix::fs::openat2(root, rel, flags, Mode::empty(), resolve) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(cgroup_id_of(&fd)?))
}

fn cgroup_id_of(fd: &OwnedFd) -> std::io::Result<u64> {
    let st = rustix::fs::fstatfs(fd)?;
    if crate::sysinfo::f_type(&st) != CGROUP2_SUPER_MAGIC {
        return Err(std::io::Error::other("not on a cgroup2 filesystem"));
    }
    Ok(rustix::fs::fstat(fd)?.st_ino)
}

/// Opens the cgroup2 root as an O_PATH directory.
pub fn open_root(path: &Path) -> std::io::Result<OwnedFd> {
    let fd = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    cgroup_id_of(&fd)?;
    Ok(fd)
}

/// The calling process's cgroup2 path relative to the cgroup root.
pub fn self_cgroup_rel() -> std::io::Result<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup")?;
    let rel = content
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| std::io::Error::other("no cgroup2 entry in /proc/self/cgroup"))?;
    Ok(PathBuf::from(rel.trim_start_matches('/')))
}

/// The cgroup id of the calling process (its cgroup2 directory's inode).
pub fn self_cgroup_id(cgroup_root: &Path) -> std::io::Result<u64> {
    let path = cgroup_root.join(self_cgroup_rel()?);
    Ok(rustix::fs::stat(&path)?.st_ino)
}

fn skip_vanished<T>(r: std::io::Result<T>) -> std::io::Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Collects the ids of every cgroup below `root`, bounded by `max` entries
/// and MAX_DEPTH levels. Used to garbage-collect bindings of removed cgroups.
/// Cgroups removed during the walk (container churn) are skipped.
pub fn existing_cgroup_ids(
    root: &Path,
    max: usize,
) -> std::io::Result<std::collections::HashSet<u64>> {
    let mut ids = std::collections::HashSet::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = if depth == 0 {
            std::fs::read_dir(&dir)?
        } else {
            match skip_vanished(std::fs::read_dir(&dir))? {
                Some(e) => e,
                None => continue,
            }
        };
        for entry in entries {
            let Some(entry) = skip_vanished(entry)? else {
                continue;
            };
            let Some(ft) = skip_vanished(entry.file_type())? else {
                continue;
            };
            if !ft.is_dir() {
                continue;
            }
            if ids.len() >= max {
                return Err(std::io::Error::other("too many cgroups"));
            }
            ids.insert(std::os::unix::fs::DirEntryExt::ino(&entry));
            if depth + 1 < MAX_DEPTH {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn systemd_paths_match_kata_agent() {
        let p =
            guest_cgroup_path("kubepods-burstable-pod1234.slice:cri-containerd:abc", CID).unwrap();
        assert_eq!(
            p,
            PathBuf::from(
                "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-abc.scope"
            )
        );
        assert_eq!(
            guest_cgroup_path("system.slice:kata_agent:123", CID).unwrap(),
            PathBuf::from("system.slice/kata_agent-123.scope")
        );
        assert_eq!(
            guest_cgroup_path("::", CID).unwrap(),
            PathBuf::from(format!("system.slice/kata_agent-{CID}.scope"))
        );
        assert_eq!(
            guest_cgroup_path(":p:n", CID).unwrap(),
            PathBuf::from("system.slice/p-n.scope")
        );
        assert_eq!(
            guest_cgroup_path("-.slice::n", CID).unwrap(),
            PathBuf::from("n.scope")
        );
        assert_eq!(
            guest_cgroup_path("a.slice:p:x.slice", CID).unwrap(),
            PathBuf::from("a.slice/x.slice")
        );
        assert!(guest_cgroup_path("bad:p:n", CID).is_err());
        assert!(guest_cgroup_path("a--b.slice:p:n", CID).is_err());
    }

    #[test]
    fn pod_paths_are_parents_of_container_paths() {
        let pod = pod_cgroup_path("kubepods-burstable-pod1234.slice").unwrap();
        let ctr =
            guest_cgroup_path("kubepods-burstable-pod1234.slice:cri-containerd:abc", CID).unwrap();
        assert_eq!(ctr.parent(), Some(pod.as_path()));

        let pod = pod_cgroup_path("/kubepods/burstable/pod1").unwrap();
        let ctr = guest_cgroup_path("/kubepods/burstable/pod1/abc", CID).unwrap();
        assert_eq!(ctr.parent(), Some(pod.as_path()));

        assert!(pod_cgroup_path("").is_err(), "cgroup root");
        assert!(pod_cgroup_path("-.slice").is_err(), "root slice");
        assert!(pod_cgroup_path("/a/../b").is_err());
        assert!(pod_cgroup_path("a--b.slice").is_err());
        assert!(pod_cgroup_path("bad name.slice").is_err());
        assert!(pod_cgroup_path(&"a/".repeat(3000)).is_err());
    }

    #[test]
    fn cgroupfs_paths() {
        assert_eq!(
            guest_cgroup_path("/kubepods/pod1/abc", CID).unwrap(),
            PathBuf::from("kubepods/pod1/abc")
        );
        assert_eq!(guest_cgroup_path("", CID).unwrap(), PathBuf::from(CID));
        assert_eq!(
            guest_cgroup_path("/a//b/", CID).unwrap(),
            PathBuf::from("a/b")
        );
        // Not the systemd shape (slash inside a field), so ':' becomes '/'.
        assert_eq!(
            guest_cgroup_path("/a/b:c:d", CID).unwrap(),
            PathBuf::from("a/b/c/d")
        );
    }

    #[test]
    fn rejects_escapes() {
        for p in [
            "/../etc",
            "/a/../../b",
            "..",
            "/a/./b",
            "/",
            "a\0b",
            "/a:..:b",
        ] {
            assert!(guest_cgroup_path(p, CID).is_err(), "{p:?}");
        }
        assert_eq!(
            guest_cgroup_path(&"a/".repeat(2049), CID),
            Err(PathError::TooLong)
        );
        assert!(guest_cgroup_path(&"/a".repeat(33), CID).is_err());
    }

    #[test]
    fn container_ids() {
        assert!(validate_container_id(CID).is_ok());
        assert!(validate_container_id("my-ctr_1.2").is_ok());
        for bad in ["", ".", "..", "a/b", "a b", &"x".repeat(129)] {
            assert!(validate_container_id(bad).is_err(), "{bad:?}");
        }
        assert!(guest_cgroup_path("", "../x").is_err());
    }

    #[test]
    fn scan_skips_vanished_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::create_dir_all(dir.path().join("c")).unwrap();
        let ids = existing_cgroup_ids(dir.path(), 100).unwrap();
        assert_eq!(ids.len(), 3);
        assert!(existing_cgroup_ids(&dir.path().join("missing"), 100).is_err());
        assert!(
            skip_vanished::<()>(Err(std::io::ErrorKind::NotFound.into()))
                .unwrap()
                .is_none()
        );
        assert!(skip_vanished::<()>(Err(std::io::ErrorKind::PermissionDenied.into())).is_err());
    }

    #[test]
    fn protected_paths() {
        assert_eq!(
            protected_path("/system.slice/kata-agent.service").unwrap(),
            PathBuf::from("system.slice/kata-agent.service")
        );
        assert!(protected_path("a/../b").is_err());
        assert!(protected_path("/").is_err());
    }

    #[test]
    fn lookup_refuses_symlinks_and_non_cgroup_fs() {
        // A tmpfs/overlay directory is not cgroup2: rejected even though it exists.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::os::unix::fs::symlink("/", dir.path().join("link")).unwrap();
        let root =
            rustix::fs::open(dir.path(), OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
        assert!(lookup_cgroup_id(&root, Path::new("a/b")).is_err());
        assert!(lookup_cgroup_id(&root, Path::new("link")).is_err());
        assert_eq!(lookup_cgroup_id(&root, Path::new("missing")).unwrap(), None);
    }
}
