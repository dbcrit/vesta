// SPDX-License-Identifier: Apache-2.0
//! Resolves exec rule paths to (s_dev, ino) inside a container's rootfs.
//!
//! kata-agent 4.2 bind-mounts every container rootfs at
//! `/run/kata-containers/<cid>/rootfs` (src/agent/src/rpc.rs, `setup_bundle`).
//! Paths are resolved with openat2(RESOLVE_IN_ROOT), so absolute symlinks and
//! `..` inside the (untrusted) image stay inside that rootfs, and with O_PATH
//! so nothing is actually opened for I/O (no FIFO blocking, no device side effects).

use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};

use crate::abi::s_dev_from_st_dev;
use crate::cgroup::validate_container_id;

/// (s_dev, ino) of an executable file.
pub type FileId = (u32, u64);

pub trait ExecResolver {
    /// Resolves `path` (absolute, validated) in the rootfs of `container_id`.
    fn resolve(&self, container_id: &str, path: &str) -> Result<FileId, String>;
}

#[derive(Debug, Clone)]
pub struct RootfsResolver {
    base: PathBuf,
}

impl RootfsResolver {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn rootfs(&self, container_id: &str) -> Result<PathBuf, String> {
        validate_container_id(container_id).map_err(|e| e.to_string())?;
        Ok(self.base.join(container_id).join("rootfs"))
    }
}

impl ExecResolver for RootfsResolver {
    fn resolve(&self, container_id: &str, path: &str) -> Result<FileId, String> {
        let rootfs = self.rootfs(container_id)?;
        let root = rustix::fs::open(
            &rootfs,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("open rootfs {}: {e}", rootfs.display()))?;
        resolve_in_root(&root, path)
    }
}

/// Resolves `path` beneath the directory fd `root` as if `root` were `/`.
pub fn resolve_in_root(root: &impl std::os::fd::AsFd, path: &str) -> Result<FileId, String> {
    let rel = Path::new(path.trim_start_matches('/'));
    if rel.as_os_str().is_empty() {
        return Err("path is the root directory".into());
    }
    let fd = rustix::fs::openat2(
        root,
        rel,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| format!("{path}: {e}"))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("{path}: stat: {e}"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!("{path}: not a regular file"));
    }
    Ok((s_dev_from_st_dev(st.st_dev), st.st_ino))
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;

    /// Test resolver: (container, path) -> id.
    #[derive(Debug, Default, Clone)]
    pub struct FakeResolver(pub HashMap<(String, String), FileId>);

    impl FakeResolver {
        pub fn with(mut self, cid: &str, path: &str, id: FileId) -> Self {
            self.0.insert((cid.into(), path.into()), id);
            self
        }
    }

    impl ExecResolver for FakeResolver {
        fn resolve(&self, container_id: &str, path: &str) -> Result<FileId, String> {
            self.0
                .get(&(container_id.to_string(), path.to_string()))
                .copied()
                .ok_or_else(|| format!("{path}: not found"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn resolves_inside_root_only() {
        let base = tempfile::tempdir().unwrap();
        let cid = "c1";
        let rootfs = base.path().join(cid).join("rootfs");
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        std::fs::write(rootfs.join("usr/bin/curl"), b"x").unwrap();
        // Absolute symlink: must resolve inside the rootfs, not on the host.
        std::os::unix::fs::symlink("/usr/bin/curl", rootfs.join("usr/bin/alias")).unwrap();
        // Escape attempts via symlink resolve to the rootfs root, where the target does not exist.
        std::os::unix::fs::symlink("../../../../etc/passwd", rootfs.join("usr/bin/escape"))
            .unwrap();

        let r = RootfsResolver::new(base.path());
        let md = std::fs::metadata(rootfs.join("usr/bin/curl")).unwrap();
        let want = (s_dev_from_st_dev(md.dev()), md.ino());
        assert_eq!(r.resolve(cid, "/usr/bin/curl"), Ok(want));
        assert_eq!(r.resolve(cid, "/usr/bin/alias"), Ok(want));
        assert!(r.resolve(cid, "/usr/bin/escape").is_err());
        assert!(r
            .resolve(cid, "/usr/bin")
            .unwrap_err()
            .contains("not a regular file"));
        assert!(r.resolve(cid, "/missing").is_err());
        assert!(r.resolve("../c1", "/usr/bin/curl").is_err());
        assert!(r.resolve(cid, "/").is_err());
    }
}
