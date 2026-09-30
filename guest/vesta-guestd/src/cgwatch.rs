// SPDX-License-Identifier: Apache-2.0
//! Event-driven wait for container cgroups.
//!
//! A pending BindContainer registers its cgroup path here. One task keeps an
//! inotify watch on the deepest existing directory on the way to each pending
//! path (inotify is not recursive, so the watch moves down as kata-agent
//! creates intermediate cgroups) and wakes all waiters on any creation. The
//! waiters re-check their own path; they also keep a slow fallback poll, so a
//! missed event or an inotify failure only delays a bind, never fails it.

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

use crate::daemon::Shared;

/// Pending cgroup paths (relative to the cgroup2 root), reference counted.
#[derive(Debug, Default)]
pub struct CgroupWaits {
    paths: HashMap<PathBuf, usize>,
    /// Woken when a watched directory gets a new entry.
    pub wake: Rc<Notify>,
    /// Woken when the set of pending paths changes.
    pub changed: Rc<Notify>,
}

impl CgroupWaits {
    pub fn register(&mut self, rel: &Path) {
        *self.paths.entry(rel.to_path_buf()).or_default() += 1;
        self.changed.notify_one();
    }

    pub fn unregister(&mut self, rel: &Path) {
        if let Some(n) = self.paths.get_mut(rel) {
            *n -= 1;
            if *n == 0 {
                self.paths.remove(rel);
            }
        }
        self.changed.notify_one();
    }

    fn paths(&self) -> impl Iterator<Item = &Path> {
        self.paths.keys().map(PathBuf::as_path)
    }
}

/// Deepest existing directory (relative to `root`) on the way to `rel`, or
/// `None` when `rel` itself exists. `rel` is a validated relative cgroup path
/// (no `..`); symlinks are not followed.
pub fn deepest_existing(root: &Path, rel: &Path) -> Option<PathBuf> {
    let mut cur = PathBuf::new();
    for c in rel.components() {
        let next = cur.join(c);
        match std::fs::symlink_metadata(root.join(&next)) {
            Ok(m) if m.is_dir() => cur = next,
            _ => return Some(cur),
        }
    }
    None
}

/// Watch descriptors by directory, relative to the cgroup root.
#[derive(Debug, Default)]
struct Watches(HashMap<PathBuf, i32>);

impl Watches {
    fn sync(&mut self, fd: impl AsFd, root: &Path, wanted: &[PathBuf]) {
        let fd = fd.as_fd();
        self.0.retain(|dir, wd| {
            let keep = wanted.contains(dir);
            if !keep {
                // Fails harmlessly if the directory (and so the watch) is gone.
                let _ = inotify::remove_watch(fd, *wd);
            }
            keep
        });
        for dir in wanted {
            if self.0.contains_key(dir) {
                continue;
            }
            let flags = WatchFlags::CREATE
                | WatchFlags::MOVED_TO
                | WatchFlags::ONLYDIR
                | WatchFlags::DONT_FOLLOW;
            match inotify::add_watch(fd, root.join(dir), flags) {
                Ok(wd) => {
                    self.0.insert(dir.clone(), wd);
                }
                // Removed meanwhile: the next sync picks a shallower directory.
                Err(e) => {
                    tracing::debug!(dir = %dir.display(), error = %e, "inotify watch not added")
                }
            }
        }
    }

    fn forget(&mut self, wd: i32) {
        self.0.retain(|_, w| *w != wd);
    }
}

/// Reads all queued events. Returns WouldBlock when there were none, so
/// `AsyncFd::try_io` clears readiness.
fn drain(fd: impl AsFd, buf: &mut [MaybeUninit<u8>], watches: &mut Watches) -> io::Result<usize> {
    let mut reader = inotify::Reader::new(fd, buf);
    let mut n = 0;
    let mut ignored = Vec::new();
    loop {
        match reader.next() {
            Ok(ev) => {
                n += 1;
                if ev.events().contains(ReadFlags::IGNORED) {
                    ignored.push(ev.wd());
                }
            }
            Err(rustix::io::Errno::AGAIN) => break,
            Err(e) => return Err(e.into()),
        }
    }
    for wd in ignored {
        watches.forget(wd);
    }
    if n == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(n)
}

fn wanted(d: &Shared, root: &Path) -> Vec<PathBuf> {
    let dm = d.borrow();
    let mut dirs: Vec<PathBuf> = dm
        .cgroup_waits
        .paths()
        .filter_map(|p| deepest_existing(root, p))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Runs for the daemon's lifetime. Returns early (logged) if inotify is
/// unavailable; binds then rely on the fallback poll.
pub async fn run(d: Shared) {
    let (root, wake, changed) = {
        let dm = d.borrow();
        (
            dm.cfg.cgroup_root.clone(),
            dm.cgroup_waits.wake.clone(),
            dm.cgroup_waits.changed.clone(),
        )
    };
    let afd = match inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
        .map_err(io::Error::from)
        .and_then(AsyncFd::new)
    {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!(error = %e, "inotify unavailable; waiting for container cgroups by polling");
            return;
        }
    };
    let mut watches = Watches::default();
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 4096];
    loop {
        let dirs = wanted(&d, &root);
        watches.sync(afd.get_ref(), &root, &dirs);
        tokio::select! {
            ready = afd.readable() => {
                let mut guard = match ready {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::warn!(error = %e, "inotify failed; waiting for container cgroups by polling");
                        return;
                    }
                };
                match guard.try_io(|fd: &AsyncFd<OwnedFd>| drain(fd.get_ref(), &mut buf, &mut watches)) {
                    Ok(Ok(_)) => wake.notify_waiters(),
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "reading inotify events failed; waiting for container cgroups by polling");
                        return;
                    }
                    Err(_would_block) => {}
                }
            }
            () = changed.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deepest_existing_walks_down() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let rel = Path::new("a/b/c");
        assert_eq!(deepest_existing(root, rel), Some(PathBuf::new()));
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        assert_eq!(deepest_existing(root, rel), Some(PathBuf::from("a/b")));
        std::fs::create_dir(root.join("a/b/c")).unwrap();
        assert_eq!(deepest_existing(root, rel), None);
    }

    #[test]
    fn deepest_existing_does_not_follow_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::create_dir_all(root.join("real/c")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("a")).unwrap();
        assert_eq!(
            deepest_existing(root, Path::new("a/c")),
            Some(PathBuf::new())
        );
        std::fs::write(root.join("f"), b"").unwrap();
        assert_eq!(
            deepest_existing(root, Path::new("f/x")),
            Some(PathBuf::new())
        );
    }

    #[test]
    fn registrations_are_counted() {
        let mut w = CgroupWaits::default();
        let p = Path::new("x/y");
        w.register(p);
        w.register(p);
        w.unregister(p);
        assert_eq!(w.paths().count(), 1);
        w.unregister(p);
        assert_eq!(w.paths().count(), 0);
        w.unregister(p); // unknown: ignored
    }

    /// The watcher follows a nested path down as directories appear and
    /// wakes waiters, without any polling.
    #[tokio::test(flavor = "current_thread")]
    async fn wakes_on_nested_creation() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_path_buf();
        let d = crate::ctrl::tests::daemon_with_root(&root);
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let wake = d.borrow().cgroup_waits.wake.clone();
                let target = Path::new("pod/ctr");
                d.borrow_mut().cgroup_waits.register(target);
                tokio::task::spawn_local(run(d.clone()));
                tokio::task::yield_now().await;

                let wait = |w: Rc<Notify>| async move {
                    tokio::time::timeout(std::time::Duration::from_secs(5), w.notified())
                        .await
                        .is_ok()
                };
                let n = tokio::task::spawn_local(wait(wake.clone()));
                tokio::task::yield_now().await;
                std::fs::create_dir(root.join("pod")).unwrap();
                assert!(n.await.unwrap(), "no wake for the intermediate directory");

                let n = tokio::task::spawn_local(wait(wake.clone()));
                tokio::task::yield_now().await;
                std::fs::create_dir(root.join("pod/ctr")).unwrap();
                assert!(n.await.unwrap(), "no wake for the target directory");
                assert_eq!(deepest_existing(&root, target), None);
            })
            .await;
    }
}
