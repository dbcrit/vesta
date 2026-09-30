// SPDX-License-Identifier: Apache-2.0
//! Process ancestry for `Event.chain`, built from exec events.
//!
//! Every exec record teaches the cache `tgid -> (ppid, comm, exe_path)`. An
//! event's chain walks `ppid` links through the cache, nearest parent first.
//! This is best effort: processes that have not exec'd since guestd started
//! appear with their pid only and end the walk, and there are no exit events,
//! so an entry can outlive its process until the pid is exec'd again or the
//! entry is evicted.

use std::collections::{HashMap, VecDeque};

use crate::proto::event as ev;

/// events.proto: chain max 8.
pub const MAX_CHAIN: usize = 8;
/// Entries kept; the oldest insertion is evicted first.
pub const DEFAULT_CAPACITY: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Proc {
    ppid: u32,
    comm: String,
    exe_path: String,
    stamp: u64,
}

#[derive(Debug)]
pub struct Ancestry {
    procs: HashMap<u32, Proc>,
    /// Insertion order as (tgid, stamp); stale pairs are skipped on eviction.
    order: VecDeque<(u32, u64)>,
    capacity: usize,
    next_stamp: u64,
}

impl Ancestry {
    pub fn new(capacity: usize) -> Self {
        Self {
            procs: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            next_stamp: 0,
        }
    }

    /// Records a successful exec by `tgid`.
    pub fn exec(&mut self, tgid: u32, ppid: u32, comm: &str, exe_path: &str) {
        if tgid == 0 {
            return;
        }
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        self.procs.insert(
            tgid,
            Proc {
                ppid,
                comm: comm.to_owned(),
                exe_path: exe_path.to_owned(),
                stamp,
            },
        );
        self.order.push_back((tgid, stamp));
        while self.procs.len() > self.capacity {
            let Some((old, s)) = self.order.pop_front() else {
                break;
            };
            if self.procs.get(&old).is_some_and(|p| p.stamp == s) {
                self.procs.remove(&old);
            }
        }
        // Stale pairs from re-execs accumulate; drop them once they dominate.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let procs = &self.procs;
            self.order
                .retain(|(t, s)| procs.get(t).is_some_and(|p| p.stamp == *s));
        }
    }

    /// Executable path of `tgid` if it exec'd with the same parent, i.e. the
    /// entry is still about this process and not a reused pid.
    pub fn exe_path(&self, tgid: u32, ppid: u32) -> Option<&str> {
        self.procs
            .get(&tgid)
            .filter(|p| p.ppid == ppid)
            .map(|p| p.exe_path.as_str())
    }

    /// Ancestors of a process whose parent is `ppid`, nearest first. An
    /// unknown parent is included with its pid only and ends the walk.
    pub fn chain(&self, ppid: u32) -> Vec<ev::Ancestor> {
        let mut out = Vec::new();
        let mut pid = ppid;
        while pid != 0 && out.len() < MAX_CHAIN {
            if out.iter().any(|a: &ev::Ancestor| a.pid == pid) {
                break;
            }
            match self.procs.get(&pid) {
                Some(p) => {
                    out.push(ev::Ancestor {
                        pid,
                        comm: p.comm.clone(),
                        exe_path: p.exe_path.clone(),
                    });
                    pid = p.ppid;
                }
                None => {
                    out.push(ev::Ancestor {
                        pid,
                        ..Default::default()
                    });
                    break;
                }
            }
        }
        out
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.procs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pids(c: &[ev::Ancestor]) -> Vec<u32> {
        c.iter().map(|a| a.pid).collect()
    }

    #[test]
    fn walks_nearest_parent_first() {
        let mut a = Ancestry::new(16);
        a.exec(1, 0, "init", "/sbin/init");
        a.exec(10, 1, "sh", "/bin/sh");
        a.exec(20, 10, "curl", "/usr/bin/curl");
        let c = a.chain(20);
        assert_eq!(pids(&c), vec![20, 10, 1]);
        assert_eq!(c[0].comm, "curl");
        assert_eq!(c[1].exe_path, "/bin/sh");
    }

    #[test]
    fn unknown_parent_ends_with_pid_only() {
        let mut a = Ancestry::new(16);
        a.exec(10, 5, "sh", "/bin/sh");
        let c = a.chain(10);
        assert_eq!(pids(&c), vec![10, 5]);
        assert!(c[1].comm.is_empty() && c[1].exe_path.is_empty());
        assert!(a.chain(0).is_empty());
    }

    #[test]
    fn bounded_depth_and_cycles() {
        let mut a = Ancestry::new(64);
        for pid in 2..40 {
            a.exec(pid, pid - 1, "p", "/p");
        }
        assert_eq!(a.chain(39).len(), MAX_CHAIN);
        // A corrupt or reused-pid loop never repeats a pid.
        a.exec(100, 101, "a", "/a");
        a.exec(101, 100, "b", "/b");
        assert_eq!(pids(&a.chain(100)), vec![100, 101]);
        a.exec(7, 7, "self", "/self");
        assert_eq!(pids(&a.chain(7)), vec![7]);
    }

    #[test]
    fn capacity_evicts_oldest_insertion() {
        let mut a = Ancestry::new(3);
        a.exec(1, 0, "a", "/a");
        a.exec(2, 1, "b", "/b");
        a.exec(3, 2, "c", "/c");
        a.exec(1, 0, "a2", "/a2"); // re-exec refreshes pid 1
        a.exec(4, 3, "d", "/d");
        assert_eq!(a.len(), 3);
        assert_eq!(pids(&a.chain(4)), vec![4, 3, 2]);
        a.exec(5, 4, "e", "/e");
        // pid 3 was now the oldest live insertion; the re-exec'd pid 1 stays.
        let c = a.chain(4);
        assert_eq!(pids(&c), vec![4, 3]);
        assert!(c[1].comm.is_empty());
        assert_eq!(a.chain(1)[0].comm, "a2");
    }

    #[test]
    fn stale_order_entries_are_compacted() {
        let mut a = Ancestry::new(4);
        for _ in 0..1000 {
            a.exec(9, 1, "x", "/x");
        }
        assert!(a.order.len() <= 8);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn exe_path_requires_matching_parent() {
        let mut a = Ancestry::new(8);
        a.exec(30, 10, "app", "/app");
        assert_eq!(a.exe_path(30, 10), Some("/app"));
        assert_eq!(a.exe_path(30, 11), None, "pid reused under another parent");
        assert_eq!(a.exe_path(31, 10), None);
    }
}
