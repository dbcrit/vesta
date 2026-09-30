// SPDX-License-Identifier: Apache-2.0
//! Shared daemon state. guestd runs on one thread (tokio current_thread +
//! LocalSet): the libbpf-rs skeleton is not `Send`, the guest is
//! memory-constrained, and nothing here needs parallelism. State lives in
//! `Rc<RefCell<Daemon>>`; borrows are never held across an `.await`.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::rc::Rc;

use tokio::sync::Notify;

use crate::abi::{CgroupPolicy, ExecKey, NetKeyV4, NetKeyV6, RuleValue};
use crate::config::Config;
use crate::events::EventHub;
use crate::proto::channel as pb;
use crate::state::{Engine, PolicyMaps};
use crate::sysinfo::GuestInfo;

/// Program lifecycle and counters, implemented over the loaded skeleton.
pub trait BpfControl {
    /// Per-program status; `with_logs` includes errors and verifier logs.
    fn prog_status(&self, with_logs: bool) -> Vec<pb::ProgStatus>;
    /// Feature strings for attached programs (control.proto "Feature strings").
    fn features(&self) -> Vec<String>;
    /// drop_counters summed over CPUs, non-zero entries only.
    fn drop_counts(&self) -> Vec<pb::DropCount>;
    /// Detaches (kill switch DETACHED) or re-attaches all programs.
    fn set_attached(&mut self, attached: bool) -> anyhow::Result<()>;
}

/// Finds container cgroups under the cgroup2 root.
pub trait CgroupLookup {
    fn lookup(&self, rel: &Path) -> std::io::Result<Option<u64>>;
    fn existing_ids(&self) -> std::io::Result<HashSet<u64>>;
}

impl<T: PolicyMaps + ?Sized> PolicyMaps for Box<T> {
    fn put_cgroup(&mut self, id: u64, v: &CgroupPolicy) -> anyhow::Result<()> {
        (**self).put_cgroup(id, v)
    }
    fn del_cgroup(&mut self, id: u64) -> anyhow::Result<()> {
        (**self).del_cgroup(id)
    }
    fn put_exec(&mut self, k: &ExecKey, v: &RuleValue) -> anyhow::Result<()> {
        (**self).put_exec(k, v)
    }
    fn del_exec(&mut self, k: &ExecKey) -> anyhow::Result<()> {
        (**self).del_exec(k)
    }
    fn put_net4(&mut self, k: &NetKeyV4, v: &RuleValue) -> anyhow::Result<()> {
        (**self).put_net4(k, v)
    }
    fn del_net4(&mut self, k: &NetKeyV4) -> anyhow::Result<()> {
        (**self).del_net4(k)
    }
    fn put_net6(&mut self, k: &NetKeyV6, v: &RuleValue) -> anyhow::Result<()> {
        (**self).put_net6(k, v)
    }
    fn del_net6(&mut self, k: &NetKeyV6) -> anyhow::Result<()> {
        (**self).del_net6(k)
    }
    fn set_policy_ready(&mut self, generation: u64) -> anyhow::Result<()> {
        (**self).set_policy_ready(generation)
    }
    fn set_global_mode(&mut self, mode: u32) -> anyhow::Result<()> {
        (**self).set_global_mode(mode)
    }
}

impl fmt::Debug for dyn PolicyMaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyMaps")
    }
}

/// Policy maps when the BPF object could not be loaded: every write fails
/// explicitly, so ApplyPolicy/BindContainer are nacked instead of pretending.
#[derive(Debug)]
pub struct Unavailable(pub String);

impl PolicyMaps for Unavailable {
    fn put_cgroup(&mut self, _: u64, _: &CgroupPolicy) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn del_cgroup(&mut self, _: u64) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn put_exec(&mut self, _: &ExecKey, _: &RuleValue) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn del_exec(&mut self, _: &ExecKey) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn put_net4(&mut self, _: &NetKeyV4, _: &RuleValue) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn del_net4(&mut self, _: &NetKeyV4) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn put_net6(&mut self, _: &NetKeyV6, _: &RuleValue) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn del_net6(&mut self, _: &NetKeyV6) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn set_policy_ready(&mut self, _: u64) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
    fn set_global_mode(&mut self, _: u32) -> anyhow::Result<()> {
        anyhow::bail!("BPF maps unavailable: {}", self.0)
    }
}

pub struct Daemon {
    pub cfg: Config,
    pub info: GuestInfo,
    pub engine: Engine<Box<dyn PolicyMaps>>,
    pub bpf: Box<dyn BpfControl>,
    pub cgroups: Box<dyn CgroupLookup>,
    pub hub: EventHub,
    /// Woken when new events are buffered.
    pub events_ready: Rc<Notify>,
    pub heartbeat_seq: u64,
    pub pending_binds: usize,
}

impl fmt::Debug for Daemon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Daemon")
            .field("applied_generation", &self.engine.applied_generation())
            .field("pending_binds", &self.pending_binds)
            .finish_non_exhaustive()
    }
}

pub type Shared = Rc<RefCell<Daemon>>;

impl Daemon {
    /// Refreshes the cgroup id -> container id map used for event attribution.
    pub fn sync_container_names(&mut self) {
        self.hub.containers = self.engine.container_names();
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[derive(Debug, Default)]
    pub struct FakeBpf {
        pub attached: bool,
        pub drops: Vec<(u32, u64)>,
    }

    impl BpfControl for FakeBpf {
        fn prog_status(&self, _with_logs: bool) -> Vec<pb::ProgStatus> {
            vec![pb::ProgStatus {
                id: "P1".into(),
                attach: "tp_btf/sched_process_exec".into(),
                state: if self.attached {
                    pb::ProgState::Attached
                } else {
                    pb::ProgState::Detached
                } as i32,
                prog_id: 10,
                tag: vec![1; 8],
                link_id: 20,
                ..Default::default()
            }]
        }
        fn features(&self) -> Vec<String> {
            if self.attached {
                vec!["exec_audit".into()]
            } else {
                Vec::new()
            }
        }
        fn drop_counts(&self) -> Vec<pb::DropCount> {
            self.drops
                .iter()
                .map(|&(event_type, count)| pb::DropCount { event_type, count })
                .collect()
        }
        fn set_attached(&mut self, attached: bool) -> anyhow::Result<()> {
            self.attached = attached;
            Ok(())
        }
    }

    /// Cgroups "appear" when inserted into the shared map.
    #[derive(Debug, Default, Clone)]
    pub struct FakeCgroups(pub Rc<RefCell<HashMap<PathBuf, u64>>>);

    impl CgroupLookup for FakeCgroups {
        fn lookup(&self, rel: &Path) -> std::io::Result<Option<u64>> {
            Ok(self.0.borrow().get(rel).copied())
        }
        fn existing_ids(&self) -> std::io::Result<HashSet<u64>> {
            Ok(self.0.borrow().values().copied().collect())
        }
    }
}
