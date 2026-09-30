// SPDX-License-Identifier: Apache-2.0
//! Loading, attaching and pinning the vesta BPF object (libbpf-rs skeleton).
//!
//! - ABI maps are pinned under `<pin_root>/maps/<name>` and reused if a
//!   compatible pin exists (guestd restarted in the same boot).
//! - Programs attach through bpf_links pinned under `<pin_root>/links/<prog>`,
//!   so they stay attached when guestd exits. On restart the new link is
//!   attached before the old pin is replaced: no enforcement gap.
//! - `Bpf::load` only loads; the caller writes `config` and reads back any
//!   adopted state before `attach_all`, so a failure in between leaves no
//!   program attached that status would not report.
//! - If the whole object fails to load, programs are tried one by one so one
//!   bad program (e.g. no BPF LSM) does not take the others down; failures
//!   are reported with their verifier log.

use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, MapType, OpenObject, PrintLevel, ProgramHandle,
};

use crate::abi::{self, CgroupPolicy, ExecKey, NetKeyV4, NetKeyV6, RuleValue};
use crate::daemon::BpfControl;
use crate::proto::channel as pb;
use crate::state::{MapState, PolicyMaps};

/// libbpf-cargo output. Generated FFI glue: the only `unsafe` in guestd.
#[allow(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    dead_code,
    missing_debug_implementations,
    unused_qualifications
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/vesta.skel.rs"));
}
use skel::{VestaSkel, VestaSkelBuilder};

const MAX_VERIFIER_LOG: usize = 65536;
const MAX_ERROR: usize = 1024;

/// Maps whose contents must be reused together or not at all: a restart that
/// could reuse only some of them would mix old and new state.
const POLICY_STATE_MAPS: [&str; 7] = [
    "config",
    "global_mode",
    "policy_ready",
    "cgroup_policy",
    "exec_rules",
    "net_rules_v4",
    "net_rules_v6",
];

/// ABI maps pinned under `<pin_root>/maps` (docs/abi.md).
pub const PINNED_MAPS: [&str; 9] = [
    "config",
    "global_mode",
    "policy_ready",
    "cgroup_policy",
    "exec_rules",
    "net_rules_v4",
    "net_rules_v6",
    "events",
    "drop_counters",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attach {
    Auto,
    Cgroup,
}

#[derive(Debug, Clone, Copy)]
struct ProgSpec {
    id: &'static str,
    name: &'static str,
    section: &'static str,
    feature: &'static str,
    attach: Attach,
    needs_bpf_lsm: bool,
}

const PROGS: [ProgSpec; 4] = [
    ProgSpec {
        id: "P1",
        name: "vesta_exec",
        section: "tp_btf/sched_process_exec",
        feature: "exec_audit",
        attach: Attach::Auto,
        needs_bpf_lsm: false,
    },
    ProgSpec {
        id: "P2",
        name: "vesta_bprm_check",
        section: "lsm/bprm_check_security",
        feature: "exec_lsm",
        attach: Attach::Auto,
        needs_bpf_lsm: true,
    },
    ProgSpec {
        id: "N1-connect4",
        name: "vesta_connect4",
        section: "cgroup/connect4",
        feature: "net_egress4",
        attach: Attach::Cgroup,
        needs_bpf_lsm: false,
    },
    ProgSpec {
        id: "N1-connect6",
        name: "vesta_connect6",
        section: "cgroup/connect6",
        feature: "net_egress6",
        attach: Attach::Cgroup,
        needs_bpf_lsm: false,
    },
];

#[derive(Debug)]
struct ProgRuntime {
    spec: ProgSpec,
    loaded: bool,
    link: Option<Link>,
    prog_id: u32,
    tag: [u8; 8],
    link_id: u32,
    error: String,
    verifier_log: Vec<u8>,
}

impl ProgRuntime {
    fn new(spec: ProgSpec) -> Self {
        Self {
            spec,
            loaded: false,
            link: None,
            prog_id: 0,
            tag: [0; 8],
            link_id: 0,
            error: String::new(),
            verifier_log: Vec::new(),
        }
    }
}

/// libbpf output captured per load attempt (verifier logs arrive as WARN).
static LIBBPF_LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn libbpf_print(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Warn => tracing::debug!(target: "libbpf", "{}", msg.trim_end()),
        _ => tracing::trace!(target: "libbpf", "{}", msg.trim_end()),
    }
    if let Ok(mut log) = LIBBPF_LOG.lock() {
        let room = MAX_VERIFIER_LOG.saturating_sub(log.len());
        log.extend_from_slice(&msg.as_bytes()[..msg.len().min(room)]);
    }
}

fn take_libbpf_log() -> Vec<u8> {
    LIBBPF_LOG
        .lock()
        .map(|mut l| std::mem::take(&mut *l))
        .unwrap_or_default()
}

fn truncated(s: String) -> String {
    let mut s = s;
    if s.len() > MAX_ERROR {
        let mut cut = MAX_ERROR;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

#[derive(Debug, Clone)]
pub struct LoadOptions {
    pub pin_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub ringbuf_bytes: u32,
    pub audit_unbound_exec: bool,
    pub bpf_lsm_active: bool,
}

/// A loaded object with pinned maps and (possibly partially) attached programs.
pub struct Bpf {
    skel: VestaSkel<'static>,
    progs: Vec<ProgRuntime>,
    cgroup_root: OwnedFd,
    pin_root: PathBuf,
    drop_counters: MapHandle,
    /// Maps were reused from pins left by an earlier guestd in this boot.
    pub maps_reused: bool,
}

impl std::fmt::Debug for Bpf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bpf")
            .field("progs", &self.progs)
            .field("maps_reused", &self.maps_reused)
            .finish_non_exhaustive()
    }
}

fn map_pin(pin_root: &Path, name: &str) -> PathBuf {
    pin_root.join("maps").join(name)
}

fn link_pin(pin_root: &Path, name: &str) -> PathBuf {
    pin_root.join("links").join(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinState {
    Absent,
    Compatible,
    Incompatible,
}

/// Whether a pinned map can be reused by the new object (same layout).
fn pin_state(path: &Path, want: &libbpf_rs::OpenMapMut<'_>) -> anyhow::Result<PinState> {
    let existing = match MapHandle::from_pinned_path(path) {
        Ok(m) => m,
        Err(_) if !path.exists() => return Ok(PinState::Absent),
        Err(e) => return Err(anyhow!("opening pinned map {}: {e}", path.display())),
    };
    let same = existing.map_type() == want.map_type()
        && existing.key_size() == want.key_size()
        && existing.value_size() == want.value_size()
        && existing.max_entries() == want.max_entries()
        && existing.info().map(|i| i.info.map_flags).ok() == Some(want.map_flags());
    Ok(if same {
        PinState::Compatible
    } else {
        PinState::Incompatible
    })
}

fn remove_pin(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Opens (and optionally loads) the skeleton with only `enabled` programs.
/// Storage for the object is leaked: the skeleton lives as long as guestd.
fn open_and_load(
    opts: &LoadOptions,
    enabled: &HashSet<&str>,
    pin: bool,
) -> anyhow::Result<(VestaSkel<'static>, bool)> {
    let storage: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut open = VestaSkelBuilder::default()
        .open(storage)
        .context("opening BPF object")?;

    let rodata = open
        .maps
        .rodata_data
        .as_deref_mut()
        .ok_or_else(|| anyhow!("BPF object has no .rodata"))?;
    if rodata.vesta_abi_version != abi::ABI_VERSION {
        bail!(
            "BPF object ABI {} != guestd ABI {}",
            rodata.vesta_abi_version,
            abi::ABI_VERSION
        );
    }
    rodata.audit_unbound_exec = opts.audit_unbound_exec;
    open.maps
        .events
        .set_max_entries(opts.ringbuf_bytes)
        .context("sizing the ring buffer")?;

    for mut p in open.open_object_mut().progs_mut() {
        let name = p.name().to_string_lossy().into_owned();
        p.set_autoload(enabled.contains(name.as_str()));
    }

    let mut reused = false;
    if pin {
        let mut states = Vec::new();
        for m in open.open_object_mut().maps_mut() {
            let name = m.name().to_string_lossy().into_owned();
            if PINNED_MAPS.contains(&name.as_str()) {
                let st = pin_state(&map_pin(&opts.pin_root, &name), &m)?;
                states.push((name, st));
            }
        }
        let policy: Vec<PinState> = states
            .iter()
            .filter(|(n, _)| POLICY_STATE_MAPS.contains(&n.as_str()))
            .map(|(_, st)| *st)
            .collect();
        let reuse_policy = policy.iter().all(|st| *st == PinState::Compatible);
        if !reuse_policy && policy.iter().any(|st| *st != PinState::Absent) {
            tracing::warn!(
                "pinned policy maps are partly missing or incompatible; starting from empty maps"
            );
        }
        for (name, st) in &states {
            let path = map_pin(&opts.pin_root, name);
            let keep = *st == PinState::Compatible
                && (reuse_policy || !POLICY_STATE_MAPS.contains(&name.as_str()));
            if !keep && *st != PinState::Absent {
                tracing::warn!(pin = %path.display(), "not reusing pinned map; replacing it");
                remove_pin(&path)?;
            }
        }
        reused = reuse_policy;
        for mut m in open.open_object_mut().maps_mut() {
            let name = m.name().to_string_lossy().into_owned();
            if !PINNED_MAPS.contains(&name.as_str()) {
                continue;
            }
            // libbpf reuses a compatible pin at load time, or pins the new map there.
            m.set_pin_path(map_pin(&opts.pin_root, &name))
                .with_context(|| format!("setting pin path for {name}"))?;
        }
    }
    let _ = take_libbpf_log();
    let skel = open
        .load()
        .map_err(|e| anyhow!("loading BPF object: {e}"))?;
    Ok((skel, reused))
}

impl Bpf {
    /// Loads the object and pins its maps. Programs are attached by `attach_all`.
    pub fn load(opts: &LoadOptions) -> anyhow::Result<Bpf> {
        libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_print)));
        for dir in ["maps", "links"] {
            let p = opts.pin_root.join(dir);
            std::fs::create_dir_all(&p).with_context(|| format!("creating {}", p.display()))?;
        }
        let mut progs: Vec<ProgRuntime> = PROGS.iter().copied().map(ProgRuntime::new).collect();
        let mut enabled: HashSet<&str> = HashSet::new();
        for p in &mut progs {
            if p.spec.needs_bpf_lsm && !opts.bpf_lsm_active {
                p.error = "bpf is not in the active LSM list (/sys/kernel/security/lsm)".into();
            } else {
                enabled.insert(p.spec.name);
            }
        }

        let (skel, reused) = match open_and_load(opts, &enabled, true) {
            Ok(r) => r,
            Err(first) => {
                tracing::warn!(error = %format!("{first:#}"), "loading all programs failed; isolating failures");
                for p in progs.iter_mut() {
                    if !enabled.contains(p.spec.name) {
                        continue;
                    }
                    let only = HashSet::from([p.spec.name]);
                    if let Err(e) = open_and_load(opts, &only, false) {
                        p.error = truncated(format!("{e:#}"));
                        p.verifier_log = take_libbpf_log();
                        enabled.remove(p.spec.name);
                        tracing::error!(prog = p.spec.id, error = %p.error, "program failed to load");
                    }
                }
                open_and_load(opts, &enabled, true)
                    .context("loading the programs that verified individually")?
            }
        };

        let cgroup_root = rustix::fs::open(
            &opts.cgroup_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("opening {}", opts.cgroup_root.display()))?;
        let drop_counters =
            MapHandle::try_from(&skel.maps.drop_counters).context("drop_counters handle")?;
        for p in &mut progs {
            p.loaded = enabled.contains(p.spec.name);
        }
        Ok(Bpf {
            skel,
            progs,
            cgroup_root,
            pin_root: opts.pin_root.clone(),
            drop_counters,
            maps_reused: reused,
        })
    }

    /// Attaches every loaded program that is not attached yet. Failures are
    /// recorded per program and reported in status.
    pub fn attach_all(&mut self) {
        for i in 0..self.progs.len() {
            if !self.progs[i].loaded || self.progs[i].link.is_some() {
                continue;
            }
            match self.attach_one(i) {
                Ok(()) => {
                    let p = &self.progs[i];
                    tracing::info!(
                        prog = p.spec.id,
                        prog_id = p.prog_id,
                        link_id = p.link_id,
                        "attached"
                    );
                }
                Err(e) => {
                    let p = &mut self.progs[i];
                    p.error = truncated(format!("{e:#}"));
                    tracing::error!(prog = p.spec.id, error = %p.error, "attach failed");
                }
            }
        }
    }

    fn attach_one(&mut self, i: usize) -> anyhow::Result<()> {
        let spec = self.progs[i].spec;
        let cgroup_fd = self.cgroup_root.as_raw_fd();
        let (mut link, prog_id, tag) = {
            let prog = self
                .skel
                .object_mut()
                .progs_mut()
                .find(|p| p.name() == spec.name)
                .ok_or_else(|| anyhow!("program {} not in object", spec.name))?;
            let link = match spec.attach {
                Attach::Auto => prog.attach(),
                Attach::Cgroup => prog.attach_cgroup(cgroup_fd),
            }
            .with_context(|| format!("attaching {}", spec.section))?;
            // From the fd we hold (BPF_OBJ_GET_INFO_BY_FD): no CAP_SYS_ADMIN needed.
            let info = ProgramHandle::try_from(&prog).context("program info")?;
            (link, info.id(), info.tag())
        };
        let link_id = link.info().map(|i| i.id).unwrap_or(0);

        // The new link is live; now replace whatever pin a previous guestd left.
        let path = link_pin(&self.pin_root, spec.name);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(pin = %path.display(), "replaced link pinned by a previous guestd")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing stale {}", path.display())),
        }
        link.pin(&path)
            .with_context(|| format!("pinning link at {}", path.display()))?;

        let p = &mut self.progs[i];
        p.prog_id = prog_id;
        p.tag = tag;
        p.link_id = link_id;
        p.error.clear();
        p.link = Some(link);
        Ok(())
    }

    fn detach_all(&mut self) -> anyhow::Result<()> {
        let mut first_err = None;
        for p in &mut self.progs {
            if let Some(mut link) = p.link.take() {
                // Unpinned and closed: the kernel detaches it with the last reference.
                if let Err(e) = link.unpin() {
                    first_err.get_or_insert_with(|| anyhow!("unpinning {}: {e}", p.spec.name));
                    p.link = Some(link);
                    continue;
                }
                drop(link);
                p.link_id = 0;
                tracing::info!(prog = p.spec.id, "detached");
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn handle(&self, name: &str) -> anyhow::Result<MapHandle> {
        let map = self
            .skel
            .object()
            .maps()
            .find(|m| m.name() == name)
            .ok_or_else(|| anyhow!("map {name} not in object"))?;
        MapHandle::try_from(&map).with_context(|| format!("handle for map {name}"))
    }

    /// Writes and freezes `config` (unless it was reused from a pin, in
    /// which case it is already frozen and must match).
    pub fn init_config(&self, cfg: &abi::Config) -> anyhow::Result<()> {
        let map = self.handle("config")?;
        let key = 0u32.to_ne_bytes();
        if self.maps_reused {
            let cur = map.lookup(&key, MapFlags::ANY)?.unwrap_or_default();
            if cur.get(..4) != Some(abi::ABI_VERSION.to_ne_bytes().as_slice()) {
                bail!("pinned config map has a different ABI version");
            }
            return Ok(());
        }
        map.update(&key, &cfg.to_bytes(), MapFlags::ANY)
            .context("writing config")?;
        map.freeze().context("freezing config")?;
        Ok(())
    }

    /// Policy map writer over owned map handles.
    pub fn policy_maps(&self) -> anyhow::Result<BpfMaps> {
        Ok(BpfMaps {
            cgroup_policy: self.handle("cgroup_policy")?,
            exec_rules: self.handle("exec_rules")?,
            net4: self.handle("net_rules_v4")?,
            net6: self.handle("net_rules_v6")?,
            policy_ready: self.handle("policy_ready")?,
            global_mode: self.handle("global_mode")?,
        })
    }

    pub fn events_map(&self) -> anyhow::Result<MapHandle> {
        self.handle("events")
    }

    /// The event seq store, pinned next to the ABI maps (not part of the ABI).
    pub fn seq_store(&self) -> anyhow::Result<SeqMap> {
        SeqMap::open_or_create(&self.pin_root.join("state").join("event_seq"))
    }
}

/// Highest reserved event seq, in a pinned one-element array map so it
/// survives guestd restarts within a guest boot (events.proto: seq is
/// monotonic per boot). Not visible to the BPF programs.
#[derive(Debug)]
pub struct SeqMap(MapHandle);

impl SeqMap {
    fn open_or_create(path: &Path) -> anyhow::Result<SeqMap> {
        if let Ok(m) = MapHandle::from_pinned_path(path) {
            if m.map_type() == MapType::Array
                && m.key_size() == 4
                && m.value_size() == 8
                && m.max_entries() == 1
            {
                return Ok(SeqMap(m));
            }
            tracing::warn!(pin = %path.display(), "pinned event seq map has an unexpected layout; replacing it");
            remove_pin(path)?;
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let opts = libbpf_rs::libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let mut m = MapHandle::create(MapType::Array, Some("vesta_seq"), 4, 8, 1, &opts)
            .context("creating the event seq map")?;
        m.pin(path)
            .with_context(|| format!("pinning {}", path.display()))?;
        Ok(SeqMap(m))
    }
}

impl crate::events::SeqStore for SeqMap {
    fn load(&self) -> anyhow::Result<u64> {
        let v = self
            .0
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
            .context("reading the event seq")?
            .unwrap_or_default();
        Ok(v.get(..8)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_ne_bytes))
    }
    fn store(&self, reserved: u64) -> anyhow::Result<()> {
        self.0
            .update(&0u32.to_ne_bytes(), &reserved.to_ne_bytes(), MapFlags::ANY)
            .context("writing the event seq")
    }
}

impl BpfControl for Bpf {
    fn prog_status(&self, with_logs: bool) -> Vec<pb::ProgStatus> {
        self.progs
            .iter()
            .map(|p| {
                let state = if p.link.is_some() {
                    pb::ProgState::Attached
                } else if p.loaded && p.error.is_empty() {
                    pb::ProgState::Detached
                } else {
                    pb::ProgState::Failed
                };
                pb::ProgStatus {
                    id: p.spec.id.into(),
                    attach: p.spec.section.into(),
                    state: state as i32,
                    prog_id: p.prog_id,
                    tag: p.tag.to_vec(),
                    link_id: p.link_id,
                    error: if with_logs {
                        p.error.clone()
                    } else {
                        String::new()
                    },
                    verifier_log: if with_logs {
                        p.verifier_log.clone()
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect()
    }

    fn features(&self) -> Vec<String> {
        self.progs
            .iter()
            .filter(|p| p.link.is_some())
            .map(|p| p.spec.feature.to_string())
            .collect()
    }

    fn drop_counts(&self) -> Vec<pb::DropCount> {
        let mut out = Vec::new();
        for t in 0..abi::event_type::MAX {
            let Ok(Some(per_cpu)) = self
                .drop_counters
                .lookup_percpu(&t.to_ne_bytes(), MapFlags::ANY)
            else {
                continue;
            };
            let count = per_cpu
                .iter()
                .filter_map(|v| {
                    v.get(..8)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_ne_bytes)
                })
                .fold(0u64, u64::saturating_add);
            if count > 0 {
                out.push(pb::DropCount {
                    event_type: t,
                    count,
                });
            }
        }
        out
    }

    fn set_attached(&mut self, attached: bool) -> anyhow::Result<()> {
        if attached {
            self.attach_all();
            match self.progs.iter().find(|p| p.loaded && p.link.is_none()) {
                Some(p) => bail!("{} did not re-attach: {}", p.spec.id, p.error),
                None => Ok(()),
            }
        } else {
            self.detach_all()
        }
    }
}

/// Status when the object could not be loaded at all.
#[derive(Debug)]
pub struct Unloaded(pub String);

impl BpfControl for Unloaded {
    fn prog_status(&self, with_logs: bool) -> Vec<pb::ProgStatus> {
        PROGS
            .iter()
            .map(|s| pb::ProgStatus {
                id: s.id.into(),
                attach: s.section.into(),
                state: pb::ProgState::Failed as i32,
                error: if with_logs {
                    truncated(self.0.clone())
                } else {
                    String::new()
                },
                ..Default::default()
            })
            .collect()
    }
    fn features(&self) -> Vec<String> {
        Vec::new()
    }
    fn drop_counts(&self) -> Vec<pb::DropCount> {
        Vec::new()
    }
    fn set_attached(&mut self, _attached: bool) -> anyhow::Result<()> {
        bail!("BPF programs are not loaded: {}", self.0)
    }
}

/// Policy map writer (state::PolicyMaps) over owned map fds.
#[derive(Debug)]
pub struct BpfMaps {
    cgroup_policy: MapHandle,
    exec_rules: MapHandle,
    net4: MapHandle,
    net6: MapHandle,
    policy_ready: MapHandle,
    global_mode: MapHandle,
}

fn update(map: &MapHandle, k: &[u8], v: &[u8]) -> anyhow::Result<()> {
    map.update(k, v, MapFlags::ANY)
        .map_err(|e| anyhow!("{}: update: {e}", map.name().to_string_lossy()))
}

fn delete(map: &MapHandle, k: &[u8]) -> anyhow::Result<()> {
    match map.delete(k) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("{}: delete: {e}", map.name().to_string_lossy())),
    }
}

impl PolicyMaps for BpfMaps {
    fn put_cgroup(&mut self, id: u64, v: &CgroupPolicy) -> anyhow::Result<()> {
        update(&self.cgroup_policy, &id.to_ne_bytes(), &v.to_bytes())
    }
    fn del_cgroup(&mut self, id: u64) -> anyhow::Result<()> {
        delete(&self.cgroup_policy, &id.to_ne_bytes())
    }
    fn put_exec(&mut self, k: &ExecKey, v: &RuleValue) -> anyhow::Result<()> {
        update(&self.exec_rules, &k.to_bytes(), &v.to_bytes())
    }
    fn del_exec(&mut self, k: &ExecKey) -> anyhow::Result<()> {
        delete(&self.exec_rules, &k.to_bytes())
    }
    fn put_net4(&mut self, k: &NetKeyV4, v: &RuleValue) -> anyhow::Result<()> {
        update(&self.net4, &k.to_bytes(), &v.to_bytes())
    }
    fn del_net4(&mut self, k: &NetKeyV4) -> anyhow::Result<()> {
        delete(&self.net4, &k.to_bytes())
    }
    fn put_net6(&mut self, k: &NetKeyV6, v: &RuleValue) -> anyhow::Result<()> {
        update(&self.net6, &k.to_bytes(), &v.to_bytes())
    }
    fn del_net6(&mut self, k: &NetKeyV6) -> anyhow::Result<()> {
        delete(&self.net6, &k.to_bytes())
    }
    fn set_policy_ready(&mut self, generation: u64) -> anyhow::Result<()> {
        update(
            &self.policy_ready,
            &0u32.to_ne_bytes(),
            &abi::PolicyReadyValue { generation }.to_bytes(),
        )
    }
    fn set_global_mode(&mut self, mode: u32) -> anyhow::Result<()> {
        update(
            &self.global_mode,
            &0u32.to_ne_bytes(),
            &abi::GlobalModeValue { mode, _pad0: 0 }.to_bytes(),
        )
    }
}

impl BpfMaps {
    /// Reads back map contents (restart adoption). Malformed entries are skipped.
    pub fn snapshot(&self) -> anyhow::Result<(MapState, u32, u64)> {
        let mut s = MapState::default();
        for k in self.cgroup_policy.keys() {
            let (Ok(id), Some(v)) = (
                <[u8; 8]>::try_from(k.as_slice()),
                self.cgroup_policy.lookup(&k, MapFlags::ANY)?,
            ) else {
                continue;
            };
            if let Some(v) = CgroupPolicy::from_bytes(&v) {
                s.cgroups.insert(u64::from_ne_bytes(id), v);
            }
        }
        for k in self.exec_rules.keys() {
            if let (Some(key), Some(v)) = (
                ExecKey::from_bytes(&k),
                self.exec_rules.lookup(&k, MapFlags::ANY)?,
            ) {
                if let Some(v) = RuleValue::from_bytes(&v) {
                    s.exec.insert(key, v);
                }
            }
        }
        for k in self.net4.keys() {
            if let (Some(key), Some(v)) = (
                NetKeyV4::from_bytes(&k),
                self.net4.lookup(&k, MapFlags::ANY)?,
            ) {
                if let Some(v) = RuleValue::from_bytes(&v) {
                    s.net4.insert(key, v);
                }
            }
        }
        for k in self.net6.keys() {
            if let (Some(key), Some(v)) = (
                NetKeyV6::from_bytes(&k),
                self.net6.lookup(&k, MapFlags::ANY)?,
            ) {
                if let Some(v) = RuleValue::from_bytes(&v) {
                    s.net6.insert(key, v);
                }
            }
        }
        let zero = 0u32.to_ne_bytes();
        let mode = self
            .global_mode
            .lookup(&zero, MapFlags::ANY)?
            .and_then(|v| {
                v.get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_ne_bytes)
            })
            .unwrap_or(abi::global_mode::NORMAL);
        let ready = self
            .policy_ready
            .lookup(&zero, MapFlags::ANY)?
            .and_then(|v| abi::PolicyReadyValue::from_bytes(&v))
            .map_or(0, |v| v.generation);
        Ok((s, mode, ready))
    }
}

/// Privileged smoke test against the running kernel (Docker Desktop's VM kernel
/// locally, a vesta guest kernel in CI):
///   VESTA_PRIVILEGED=1 guest/hack/in-builder.sh sh -c 'cd guest && cargo test -- --ignored --test-threads=1 smoke'
/// Uses a private bpffs and a scratch cgroup; programs only act on that cgroup.
#[cfg(test)]
mod smoke {
    use super::*;
    use crate::abi::Record;
    use std::cell::RefCell;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    const CG: &str = "/sys/fs/cgroup/vesta-smoke";
    const POLICY: u32 = 5;

    struct Env {
        pin_dir: PathBuf,
        /// Set when the test mounted its own bpffs (and unmounts it).
        own_mount: Option<tempfile::TempDir>,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(CG);
            if self.own_mount.is_some() {
                let _ = rustix::mount::unmount(&self.pin_dir, rustix::mount::UnmountFlags::DETACH);
            }
        }
    }

    fn skip(why: &str) {
        eprintln!("SKIP vesta BPF smoke test: {why}");
    }

    /// Runs `cmd` via sh after moving the shell into the scratch cgroup.
    fn run_in_cgroup(cmd: &str) -> std::process::ExitStatus {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("echo $$ > {CG}/cgroup.procs && exec {cmd}"))
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("spawning sh")
    }

    fn drain(
        rb: &libbpf_rs::RingBuffer<'_>,
        got: &Rc<RefCell<Vec<Record>>>,
        want: impl Fn(&Record) -> bool,
    ) -> Record {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            rb.poll(Duration::from_millis(100)).expect("ringbuf poll");
            let pos = got.borrow().iter().position(&want);
            if let Some(pos) = pos {
                return got.borrow_mut().remove(pos);
            }
            assert!(
                Instant::now() < deadline,
                "expected event not seen; got {:#?}",
                got.borrow()
            );
        }
    }

    fn hdr(r: &Record) -> &abi::EventHeader {
        match r {
            Record::Exec(e) => &e.hdr,
            Record::Connect(c) => &c.hdr,
        }
    }

    #[test]
    #[ignore = "needs a privileged container (BPF, bpffs, cgroup2)"]
    fn smoke() {
        if !rustix::process::geteuid().is_root() || !Path::new("/sys/kernel/btf/vmlinux").exists() {
            return skip("needs root and /sys/kernel/btf/vmlinux");
        }
        if !crate::sysinfo::is_cgroup2(Path::new("/sys/fs/cgroup")) {
            return skip("/sys/fs/cgroup is not cgroup2");
        }
        // VESTA_SMOKE_BPFFS names a bpffs mounted beforehand, so the test can
        // run without CAP_SYS_ADMIN (the capability set of the guestd unit).
        let (pin_dir, own_mount) = match std::env::var_os("VESTA_SMOKE_BPFFS") {
            Some(p) => (PathBuf::from(p), None),
            None => {
                let t = tempfile::tempdir().unwrap();
                (t.path().to_path_buf(), Some(t))
            }
        };
        if let Err(e) = crate::sysinfo::ensure_bpffs(&pin_dir) {
            return skip(&format!(
                "cannot mount bpffs ({e:#}); run with --privileged"
            ));
        }
        let _ = std::fs::remove_dir(CG);
        std::fs::create_dir(CG).expect("creating the scratch cgroup");
        let env = Env { pin_dir, own_mount };
        let lsm = crate::sysinfo::active_lsms()
            .unwrap_or_default()
            .iter()
            .any(|l| l == "bpf");
        if !lsm {
            skip("bpf LSM not active: P2 (exec enforcement) checks are skipped");
        }
        // After the setup that mounts (bpffs, securityfs). VESTA_SMOKE_UNIT_CAPS=1: keep only the vesta-guestd.service
        // capabilities in this thread, proving load/attach/pin/status need
        // no CAP_SYS_ADMIN. Child processes (sh, nc) are unaffected.
        if std::env::var_os("VESTA_SMOKE_UNIT_CAPS").is_some() {
            use rustix::thread::{set_capabilities, CapabilitySet, CapabilitySets};
            let keep = CapabilitySet::BPF
                | CapabilitySet::PERFMON
                | CapabilitySet::NET_ADMIN
                | CapabilitySet::DAC_READ_SEARCH;
            set_capabilities(
                None,
                CapabilitySets {
                    effective: keep,
                    permitted: keep,
                    inheritable: CapabilitySet::empty(),
                },
            )
            .expect("dropping capabilities");
            eprintln!("running with CAP_BPF|CAP_PERFMON|CAP_NET_ADMIN|CAP_DAC_READ_SEARCH only");
        }

        let opts = LoadOptions {
            pin_root: env.pin_dir.join("vesta"),
            cgroup_root: "/sys/fs/cgroup".into(),
            ringbuf_bytes: 1 << 20,
            audit_unbound_exec: false,
            bpf_lsm_active: lsm,
        };
        let mut bpf = Bpf::load(&opts).expect("loading BPF");
        assert!(bpf.features().is_empty(), "load alone attaches nothing");
        bpf.attach_all();
        let status = bpf.prog_status(true);
        for p in &status {
            eprintln!(
                "{} {} state={} prog_id={} link_id={} {}",
                p.id, p.attach, p.state, p.prog_id, p.link_id, p.error
            );
        }
        let attached: Vec<&str> = status
            .iter()
            .filter(|p| p.state == pb::ProgState::Attached as i32)
            .map(|p| p.id.as_str())
            .collect();
        assert!(
            attached.contains(&"P1")
                && attached.contains(&"N1-connect4")
                && attached.contains(&"N1-connect6"),
            "{attached:?}"
        );
        assert_eq!(attached.contains(&"P2"), lsm);
        for name in PINNED_MAPS {
            assert!(
                opts.pin_root.join("maps").join(name).exists(),
                "map {name} pinned"
            );
        }
        bpf.init_config(&abi::Config {
            abi_version: 1,
            flags: abi::CFG_EXEC_ARGV,
            ..Default::default()
        })
        .unwrap();
        assert!(
            bpf.init_config(&abi::Config::default()).is_err(),
            "config is frozen"
        );

        let mut maps = bpf.policy_maps().unwrap();
        let events = bpf.events_map().unwrap();
        let got: Rc<RefCell<Vec<Record>>> = Rc::default();
        let sink = got.clone();
        let mut b = libbpf_rs::RingBufferBuilder::new();
        b.add(&events, move |s: &[u8]| {
            sink.borrow_mut()
                .push(Record::decode(s).expect("valid record"));
            0
        })
        .unwrap();
        let rb = b.build().unwrap();

        let cg_id = std::fs::metadata(CG).unwrap().ino();
        let bind = |maps: &mut BpfMaps, mode: u8| {
            let v = CgroupPolicy {
                generation: 1,
                policy_id: POLICY,
                mode,
                ..Default::default()
            };
            maps.put_cgroup(cg_id, &v).unwrap();
        };

        // Unbound cgroup: nothing is emitted (audit_unbound_exec = false).
        assert!(run_in_cgroup("/bin/true").success());
        rb.poll(Duration::from_millis(200)).unwrap();
        assert!(
            got.borrow().is_empty(),
            "unbound cgroup must not emit: {:?}",
            got.borrow()
        );

        // P1 exec audit with path and argv; policy_ready == 0 => POLICY_PENDING.
        bind(&mut maps, abi::mode::AUDIT);
        assert!(run_in_cgroup("/bin/true smoke-arg").success());
        let e = drain(
            &rb,
            &got,
            |r| matches!(r, Record::Exec(e) if e.hdr.hook == abi::hook::SCHED_PROCESS_EXEC),
        );
        let Record::Exec(e) = e else { unreachable!() };
        let path =
            String::from_utf8_lossy(&e.exec.path[..usize::from(e.exec.path_len)]).into_owned();
        let target = std::fs::canonicalize("/bin/true").unwrap();
        assert_eq!(Path::new(&path), target, "exe path");
        let md = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (e.exec.exe_ino, e.exec.exe_dev),
            (md.ino(), abi::s_dev_from_st_dev(md.dev()))
        );
        let argv = &e.exec.argv[..usize::from(e.exec.argv_len)];
        assert_eq!(argv, b"/bin/true\0smoke-arg\0");
        assert_eq!(
            (e.hdr.cgroup_id, e.hdr.policy_id, e.hdr.action),
            (cg_id, POLICY, abi::action::AUDITED)
        );
        assert_ne!(e.hdr.flags & abi::evf::POLICY_PENDING, 0);
        assert_eq!(e.hdr.flags & abi::evf::EXE_UNLINKED, 0);
        assert!(e.hdr.ns_tgid > 0 && e.hdr.tgid > 0);

        // fexecve of a deleted file is flagged EXE_UNLINKED.
        got.borrow_mut().clear();
        let _ = run_in_cgroup(&format!(
            "/bin/sh -c 'cp {} /tmp/vesta-unlinked && exec 3</tmp/vesta-unlinked && rm /tmp/vesta-unlinked && exec /proc/self/fd/3 true'",
            target.display()
        ));
        let e = drain(&rb, &got, |r| {
            matches!(r, Record::Exec(e) if e.hdr.hook == abi::hook::SCHED_PROCESS_EXEC
                && String::from_utf8_lossy(&e.exec.path[..usize::from(e.exec.path_len)]).contains("vesta-unlinked"))
        });
        assert_ne!(
            hdr(&e).flags & abi::evf::EXE_UNLINKED,
            0,
            "deleted exe flagged"
        );
        maps.set_policy_ready(1).unwrap();

        // A copy of the binary so denying it does not affect the shell. Same
        // file name, so a busybox copy still dispatches `true`.
        let bin_dir = tempfile::tempdir().unwrap();
        let bin = bin_dir.path().join(target.file_name().unwrap());
        std::fs::copy(&target, &bin).unwrap();
        let bmd = std::fs::metadata(&bin).unwrap();
        let key = ExecKey {
            policy_id: POLICY,
            dev: abi::s_dev_from_st_dev(bmd.dev()),
            ino: bmd.ino(),
        };
        maps.put_exec(
            &key,
            &RuleValue {
                verdict: 2,
                rule_id: 77,
            },
        )
        .unwrap();
        let run_bin = format!("{} true", bin.display());

        if lsm {
            // Audit mode: allowed, P2 reports WOULD_DENY with the rule.
            got.borrow_mut().clear();
            assert!(run_in_cgroup(&run_bin).success());
            let r = drain(&rb, &got, |r| hdr(r).hook == abi::hook::BPRM_CHECK_SECURITY);
            assert_eq!(
                (hdr(&r).action, hdr(&r).rule_id),
                (abi::action::AUDITED, 77)
            );
            assert_ne!(hdr(&r).flags & abi::evf::WOULD_DENY, 0);

            // Enforce: exec fails with EPERM and a DENIED event.
            bind(&mut maps, abi::mode::ENFORCE);
            got.borrow_mut().clear();
            assert!(!run_in_cgroup(&run_bin).success(), "exec must be denied");
            let r = drain(&rb, &got, |r| hdr(r).hook == abi::hook::BPRM_CHECK_SECURITY);
            assert_eq!(hdr(&r).action, abi::action::DENIED);

            // Kill switch AUDIT_ONLY: never deny.
            maps.set_global_mode(abi::global_mode::AUDIT_ONLY).unwrap();
            got.borrow_mut().clear();
            assert!(run_in_cgroup(&run_bin).success());
            let r = drain(&rb, &got, |r| hdr(r).hook == abi::hook::BPRM_CHECK_SECURITY);
            assert_ne!(hdr(&r).flags & abi::evf::GLOBAL_AUDIT_ONLY, 0);
            maps.set_global_mode(abi::global_mode::NORMAL).unwrap();

            // Fail-closed while the binding is pending.
            let v = CgroupPolicy {
                generation: 2,
                policy_id: POLICY,
                mode: 1,
                failure: 1,
                flags: abi::CGF_PENDING,
                ..Default::default()
            };
            maps.put_cgroup(cg_id, &v).unwrap();
            assert!(
                !run_in_cgroup("/bin/true").success(),
                "pending + closed denies"
            );
        }
        drop(bin_dir);

        // N1: deny TCP to 127.0.0.1:9 in enforce mode (connect4 works without the bpf LSM).
        bind(&mut maps, abi::mode::ENFORCE);
        let k = NetKeyV4 {
            prefixlen: 64 + 32,
            policy_id: POLICY,
            protocol: 6,
            _pad0: 0,
            port: 9u16.to_be_bytes(),
            addr: [127, 0, 0, 1],
        };
        maps.put_net4(
            &k,
            &RuleValue {
                verdict: 2,
                rule_id: 88,
            },
        )
        .unwrap();
        got.borrow_mut().clear();
        let _ = run_in_cgroup("nc -w 1 127.0.0.1 9");
        let r = drain(&rb, &got, |r| matches!(r, Record::Connect(_)));
        let Record::Connect(c) = r else {
            unreachable!()
        };
        assert_eq!(
            (c.hdr.action, c.hdr.rule_id, c.connect.protocol),
            (abi::action::DENIED, 88, 6)
        );
        assert_eq!(
            (
                c.connect.daddr[..4].to_vec(),
                u16::from_be_bytes(c.connect.dport)
            ),
            (vec![127, 0, 0, 1], 9)
        );
        // A different port falls through to the default (allow) and is audited as ALLOWED.
        got.borrow_mut().clear();
        let _ = run_in_cgroup("nc -w 1 127.0.0.1 10");
        let r = drain(&rb, &got, |r| matches!(r, Record::Connect(_)));
        assert_eq!((hdr(&r).action, hdr(&r).rule_id), (abi::action::ALLOWED, 0));

        // Kill switch DETACHED: links are unpinned and closed.
        bpf.set_attached(false).unwrap();
        assert_eq!(
            std::fs::read_dir(opts.pin_root.join("links"))
                .unwrap()
                .count(),
            0
        );
        assert!(bpf.features().is_empty());
        bpf.set_attached(true).unwrap();
        assert_eq!(
            std::fs::read_dir(opts.pin_root.join("links"))
                .unwrap()
                .count(),
            attached.len()
        );
        eprintln!("drops: {:?}", bpf.drop_counts());

        // Restart: a second load reuses the pinned maps and replaces the link pins.
        let mut bpf2 = Bpf::load(&opts).expect("reloading");
        assert!(bpf2.maps_reused);
        bpf2.attach_all();
        {
            use crate::events::SeqStore;
            let seq = bpf2.seq_store().unwrap();
            seq.store(4242).unwrap();
            assert_eq!(
                bpf2.seq_store().unwrap().load().unwrap(),
                4242,
                "seq survives reopen"
            );
        }
        let (state, _, ready) = bpf2.policy_maps().unwrap().snapshot().unwrap();
        assert_eq!(ready, 1);
        assert!(state.cgroups.contains_key(&cg_id));
        assert!(
            bpf2.init_config(&abi::Config::default()).is_ok(),
            "reused frozen config is accepted"
        );
        drop(bpf);
        assert_eq!(
            std::fs::read_dir(opts.pin_root.join("links"))
                .unwrap()
                .count(),
            attached.len()
        );
    }
}
