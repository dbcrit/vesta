// SPDX-License-Identifier: Apache-2.0
//! Startup sequence and long-running tasks (ARCHITECTURE §2.9):
//! checks -> load/attach/pin -> config map -> READY=1 -> vsock listeners,
//! ring buffer consumer, cgroup GC. On SIGTERM guestd exits and leaves the
//! pinned links attached, so enforcement continues without it.

use std::cell::RefCell;
use std::collections::HashSet;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

use crate::abi;
use crate::bpf::{Bpf, LoadOptions, Unloaded};
use crate::cgroup;
use crate::config::Config;
use crate::daemon::{BpfControl, CgroupLookup, Daemon, Shared, Unavailable};
use crate::events::EventHub;
use crate::resolve::RootfsResolver;
use crate::state::{Engine, PolicyMaps};
use crate::sysinfo::{self, GuestInfo};

const MAX_CGROUPS_SCANNED: usize = 65536;
/// Ring buffer records handled per turn before other tasks get to run.
const RING_BUDGET: usize = 1024;

#[derive(Debug)]
struct RealCgroups {
    root: PathBuf,
    root_fd: OwnedFd,
}

impl CgroupLookup for RealCgroups {
    fn lookup(&self, rel: &Path) -> std::io::Result<Option<u64>> {
        cgroup::lookup_cgroup_id(&self.root_fd, rel)
    }
    fn existing_ids(&self) -> std::io::Result<HashSet<u64>> {
        cgroup::existing_cgroup_ids(&self.root, MAX_CGROUPS_SCANNED)
    }
}

/// The ring buffer's epoll fd, borrowed for tokio readiness. `RingBuffer` owns it
/// and outlives the `AsyncFd` (see `consume_events`).
struct EpollFd(RawFd);

impl AsRawFd for EpollFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

async fn consume_events(d: Shared, events: MapHandle) -> anyhow::Result<()> {
    let cb = d.clone();
    let mut builder = RingBufferBuilder::new();
    builder.add(&events, move |sample: &[u8]| {
        match cb.try_borrow_mut() {
            Ok(mut dm) => dm.hub.ingest(sample),
            // Unreachable: no borrow is held while consuming.
            Err(_) => tracing::error!("event hub busy; dropping a ring buffer record"),
        }
        0
    })?;
    let rb = builder
        .build()
        .context("creating the ring buffer consumer")?;
    let afd = AsyncFd::with_interest(EpollFd(rb.epoll_fd()), Interest::READABLE)?;
    let notify = d.borrow().events_ready.clone();
    // Safety net against a missed edge on the nested epoll fd.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut backlog = false;
    loop {
        if !backlog {
            tokio::select! {
                g = afd.readable() => g?.clear_ready(),
                _ = tick.tick() => {}
            }
        }
        d.borrow_mut().hub.refresh_clock();
        // Bounded: a producer at least as fast as guestd must not keep it
        // here (ring_buffer__poll loops for as long as data keeps arriving).
        let n = rb.consume_raw_n(RING_BUDGET);
        if n < 0 {
            return Err(anyhow!(
                "consuming the ring buffer: {}",
                std::io::Error::from_raw_os_error(n.saturating_neg())
            ));
        }
        backlog = usize::try_from(n).unwrap_or(0) >= RING_BUDGET;
        notify.notify_one();
        if backlog {
            tokio::task::yield_now().await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Channel {
    Ctrl,
    Evt,
}

/// Accepts connections on `port`; a new connection replaces the previous one.
async fn listen(d: Shared, port: u32, kind: Channel) {
    let allowed = d.borrow().cfg.allowed_peer_cid;
    let listener = loop {
        match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)) {
            Ok(l) => break l,
            Err(e) => {
                tracing::error!(port, error = %e, "vsock bind failed; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    tracing::info!(port, ?kind, "listening on vsock");
    let mut current: Option<JoinHandle<()>> = None;
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(port, error = %e, "vsock accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Only the host may connect; in-guest processes (vsock loopback) are refused.
        if addr.cid() != allowed {
            tracing::warn!(
                port,
                peer_cid = addr.cid(),
                "refusing vsock connection from unexpected CID"
            );
            continue;
        }
        if let Some(prev) = current.take() {
            tracing::info!(port, "new connection replaces the previous one");
            prev.abort();
        }
        current = Some(match kind {
            Channel::Ctrl => tokio::task::spawn_local(crate::ctrl::serve(d.clone(), stream)),
            Channel::Evt => tokio::task::spawn_local(crate::evt::serve(d.clone(), stream)),
        });
    }
}

async fn gc_loop(d: Shared) {
    let period = Duration::from_millis(d.borrow().cfg.gc_interval_ms.into());
    let mut tick = tokio::time::interval(period);
    tick.tick().await;
    loop {
        tick.tick().await;
        let existing = d.borrow().cgroups.existing_ids();
        match existing {
            Ok(ids) => {
                let mut dm = d.borrow_mut();
                match dm.engine.gc(&ids) {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(removed = n, "removed bindings of deleted cgroups"),
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "cgroup GC failed"),
                }
                dm.sync_container_names();
            }
            Err(e) => tracing::warn!(error = %e, "scanning cgroups failed"),
        }
    }
}

fn guestd_identity(cgroup_root: &Path) -> anyhow::Result<(u64, u64, u32)> {
    let exe = std::fs::metadata("/proc/self/exe").context("stat /proc/self/exe")?;
    let cg = cgroup::self_cgroup_id(cgroup_root).context("own cgroup id")?;
    Ok((cg, exe.ino(), abi::s_dev_from_st_dev(exe.dev())))
}

struct Loaded {
    maps: Box<dyn PolicyMaps>,
    control: Box<dyn BpfControl>,
    events: Option<MapHandle>,
    seq: Option<crate::bpf::SeqMap>,
    adopted: Option<(crate::state::MapState, u32, u64)>,
}

/// Loads the object, then writes `config` and reads adopted state, and only
/// then attaches: if anything before attaching fails, nothing new is attached.
fn load_bpf(cfg: &Config, info: &GuestInfo) -> anyhow::Result<Loaded> {
    if !info.cgroup_v2 {
        return Err(anyhow!(
            "cgroup v2 is not mounted at {}",
            cfg.cgroup_root.display()
        ));
    }
    let bpffs = cfg
        .pin_root
        .parent()
        .ok_or_else(|| anyhow!("pin_root has no parent"))?;
    sysinfo::ensure_bpffs(bpffs)?;
    let mut bpf = Bpf::load(&LoadOptions {
        pin_root: cfg.pin_root.clone(),
        cgroup_root: cfg.cgroup_root.clone(),
        ringbuf_bytes: cfg.ringbuf_bytes,
        audit_unbound_exec: cfg.audit_unbound_exec,
        bpf_lsm_active: info.bpf_lsm,
    })?;
    let (cg, ino, dev) = guestd_identity(&cfg.cgroup_root)?;
    bpf.init_config(&abi::Config {
        abi_version: abi::ABI_VERSION,
        flags: if cfg.capture_argv {
            abi::CFG_EXEC_ARGV
        } else {
            0
        },
        guestd_cgroup_id: cg,
        guestd_exe_ino: ino,
        guestd_exe_dev: dev,
        heartbeat_interval_ms: cfg.heartbeat_interval_ms,
    })?;
    let maps = bpf.policy_maps()?;
    let adopted = if bpf.maps_reused {
        let (state, mode, ready) = maps.snapshot()?;
        tracing::info!(
            cgroups = state.cgroups.len(),
            exec_rules = state.exec.len(),
            policy_ready = ready,
            "adopted maps pinned by a previous guestd"
        );
        Some((state, mode, ready))
    } else {
        None
    };
    let events = bpf.events_map()?;
    let seq = match bpf.seq_store() {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "event seq store unavailable; seqs restart at 1 after a guestd restart");
            None
        }
    };
    bpf.attach_all();
    Ok(Loaded {
        maps: Box::new(maps),
        control: Box::new(bpf),
        events: Some(events),
        seq,
        adopted,
    })
}

/// Cgroups no BindContainer may cover: guestd's own plus the configured ones.
fn protected_cgroups(cfg: &Config) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = cfg
        .protected_cgroups
        .iter()
        .filter_map(|p| cgroup::protected_path(p).ok())
        .collect();
    match cgroup::self_cgroup_rel() {
        Ok(own) if own.components().next().is_some() => out.push(own),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "cannot read guestd's own cgroup"),
    }
    out
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let active_lsms = sysinfo::active_lsms().unwrap_or_else(|e| {
        tracing::warn!(error = %format!("{e:#}"), "cannot read the active LSM list");
        Vec::new()
    });
    let info = GuestInfo {
        kernel_release: sysinfo::kernel_release(),
        bpf_lsm: active_lsms.iter().any(|l| l == "bpf"),
        active_lsms,
        cgroup_v2: sysinfo::is_cgroup2(&cfg.cgroup_root),
        guest_image_version: cfg.guest_image_version.clone(),
        guestd_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    tracing::info!(kernel = %info.kernel_release, lsms = ?info.active_lsms, cgroup_v2 = info.cgroup_v2, "starting vesta-guestd");

    let loaded = load_bpf(&cfg, &info).unwrap_or_else(|e| {
        let msg = format!("{e:#}");
        tracing::error!(error = %msg, "BPF programs unavailable; serving status only");
        Loaded {
            maps: Box::new(Unavailable(msg.clone())),
            control: Box::new(Unloaded(msg)),
            events: None,
            seq: None,
            adopted: None,
        }
    });
    let enforce = cfg.allow_enforce
        && info.bpf_lsm
        && loaded.control.features().iter().any(|f| f == "exec_lsm");
    let mut engine = Engine::new(
        loaded.maps,
        Box::new(RootfsResolver::new(&cfg.container_rootfs_base)),
        cfg.baseline_abi(),
        enforce,
    );
    if let Some((state, mode, ready)) = loaded.adopted {
        engine.adopt(state, mode, ready);
    }
    engine.set_protected_cgroups(protected_cgroups(&cfg));
    let mut hub = EventHub::new(cfg.replay_max_events, cfg.replay_max_bytes);
    if let Some(seq) = loaded.seq {
        hub = hub.with_seq_store(Box::new(seq)).unwrap_or_else(|e| {
            tracing::warn!(error = %format!("{e:#}"), "reading the event seq failed; numbering starts at 1");
            EventHub::new(cfg.replay_max_events, cfg.replay_max_bytes)
        });
    }
    let cgroups = RealCgroups {
        root: cfg.cgroup_root.clone(),
        root_fd: cgroup::open_root(&cfg.cgroup_root).or_else(|_| {
            rustix::fs::open(
                &cfg.cgroup_root,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)
        })?,
    };
    let (ctrl_port, evt_port) = (cfg.ctrl_port, cfg.evt_port);
    let d: Shared = Rc::new(RefCell::new(Daemon {
        hub,
        cfg,
        info,
        engine,
        bpf: loaded.control,
        cgroups: Box::new(cgroups),
        cgroup_waits: crate::cgwatch::CgroupWaits::default(),
        events_ready: Rc::new(Notify::new()),
        heartbeat_seq: 0,
        pending_binds: 0,
    }));

    if let Some(events) = loaded.events {
        let dc = d.clone();
        tokio::task::spawn_local(async move {
            if let Err(e) = consume_events(dc, events).await {
                tracing::error!(error = %format!("{e:#}"), "ring buffer consumer stopped; events are no longer delivered");
            }
        });
    }
    let attached = d.borrow().bpf.features();
    sysinfo::sd_notify(&format!(
        "READY=1\nSTATUS=attached: {}",
        if attached.is_empty() {
            "none".into()
        } else {
            attached.join(",")
        }
    ));

    tokio::task::spawn_local(listen(d.clone(), ctrl_port, Channel::Ctrl));
    tokio::task::spawn_local(listen(d.clone(), evt_port, Channel::Evt));
    tokio::task::spawn_local(gc_loop(d.clone()));
    tokio::task::spawn_local(crate::cgwatch::run(d.clone()));

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    sysinfo::sd_notify("STOPPING=1");
    d.borrow_mut().hub.persist_last_seq();
    tracing::info!("shutting down; pinned programs stay attached");
    Ok(())
}
