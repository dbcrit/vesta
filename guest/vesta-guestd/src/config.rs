// SPDX-License-Identifier: Apache-2.0
//! `/etc/vesta/guestd.toml`, baked into the read-only guest image.
//! Unknown keys are rejected; every value is range-checked.

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde::Deserialize;

use crate::abi;

pub const DEFAULT_PATH: &str = "/etc/vesta/guestd.toml";
/// Ports Kata itself uses in the guest (docs/compat/kata-4.2.md §3).
const KATA_PORTS: [u32; 4] = [1024, 1025, 1026, 1027];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineMode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineFailure {
    Open,
    Closed,
}

/// Applied to bound containers whose policy generation is not applied yet.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Baseline {
    pub mode: BaselineMode,
    pub failure: BaselineFailure,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            mode: BaselineMode::Audit,
            failure: BaselineFailure::Open,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Guest image version (semver, no build metadata), reported in HelloReply.
    pub guest_image_version: String,
    pub ctrl_port: u32,
    pub evt_port: u32,
    /// Only connections from this vsock CID are served (2 = host).
    pub allowed_peer_cid: u32,
    pub pin_root: PathBuf,
    pub cgroup_root: PathBuf,
    /// kata-agent's container bundle base; rootfs is `<base>/<cid>/rootfs`.
    pub container_rootfs_base: PathBuf,
    pub heartbeat_interval_ms: u32,
    pub ringbuf_bytes: u32,
    pub replay_max_events: usize,
    pub replay_max_bytes: usize,
    pub bind_timeout_ms: u32,
    pub bind_poll_ms: u32,
    pub frame_timeout_ms: u32,
    pub write_timeout_ms: u32,
    pub gc_interval_ms: u32,
    pub capture_argv: bool,
    pub audit_unbound_exec: bool,
    /// Accept MODE_ENFORCE bundles (still requires the bpf LSM to be active).
    pub allow_enforce: bool,
    /// Cgroups (relative to cgroup_root) that no BindContainer may cover.
    /// guestd's own cgroup is always protected.
    pub protected_cgroups: Vec<String>,
    pub log_level: LogLevel,
    pub baseline: Baseline,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            guest_image_version: "0.0.0".into(),
            ctrl_port: 22085,
            evt_port: 22086,
            allowed_peer_cid: 2,
            pin_root: "/sys/fs/bpf/vesta".into(),
            cgroup_root: "/sys/fs/cgroup".into(),
            container_rootfs_base: "/run/kata-containers".into(),
            heartbeat_interval_ms: 5000,
            ringbuf_bytes: abi::RINGBUF_DEFAULT_BYTES,
            replay_max_events: 16384,
            replay_max_bytes: 8 << 20,
            bind_timeout_ms: 10_000,
            bind_poll_ms: 100,
            frame_timeout_ms: 10_000,
            write_timeout_ms: 10_000,
            gc_interval_ms: 30_000,
            capture_argv: true,
            audit_unbound_exec: false,
            allow_enforce: true,
            protected_cgroups: vec!["system.slice/kata-agent.service".into()],
            log_level: LogLevel::Info,
            baseline: Baseline::default(),
        }
    }
}

fn is_label_semver(v: &str) -> bool {
    // MAJOR.MINOR.PATCH[-prerelease], no build metadata, <= 63 bytes (label value).
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let nums: Vec<&str> = core.split('.').collect();
    v.len() <= 63
        && nums.len() == 3
        && nums
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && pre
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !(v.contains('-') && pre.is_empty())
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %path.display(), "config file not found, using defaults");
                String::new()
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            is_label_semver(&self.guest_image_version),
            "guest_image_version must be semver without build metadata"
        );
        for (name, port) in [("ctrl_port", self.ctrl_port), ("evt_port", self.evt_port)] {
            ensure!(
                port >= 1024 && port != u32::MAX,
                "{name} {port} out of range"
            );
            ensure!(!KATA_PORTS.contains(&port), "{name} {port} is used by Kata");
        }
        ensure!(
            self.ctrl_port != self.evt_port,
            "ctrl_port and evt_port must differ"
        );
        ensure!(
            self.allowed_peer_cid != u32::MAX,
            "allowed_peer_cid must be a specific CID"
        );
        for (name, p) in [
            ("pin_root", &self.pin_root),
            ("cgroup_root", &self.cgroup_root),
            ("container_rootfs_base", &self.container_rootfs_base),
        ] {
            ensure!(p.is_absolute(), "{name} must be absolute");
            ensure!(
                !std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()).contains(&0),
                "{name} must not contain NUL"
            );
            ensure!(
                !p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "{name} must not contain .."
            );
        }
        ensure!(
            (100..=60_000).contains(&self.heartbeat_interval_ms),
            "heartbeat_interval_ms outside 100..=60000"
        );
        let page = rustix::param::page_size() as u32;
        ensure!(
            self.ringbuf_bytes.is_power_of_two()
                && self.ringbuf_bytes >= page
                && self.ringbuf_bytes <= 256 << 20,
            "ringbuf_bytes must be a power of two between the page size and 256 MiB"
        );
        ensure!(
            (1..=1_000_000).contains(&self.replay_max_events),
            "replay_max_events outside 1..=1000000"
        );
        ensure!(
            (64 << 10..=256 << 20).contains(&self.replay_max_bytes),
            "replay_max_bytes outside 64KiB..=256MiB"
        );
        ensure!(
            (100..=120_000).contains(&self.bind_timeout_ms),
            "bind_timeout_ms outside 100..=120000"
        );
        ensure!(
            (5..=1000).contains(&self.bind_poll_ms),
            "bind_poll_ms outside 5..=1000"
        );
        ensure!(
            (100..=120_000).contains(&self.frame_timeout_ms),
            "frame_timeout_ms outside 100..=120000"
        );
        ensure!(
            (100..=120_000).contains(&self.write_timeout_ms),
            "write_timeout_ms outside 100..=120000"
        );
        ensure!(
            (1000..=3_600_000).contains(&self.gc_interval_ms),
            "gc_interval_ms outside 1000..=3600000"
        );
        ensure!(
            self.protected_cgroups.len() <= 64,
            "protected_cgroups has more than 64 entries"
        );
        for p in &self.protected_cgroups {
            crate::cgroup::protected_path(p)
                .with_context(|| format!("protected_cgroups entry {p:?}"))?;
        }
        if self.baseline.mode == BaselineMode::Enforce && !self.allow_enforce {
            bail!("baseline.mode = enforce needs allow_enforce = true");
        }
        Ok(())
    }

    pub fn baseline_abi(&self) -> crate::state::Baseline {
        crate::state::Baseline {
            mode: match self.baseline.mode {
                BaselineMode::Audit => abi::mode::AUDIT,
                BaselineMode::Enforce => abi::mode::ENFORCE,
            },
            failure: match self.baseline.failure {
                BaselineFailure::Open => abi::failure::OPEN,
                BaselineFailure::Closed => abi::failure::CLOSED,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> anyhow::Result<Config> {
        let c: Config = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn defaults_are_valid() {
        let c = parse("").unwrap();
        assert_eq!(
            (c.ctrl_port, c.evt_port, c.allowed_peer_cid),
            (22085, 22086, 2)
        );
    }

    #[test]
    fn full_file() {
        let c = parse(
            r#"
            guest_image_version = "1.2.3-rc.1"
            ctrl_port = 30000
            evt_port = 30001
            heartbeat_interval_ms = 1000
            ringbuf_bytes = 8388608
            capture_argv = false
            log_level = "debug"
            [baseline]
            mode = "enforce"
            failure = "closed"
            "#,
        )
        .unwrap();
        assert_eq!(
            c.baseline_abi(),
            crate::state::Baseline {
                mode: 1,
                failure: 1
            }
        );
        assert!(!c.capture_argv);
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            "unknown_key = 1",
            "ctrl_port = 1024",
            "ctrl_port = 80",
            "evt_port = 22085",
            "ringbuf_bytes = 12345",
            "heartbeat_interval_ms = 0",
            "pin_root = \"relative\"",
            "pin_root = \"/sys/../etc\"",
            "pin_root = \"/sys/fs/bpf\\u0000x\"",
            "guest_image_version = \"1.2.3+build\"",
            "guest_image_version = \"1.2\"",
            "guest_image_version = \"1.2.3-\"",
            "allowed_peer_cid = 4294967295",
            "protected_cgroups = [\"a/../b\"]",
            "protected_cgroups = [\"\"]",
            "[baseline]\nmode = \"loud\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
