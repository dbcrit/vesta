// SPDX-License-Identifier: Apache-2.0
//! Startup environment checks and small process-level helpers.

use std::path::Path;

use anyhow::{bail, Context};
use rustix::mount::{mount, MountFlags};

const SECURITYFS: &str = "/sys/kernel/security";
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const SECURITYFS_MAGIC: i64 = 0x7363_6673;

/// HelloReply limits (control.proto).
const MAX_LSMS: usize = 32;
const MAX_LSM_LEN: usize = 32;
const MAX_RELEASE_LEN: usize = 128;

/// Static facts about this guest, reported in HelloReply.
#[derive(Debug, Clone, Default)]
pub struct GuestInfo {
    pub kernel_release: String,
    pub active_lsms: Vec<String>,
    pub bpf_lsm: bool,
    pub cgroup_v2: bool,
    pub guest_image_version: String,
    pub guestd_version: String,
}

/// statfs f_type as i64 (its C type differs between targets).
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
pub fn f_type(st: &rustix::fs::StatFs) -> i64 {
    st.f_type as i64
}

fn fs_magic(path: &Path) -> Option<i64> {
    rustix::fs::statfs(path).ok().map(|s| f_type(&s))
}

/// Parses `/sys/kernel/security/lsm` ("capability,landlock,bpf").
pub fn parse_lsms(s: &str) -> Vec<String> {
    s.trim()
        .split(',')
        .filter(|l| {
            !l.is_empty() && l.len() <= MAX_LSM_LEN && l.bytes().all(|b| b.is_ascii_graphic())
        })
        .take(MAX_LSMS)
        .map(str::to_string)
        .collect()
}

/// Reads the active LSM list, mounting securityfs if systemd has not.
pub fn active_lsms() -> anyhow::Result<Vec<String>> {
    let path = Path::new(SECURITYFS).join("lsm");
    if fs_magic(Path::new(SECURITYFS)) != Some(SECURITYFS_MAGIC) {
        mount(
            "securityfs",
            SECURITYFS,
            "securityfs",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .context("mounting securityfs")?;
    }
    let s =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_lsms(&s))
}

pub fn is_cgroup2(path: &Path) -> bool {
    fs_magic(path) == Some(CGROUP2_SUPER_MAGIC)
}

/// Makes sure a bpffs is mounted at `mountpoint` (usually /sys/fs/bpf).
pub fn ensure_bpffs(mountpoint: &Path) -> anyhow::Result<()> {
    if fs_magic(mountpoint) == Some(BPF_FS_MAGIC) {
        return Ok(());
    }
    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("creating {}", mountpoint.display()))?;
    mount(
        "bpf",
        mountpoint,
        "bpf",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        Some(c"mode=0700"),
    )
    .with_context(|| format!("mounting bpffs at {}", mountpoint.display()))?;
    if fs_magic(mountpoint) != Some(BPF_FS_MAGIC) {
        bail!("{} is not a bpffs after mounting", mountpoint.display());
    }
    Ok(())
}

pub fn kernel_release() -> String {
    let uname = rustix::system::uname();
    let mut r = uname.release().to_string_lossy().into_owned();
    r.truncate(MAX_RELEASE_LEN);
    r
}

/// (resident bytes, user+system CPU ns) of this process.
pub fn process_usage() -> (u64, u64) {
    let page = rustix::param::page_size() as u64;
    let rss = std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
        })
        .map_or(0, |pages| pages * page);
    let ticks = rustix::param::clock_ticks_per_second().max(1);
    let cpu = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            // Fields after the parenthesised comm; utime and stime are fields 14 and 15.
            let rest = s.rsplit_once(')')?.1;
            let f: Vec<&str> = rest.split_whitespace().collect();
            Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
        })
        .map_or(0, |t| t.saturating_mul(1_000_000_000 / ticks));
    (rss, cpu)
}

/// Sends a systemd notification (`READY=1`, `STATUS=...`) if NOTIFY_SOCKET is set.
pub fn sd_notify(msg: &str) {
    let Some(sock) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let res = (|| -> std::io::Result<()> {
        let s = std::os::unix::net::UnixDatagram::unbound()?;
        let bytes = sock.as_encoded_bytes();
        if let Some(name) = bytes.strip_prefix(b"@") {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            s.send_to_addr(msg.as_bytes(), &addr)?;
        } else {
            s.send_to(msg.as_bytes(), Path::new(&sock))?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!(error = %e, "sd_notify failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsm_parsing_is_bounded() {
        assert_eq!(
            parse_lsms("capability,landlock,bpf\n"),
            vec!["capability", "landlock", "bpf"]
        );
        assert_eq!(parse_lsms(""), Vec::<String>::new());
        let long = format!("{},bpf", "x".repeat(40));
        assert_eq!(parse_lsms(&long), vec!["bpf"]);
        let many = vec!["a"; 100].join(",");
        assert_eq!(parse_lsms(&many).len(), MAX_LSMS);
    }

    #[test]
    fn usage_reads_proc() {
        let (rss, _cpu) = process_usage();
        assert!(rss > 0);
    }
}
