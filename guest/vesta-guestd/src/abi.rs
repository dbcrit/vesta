// SPDX-License-Identifier: Apache-2.0
//! Mirror of `bpf/include/vesta_abi.h` (docs/abi.md).
//!
//! Structs are `#[repr(C)]` with the same explicit padding as the header;
//! sizes and offsets are pinned by const assertions here and cross-checked
//! against the header's `_Static_assert`s in the tests. Conversion to and
//! from bytes is done field by field (no transmutes), in guest byte order.

// The constant set mirrors the header completely; some values are only used by tests.
#![allow(dead_code)]

use std::mem::{offset_of, size_of};

pub const ABI_VERSION: u32 = 1;

pub const COMM_LEN: usize = 16;
pub const PATH_MAX: usize = 256;
pub const ARGV_MAX: usize = 1024;

pub const MAX_CGROUPS: usize = 4096;
pub const MAX_EXEC_RULES: usize = 65536;
pub const MAX_NET_RULES: usize = 16384;
pub const MAX_POLICIES: u32 = 1024;
pub const RINGBUF_DEFAULT_BYTES: u32 = 4 << 20;
pub const NET_KEY_FIXED_BITS: u32 = 64;

pub mod event_type {
    pub const EXEC: u16 = 1;
    pub const CONNECT: u16 = 2;
    /// Bound of `drop_counters`.
    pub const MAX: u32 = 16;
}

pub mod action {
    pub const AUDITED: u8 = 1;
    pub const DENIED: u8 = 2;
    pub const ALLOWED: u8 = 3;
}

pub mod hook {
    pub const SCHED_PROCESS_EXEC: u8 = 1;
    pub const BPRM_CHECK_SECURITY: u8 = 2;
    pub const CGROUP_CONNECT4: u8 = 3;
    pub const CGROUP_CONNECT6: u8 = 4;
}

pub mod mode {
    pub const AUDIT: u8 = 0;
    pub const ENFORCE: u8 = 1;
}

pub mod failure {
    pub const OPEN: u8 = 0;
    pub const CLOSED: u8 = 1;
}

pub mod global_mode {
    pub const NORMAL: u32 = 0;
    pub const AUDIT_ONLY: u32 = 1;
    pub const DETACHED: u32 = 2;
}

pub mod verdict {
    pub const NONE: u8 = 0;
    pub const ALLOW: u8 = 1;
    pub const DENY: u8 = 2;
}

pub mod evf {
    pub const PATH_TRUNCATED: u32 = 1 << 0;
    pub const ARGV_TRUNCATED: u32 = 1 << 1;
    pub const CGROUP_UNBOUND: u32 = 1 << 2;
    pub const POLICY_PENDING: u32 = 1 << 3;
    pub const WOULD_DENY: u32 = 1 << 4;
    pub const GLOBAL_AUDIT_ONLY: u32 = 1 << 5;
    pub const EXE_UNLINKED: u32 = 1 << 6;
    pub const EXE_OUTSIDE_ROOT: u32 = 1 << 7;
    /// Number of defined flag bits (bit n = event.v1.EventFlag n + 1).
    pub const COUNT: u32 = 8;
}

pub const CGF_PENDING: u8 = 1 << 0;
pub const CFG_EXEC_ARGV: u32 = 1 << 0;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventHeader {
    pub abi_version: u16,
    pub r#type: u16,
    pub size: u16,
    pub action: u8,
    pub hook: u8,
    pub ktime_boot_ns: u64,
    pub cgroup_id: u64,
    pub policy_generation: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub policy_id: u32,
    pub rule_id: u32,
    pub flags: u32,
    pub comm: [u8; COMM_LEN],
    pub ns_tgid: u32,
    pub _pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecPayload {
    pub exe_dev: u32,
    pub argc: u32,
    pub exe_ino: u64,
    pub path_len: u16,
    pub argv_len: u16,
    pub _pad0: u32,
    pub path: [u8; PATH_MAX],
    pub argv: [u8; ARGV_MAX],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecEvent {
    pub hdr: EventHeader,
    pub exec: ExecPayload,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectPayload {
    pub family: u16,
    pub protocol: u8,
    pub verdict: u8,
    /// Network byte order, stored as raw bytes.
    pub dport: [u8; 2],
    pub _pad0: u16,
    pub daddr: [u8; 16],
    pub sock_cookie: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectEvent {
    pub hdr: EventHeader,
    pub connect: ConnectPayload,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub abi_version: u32,
    pub flags: u32,
    pub guestd_cgroup_id: u64,
    pub guestd_exe_ino: u64,
    pub guestd_exe_dev: u32,
    pub heartbeat_interval_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlobalModeValue {
    pub mode: u32,
    pub _pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyReadyValue {
    pub generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CgroupPolicy {
    pub generation: u64,
    pub policy_id: u32,
    pub mode: u8,
    pub failure: u8,
    pub rootfs_type: u8,
    pub flags: u8,
    pub exec_default: u8,
    pub net_default: u8,
    pub _pad0: u16,
    pub _pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecKey {
    pub policy_id: u32,
    pub dev: u32,
    pub ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RuleValue {
    pub verdict: u32,
    pub rule_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetKeyV4 {
    pub prefixlen: u32,
    pub policy_id: u32,
    pub protocol: u8,
    pub _pad0: u8,
    /// Network byte order.
    pub port: [u8; 2],
    pub addr: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetKeyV6 {
    pub prefixlen: u32,
    pub policy_id: u32,
    pub protocol: u8,
    pub _pad0: u8,
    pub port: [u8; 2],
    pub addr: [u8; 16],
}

// Layout pins, same values as the header's _Static_asserts.
const _: () = assert!(size_of::<EventHeader>() == 88);
const _: () = assert!(offset_of!(EventHeader, ktime_boot_ns) == 8);
const _: () = assert!(offset_of!(EventHeader, pid) == 32);
const _: () = assert!(offset_of!(EventHeader, comm) == 64);
const _: () = assert!(offset_of!(EventHeader, ns_tgid) == 80);
const _: () = assert!(size_of::<ExecPayload>() == 1304);
const _: () = assert!(offset_of!(ExecPayload, path) == 24);
const _: () = assert!(offset_of!(ExecPayload, argv) == 280);
const _: () = assert!(size_of::<ExecEvent>() == 1392);
const _: () = assert!(size_of::<ConnectPayload>() == 32);
const _: () = assert!(offset_of!(ConnectPayload, daddr) == 8);
const _: () = assert!(offset_of!(ConnectPayload, sock_cookie) == 24);
const _: () = assert!(size_of::<ConnectEvent>() == 120);
const _: () = assert!(size_of::<Config>() == 32);
const _: () = assert!(size_of::<GlobalModeValue>() == 8);
const _: () = assert!(size_of::<PolicyReadyValue>() == 8);
const _: () = assert!(size_of::<CgroupPolicy>() == 24);
const _: () = assert!(offset_of!(CgroupPolicy, exec_default) == 16);
const _: () = assert!(size_of::<ExecKey>() == 16);
const _: () = assert!(size_of::<RuleValue>() == 8);
const _: () = assert!(size_of::<NetKeyV4>() == 16);
const _: () = assert!(offset_of!(NetKeyV4, addr) == 12);
const _: () = assert!(size_of::<NetKeyV6>() == 28);
const _: () = assert!(offset_of!(NetKeyV6, addr) == 12);
const _: () = assert!(NET_KEY_FIXED_BITS as usize == 8 * (offset_of!(NetKeyV4, addr) - 4));

/// Builds a fixed-size byte image of an ABI struct, zero-filled so padding is zero.
struct Writer<const N: usize>([u8; N]);

impl<const N: usize> Writer<N> {
    fn new() -> Self {
        Self([0; N])
    }
    fn put(&mut self, off: usize, bytes: &[u8]) -> &mut Self {
        self.0[off..off + bytes.len()].copy_from_slice(bytes);
        self
    }
    fn done(&self) -> [u8; N] {
        self.0
    }
}

macro_rules! to_bytes {
    ($ty:ty, $self:ident, [$($field:ident),* $(,)?]) => {{
        let mut w = Writer::<{ size_of::<$ty>() }>::new();
        $( w.put(offset_of!($ty, $field), &field_bytes(&$self.$field)); )*
        w.done()
    }};
}

/// Native-endian bytes of a scalar or byte-array field.
trait FieldBytes {
    fn bytes(&self) -> Vec<u8>;
}
macro_rules! impl_field_bytes {
    ($($t:ty),*) => { $(impl FieldBytes for $t { fn bytes(&self) -> Vec<u8> { self.to_ne_bytes().to_vec() } })* };
}
impl_field_bytes!(u8, u16, u32, u64);
impl<const N: usize> FieldBytes for [u8; N] {
    fn bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}
fn field_bytes<T: FieldBytes>(v: &T) -> Vec<u8> {
    v.bytes()
}

impl Config {
    pub fn to_bytes(self) -> [u8; size_of::<Config>()] {
        to_bytes!(
            Config,
            self,
            [
                abi_version,
                flags,
                guestd_cgroup_id,
                guestd_exe_ino,
                guestd_exe_dev,
                heartbeat_interval_ms
            ]
        )
    }
}

impl GlobalModeValue {
    pub fn to_bytes(self) -> [u8; size_of::<GlobalModeValue>()] {
        to_bytes!(GlobalModeValue, self, [mode])
    }
}

impl PolicyReadyValue {
    pub fn to_bytes(self) -> [u8; size_of::<PolicyReadyValue>()] {
        to_bytes!(PolicyReadyValue, self, [generation])
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            generation: r.u64(offset_of!(Self, generation)),
        })
    }
}

impl CgroupPolicy {
    pub fn to_bytes(self) -> [u8; size_of::<CgroupPolicy>()] {
        to_bytes!(
            CgroupPolicy,
            self,
            [
                generation,
                policy_id,
                mode,
                failure,
                rootfs_type,
                flags,
                exec_default,
                net_default
            ]
        )
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            generation: r.u64(offset_of!(Self, generation)),
            policy_id: r.u32(offset_of!(Self, policy_id)),
            mode: r.u8(offset_of!(Self, mode)),
            failure: r.u8(offset_of!(Self, failure)),
            rootfs_type: r.u8(offset_of!(Self, rootfs_type)),
            flags: r.u8(offset_of!(Self, flags)),
            exec_default: r.u8(offset_of!(Self, exec_default)),
            net_default: r.u8(offset_of!(Self, net_default)),
            _pad0: 0,
            _pad1: 0,
        })
    }
}

impl ExecKey {
    pub fn to_bytes(self) -> [u8; size_of::<ExecKey>()] {
        to_bytes!(ExecKey, self, [policy_id, dev, ino])
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            policy_id: r.u32(offset_of!(Self, policy_id)),
            dev: r.u32(offset_of!(Self, dev)),
            ino: r.u64(offset_of!(Self, ino)),
        })
    }
}

impl RuleValue {
    pub fn to_bytes(self) -> [u8; size_of::<RuleValue>()] {
        to_bytes!(RuleValue, self, [verdict, rule_id])
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            verdict: r.u32(offset_of!(Self, verdict)),
            rule_id: r.u32(offset_of!(Self, rule_id)),
        })
    }
}

impl NetKeyV4 {
    pub fn to_bytes(self) -> [u8; size_of::<NetKeyV4>()] {
        to_bytes!(NetKeyV4, self, [prefixlen, policy_id, protocol, port, addr])
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            prefixlen: r.u32(offset_of!(Self, prefixlen)),
            policy_id: r.u32(offset_of!(Self, policy_id)),
            protocol: r.u8(offset_of!(Self, protocol)),
            _pad0: 0,
            port: r.array(offset_of!(Self, port)),
            addr: r.array(offset_of!(Self, addr)),
        })
    }
}

impl NetKeyV6 {
    pub fn to_bytes(self) -> [u8; size_of::<NetKeyV6>()] {
        to_bytes!(NetKeyV6, self, [prefixlen, policy_id, protocol, port, addr])
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let r = Reader::new(b, size_of::<Self>())?;
        Some(Self {
            prefixlen: r.u32(offset_of!(Self, prefixlen)),
            policy_id: r.u32(offset_of!(Self, policy_id)),
            protocol: r.u8(offset_of!(Self, protocol)),
            _pad0: 0,
            port: r.array(offset_of!(Self, port)),
            addr: r.array(offset_of!(Self, addr)),
        })
    }
}

/// Bounds-checked field reader over untrusted bytes. `new` fails unless the
/// buffer is at least `len` bytes, so later reads below `len` cannot panic.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8], len: usize) -> Option<Self> {
        (b.len() >= len).then_some(Self { b })
    }
    fn array<const N: usize>(&self, off: usize) -> [u8; N] {
        let mut a = [0u8; N];
        a.copy_from_slice(&self.b[off..off + N]);
        a
    }
    fn u8(&self, off: usize) -> u8 {
        self.b[off]
    }
    fn u16(&self, off: usize) -> u16 {
        u16::from_ne_bytes(self.array(off))
    }
    fn u32(&self, off: usize) -> u32 {
        u32::from_ne_bytes(self.array(off))
    }
    fn u64(&self, off: usize) -> u64 {
        u64::from_ne_bytes(self.array(off))
    }
}

/// A ring buffer record, validated against the ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Exec(Box<ExecEvent>),
    Connect(ConnectEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("record too short: {0} bytes")]
    Short(usize),
    #[error("abi_version {0}, expected {ABI_VERSION}")]
    AbiVersion(u16),
    #[error("record size {size} does not match type {ty} (buffer {len} bytes)")]
    Size { ty: u16, size: u16, len: usize },
    #[error("unknown event type {0}")]
    UnknownType(u16),
}

impl Record {
    /// Decodes one ring buffer sample. Never panics on malformed input.
    pub fn decode(b: &[u8]) -> Result<Record, RecordError> {
        let hdr = EventHeader::decode(b)?;
        if u32::from(hdr.abi_version) != ABI_VERSION {
            return Err(RecordError::AbiVersion(hdr.abi_version));
        }
        let want = match hdr.r#type {
            event_type::EXEC => size_of::<ExecEvent>(),
            event_type::CONNECT => size_of::<ConnectEvent>(),
            t => return Err(RecordError::UnknownType(t)),
        };
        if usize::from(hdr.size) != want || b.len() < want {
            return Err(RecordError::Size {
                ty: hdr.r#type,
                size: hdr.size,
                len: b.len(),
            });
        }
        let p = &b[size_of::<EventHeader>()..want];
        let r = Reader { b: p };
        Ok(match hdr.r#type {
            event_type::EXEC => Record::Exec(Box::new(ExecEvent {
                hdr,
                exec: ExecPayload {
                    exe_dev: r.u32(offset_of!(ExecPayload, exe_dev)),
                    argc: r.u32(offset_of!(ExecPayload, argc)),
                    exe_ino: r.u64(offset_of!(ExecPayload, exe_ino)),
                    path_len: r.u16(offset_of!(ExecPayload, path_len)),
                    argv_len: r.u16(offset_of!(ExecPayload, argv_len)),
                    _pad0: 0,
                    path: r.array(offset_of!(ExecPayload, path)),
                    argv: r.array(offset_of!(ExecPayload, argv)),
                },
            })),
            _ => Record::Connect(ConnectEvent {
                hdr,
                connect: ConnectPayload {
                    family: r.u16(offset_of!(ConnectPayload, family)),
                    protocol: r.u8(offset_of!(ConnectPayload, protocol)),
                    verdict: r.u8(offset_of!(ConnectPayload, verdict)),
                    dport: r.array(offset_of!(ConnectPayload, dport)),
                    _pad0: 0,
                    daddr: r.array(offset_of!(ConnectPayload, daddr)),
                    sock_cookie: r.u64(offset_of!(ConnectPayload, sock_cookie)),
                },
            }),
        })
    }
}

impl EventHeader {
    fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let r = Reader::new(b, size_of::<Self>()).ok_or(RecordError::Short(b.len()))?;
        Ok(Self {
            abi_version: r.u16(offset_of!(Self, abi_version)),
            r#type: r.u16(offset_of!(Self, r#type)),
            size: r.u16(offset_of!(Self, size)),
            action: r.u8(offset_of!(Self, action)),
            hook: r.u8(offset_of!(Self, hook)),
            ktime_boot_ns: r.u64(offset_of!(Self, ktime_boot_ns)),
            cgroup_id: r.u64(offset_of!(Self, cgroup_id)),
            policy_generation: r.u64(offset_of!(Self, policy_generation)),
            pid: r.u32(offset_of!(Self, pid)),
            tgid: r.u32(offset_of!(Self, tgid)),
            ppid: r.u32(offset_of!(Self, ppid)),
            uid: r.u32(offset_of!(Self, uid)),
            gid: r.u32(offset_of!(Self, gid)),
            policy_id: r.u32(offset_of!(Self, policy_id)),
            rule_id: r.u32(offset_of!(Self, rule_id)),
            flags: r.u32(offset_of!(Self, flags)),
            comm: r.array(offset_of!(Self, comm)),
            ns_tgid: r.u32(offset_of!(Self, ns_tgid)),
            _pad0: 0,
        })
    }

    #[cfg(test)]
    pub fn to_bytes(self) -> [u8; size_of::<EventHeader>()] {
        to_bytes!(
            EventHeader,
            self,
            [
                abi_version,
                r#type,
                size,
                action,
                hook,
                ktime_boot_ns,
                cgroup_id,
                policy_generation,
                pid,
                tgid,
                ppid,
                uid,
                gid,
                policy_id,
                rule_id,
                flags,
                comm,
                ns_tgid
            ]
        )
    }
}

#[cfg(test)]
impl ExecEvent {
    pub fn to_bytes(self) -> Vec<u8> {
        let p = &self.exec;
        let payload = to_bytes!(
            ExecPayload,
            p,
            [exe_dev, argc, exe_ino, path_len, argv_len, path, argv]
        );
        [self.hdr.to_bytes().as_slice(), payload.as_slice()].concat()
    }
}

#[cfg(test)]
impl ConnectEvent {
    pub fn to_bytes(self) -> Vec<u8> {
        let p = &self.connect;
        let payload = to_bytes!(
            ConnectPayload,
            p,
            [family, protocol, verdict, dport, daddr, sock_cookie]
        );
        [self.hdr.to_bytes().as_slice(), payload.as_slice()].concat()
    }
}

/// Converts a `stat(2)` st_dev to the kernel's internal s_dev encoding.
pub fn s_dev_from_st_dev(st_dev: u64) -> u32 {
    let major = rustix::fs::major(st_dev);
    let minor = rustix::fs::minor(st_dev);
    (major << 20) | (minor & 0xfffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const HEADER: &str = include_str!("../../../bpf/include/vesta_abi.h");

    fn rust_layout() -> HashMap<&'static str, (usize, HashMap<&'static str, usize>)> {
        macro_rules! layout {
            ($m:ident, $c:literal, $ty:ty, [$($cf:literal => $rf:ident),*]) => {
                $m.insert($c, (size_of::<$ty>(), HashMap::from([$(($cf, offset_of!($ty, $rf))),*])));
            };
        }
        let mut m = HashMap::new();
        layout!(m, "vesta_event_header", EventHeader,
            ["ktime_boot_ns" => ktime_boot_ns, "pid" => pid, "comm" => comm, "ns_tgid" => ns_tgid]);
        layout!(m, "vesta_exec_payload", ExecPayload, ["path" => path, "argv" => argv]);
        layout!(m, "vesta_exec_event", ExecEvent, []);
        layout!(m, "vesta_connect_payload", ConnectPayload, ["daddr" => daddr, "sock_cookie" => sock_cookie]);
        layout!(m, "vesta_connect_event", ConnectEvent, []);
        layout!(m, "vesta_config", Config, []);
        layout!(m, "vesta_global_mode_value", GlobalModeValue, []);
        layout!(m, "vesta_policy_ready_value", PolicyReadyValue, []);
        layout!(m, "vesta_cgroup_policy", CgroupPolicy, ["exec_default" => exec_default]);
        layout!(m, "vesta_exec_key", ExecKey, []);
        layout!(m, "vesta_rule_value", RuleValue, []);
        layout!(m, "vesta_net_key_v4", NetKeyV4, ["addr" => addr]);
        layout!(m, "vesta_net_key_v6", NetKeyV6, ["addr" => addr]);
        m
    }

    /// Every size/offset pinned in the C header matches the Rust mirror.
    #[test]
    fn layout_matches_c_header() {
        let layout = rust_layout();
        let mut checked = 0;
        for line in HEADER
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("_Static_assert("))
        {
            let expr = &line["_Static_assert(".len()..];
            let Some((lhs, rest)) = expr.split_once("==") else {
                continue;
            };
            let Ok(want) = rest
                .trim()
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .parse::<usize>()
            else {
                continue;
            };
            let lhs = lhs.trim();
            if let Some(s) = lhs
                .strip_prefix("sizeof(struct ")
                .and_then(|s| s.strip_suffix(')'))
            {
                let (size, _) = layout
                    .get(s)
                    .unwrap_or_else(|| panic!("no Rust mirror for {s}"));
                assert_eq!(*size, want, "sizeof {s}");
                checked += 1;
            } else if let Some(s) = lhs
                .strip_prefix("offsetof(struct ")
                .and_then(|s| s.strip_suffix(')'))
            {
                let (st, field) = s.split_once(',').expect("offsetof args");
                let (_, fields) = layout
                    .get(st.trim())
                    .unwrap_or_else(|| panic!("no Rust mirror for {st}"));
                let off = fields
                    .get(field.trim())
                    .unwrap_or_else(|| panic!("offset {st}.{field} not mirrored"));
                assert_eq!(*off, want, "offsetof {st}.{field}");
                checked += 1;
            }
        }
        assert!(
            checked >= 24,
            "only {checked} asserts parsed from the header"
        );
    }

    fn c_defines() -> HashMap<String, u64> {
        let mut m = HashMap::new();
        for line in HEADER.lines().map(str::trim) {
            let (name, val) = if let Some(rest) = line.strip_prefix("#define ") {
                match rest.split_once(char::is_whitespace) {
                    Some((n, v)) => (n, v),
                    None => continue,
                }
            } else if line.starts_with("VESTA_") {
                match line.split_once('=') {
                    Some((n, v)) => (n.trim(), v),
                    None => continue,
                }
            } else {
                continue;
            };
            let v = val
                .split("/*")
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches(',');
            let v = v.trim_start_matches('(').trim_end_matches(')').trim();
            let parsed = match v.split_once("U << ") {
                Some((base, shift)) => base
                    .parse::<u64>()
                    .ok()
                    .zip(shift.parse::<u32>().ok())
                    .map(|(b, s)| b << s),
                None => v.parse::<u64>().ok(),
            };
            if let Some(p) = parsed {
                m.insert(name.to_string(), p);
            }
        }
        m
    }

    #[test]
    fn constants_match_c_header() {
        let d = c_defines();
        let want: &[(&str, u64)] = &[
            ("VESTA_ABI_VERSION", u64::from(ABI_VERSION)),
            ("VESTA_COMM_LEN", COMM_LEN as u64),
            ("VESTA_PATH_MAX", PATH_MAX as u64),
            ("VESTA_ARGV_MAX", ARGV_MAX as u64),
            ("VESTA_MAX_CGROUPS", MAX_CGROUPS as u64),
            ("VESTA_MAX_EXEC_RULES", MAX_EXEC_RULES as u64),
            ("VESTA_MAX_NET_RULES", MAX_NET_RULES as u64),
            ("VESTA_MAX_POLICIES", u64::from(MAX_POLICIES)),
            (
                "VESTA_RINGBUF_DEFAULT_BYTES",
                u64::from(RINGBUF_DEFAULT_BYTES),
            ),
            ("VESTA_NET_KEY_FIXED_BITS", u64::from(NET_KEY_FIXED_BITS)),
            ("VESTA_EVENT_EXEC", u64::from(event_type::EXEC)),
            ("VESTA_EVENT_CONNECT", u64::from(event_type::CONNECT)),
            ("VESTA_EVENT_TYPE_MAX", u64::from(event_type::MAX)),
            ("VESTA_ACTION_AUDITED", u64::from(action::AUDITED)),
            ("VESTA_ACTION_DENIED", u64::from(action::DENIED)),
            ("VESTA_ACTION_ALLOWED", u64::from(action::ALLOWED)),
            (
                "VESTA_HOOK_SCHED_PROCESS_EXEC",
                u64::from(hook::SCHED_PROCESS_EXEC),
            ),
            (
                "VESTA_HOOK_BPRM_CHECK_SECURITY",
                u64::from(hook::BPRM_CHECK_SECURITY),
            ),
            (
                "VESTA_HOOK_CGROUP_CONNECT4",
                u64::from(hook::CGROUP_CONNECT4),
            ),
            (
                "VESTA_HOOK_CGROUP_CONNECT6",
                u64::from(hook::CGROUP_CONNECT6),
            ),
            ("VESTA_MODE_ENFORCE", u64::from(mode::ENFORCE)),
            ("VESTA_FAILURE_CLOSED", u64::from(failure::CLOSED)),
            (
                "VESTA_GLOBAL_AUDIT_ONLY",
                u64::from(global_mode::AUDIT_ONLY),
            ),
            ("VESTA_GLOBAL_DETACHED", u64::from(global_mode::DETACHED)),
            ("VESTA_VERDICT_ALLOW", u64::from(verdict::ALLOW)),
            ("VESTA_VERDICT_DENY", u64::from(verdict::DENY)),
            ("VESTA_EVF_PATH_TRUNCATED", u64::from(evf::PATH_TRUNCATED)),
            ("VESTA_EVF_ARGV_TRUNCATED", u64::from(evf::ARGV_TRUNCATED)),
            ("VESTA_EVF_CGROUP_UNBOUND", u64::from(evf::CGROUP_UNBOUND)),
            ("VESTA_EVF_POLICY_PENDING", u64::from(evf::POLICY_PENDING)),
            ("VESTA_EVF_WOULD_DENY", u64::from(evf::WOULD_DENY)),
            (
                "VESTA_EVF_GLOBAL_AUDIT_ONLY",
                u64::from(evf::GLOBAL_AUDIT_ONLY),
            ),
            ("VESTA_EVF_EXE_UNLINKED", u64::from(evf::EXE_UNLINKED)),
            (
                "VESTA_EVF_EXE_OUTSIDE_ROOT",
                u64::from(evf::EXE_OUTSIDE_ROOT),
            ),
            ("VESTA_CGF_PENDING", u64::from(CGF_PENDING)),
            ("VESTA_CFG_EXEC_ARGV", u64::from(CFG_EXEC_ARGV)),
        ];
        for (name, v) in want {
            assert_eq!(d.get(*name), Some(v), "{name}");
        }
    }

    fn sample_exec() -> ExecEvent {
        let mut path = [0u8; PATH_MAX];
        path[..9].copy_from_slice(b"/bin/true");
        let mut argv = [0u8; ARGV_MAX];
        argv[..8].copy_from_slice(b"true\0-x\0");
        let mut comm = [0u8; COMM_LEN];
        comm[..4].copy_from_slice(b"true");
        ExecEvent {
            hdr: EventHeader {
                abi_version: 1,
                r#type: event_type::EXEC,
                size: size_of::<ExecEvent>() as u16,
                action: action::AUDITED,
                hook: hook::SCHED_PROCESS_EXEC,
                ktime_boot_ns: 42,
                cgroup_id: 7,
                pid: 100,
                tgid: 100,
                comm,
                ..Default::default()
            },
            exec: ExecPayload {
                exe_dev: 3,
                argc: 2,
                exe_ino: 99,
                path_len: 9,
                argv_len: 8,
                _pad0: 0,
                path,
                argv,
            },
        }
    }

    #[test]
    fn record_roundtrip() {
        let ev = sample_exec();
        assert_eq!(
            Record::decode(&ev.to_bytes()),
            Ok(Record::Exec(Box::new(ev)))
        );
        let c = ConnectEvent {
            hdr: EventHeader {
                abi_version: 1,
                r#type: event_type::CONNECT,
                size: 120,
                ..Default::default()
            },
            connect: ConnectPayload {
                family: AF_INET,
                protocol: 6,
                dport: 443u16.to_be_bytes(),
                ..Default::default()
            },
        };
        assert_eq!(Record::decode(&c.to_bytes()), Ok(Record::Connect(c)));
    }

    #[test]
    fn record_rejects_malformed() {
        let good = sample_exec().to_bytes();
        assert_eq!(Record::decode(&good[..10]), Err(RecordError::Short(10)));
        assert!(matches!(
            Record::decode(&good[..200]),
            Err(RecordError::Size { .. })
        ));
        let mut bad = good.clone();
        bad[0] = 9;
        assert_eq!(Record::decode(&bad), Err(RecordError::AbiVersion(9)));
        let mut bad = good.clone();
        bad[2..4].copy_from_slice(&77u16.to_ne_bytes());
        assert_eq!(Record::decode(&bad), Err(RecordError::UnknownType(77)));
        let mut bad = good;
        bad[4..6].copy_from_slice(&120u16.to_ne_bytes());
        assert!(matches!(
            Record::decode(&bad),
            Err(RecordError::Size { .. })
        ));
    }

    #[test]
    fn record_decode_random_bytes_never_panics() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for i in 0..20_000usize {
            let len = i % 1500;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf.push(x as u8);
            }
            if len >= 6 && i % 3 == 0 {
                // Make some inputs pass the header checks to reach payload decoding.
                buf[0..2].copy_from_slice(&1u16.to_ne_bytes());
                let (ty, sz) = if i % 2 == 0 {
                    (1u16, 1392u16)
                } else {
                    (2, 120)
                };
                buf[2..4].copy_from_slice(&ty.to_ne_bytes());
                buf[4..6].copy_from_slice(&sz.to_ne_bytes());
            }
            let _ = Record::decode(&buf);
        }
    }

    #[test]
    fn keys_encode_with_zero_padding() {
        let k = NetKeyV4 {
            prefixlen: 64 + 24,
            policy_id: 5,
            protocol: 6,
            _pad0: 0xff,
            port: 443u16.to_be_bytes(),
            addr: [10, 0, 0, 0],
        };
        let b = k.to_bytes();
        assert_eq!(
            b[9], 0,
            "padding must be zero even if the struct field is not"
        );
        assert_eq!(&b[10..12], &[0x01, 0xbb]);
        assert_eq!(NetKeyV4::from_bytes(&b), Some(NetKeyV4 { _pad0: 0, ..k }));
        let cg = CgroupPolicy {
            generation: 3,
            policy_id: 9,
            mode: 1,
            flags: CGF_PENDING,
            _pad0: 7,
            ..Default::default()
        };
        assert_eq!(
            CgroupPolicy::from_bytes(&cg.to_bytes()),
            Some(CgroupPolicy { _pad0: 0, ..cg })
        );
    }

    #[test]
    fn s_dev_encoding() {
        // st_dev for 8:1 is makedev(8, 1); s_dev is (8 << 20) | 1.
        assert_eq!(s_dev_from_st_dev(rustix::fs::makedev(8, 1)), (8 << 20) | 1);
        assert_eq!(s_dev_from_st_dev(rustix::fs::makedev(0, 0x2f)), 0x2f);
    }
}
