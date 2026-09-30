// SPDX-License-Identifier: Apache-2.0
//! ApplyPolicy validation and translation to map entries (control.proto,
//! docs/abi.md). Everything here is pure: no syscalls, no map writes.
//!
//! Exec rule paths are kept as paths; they are resolved to (dev, ino) per
//! bound container, inside that container's rootfs (see `resolve`), because
//! the same path names a different file in every container image.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use prost::Message;
use sha2::{Digest, Sha256};

use crate::abi::{self, NetKeyV4, NetKeyV6, RuleValue};
use crate::proto::channel::{self as pb, ErrorCode};

pub const MAX_BUNDLES: usize = 256;
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_EXEC_RULES_PER_BUNDLE: usize = 4096;
pub const MAX_NET_RULES_PER_BUNDLE: usize = 1024;
pub const MAX_PORTS: usize = 64;
pub const MAX_PATH_LEN: usize = 4096;
pub const SCHEMA_VERSION: u32 = 1;

/// A request rejected before any state changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Rejection {
    pub code: ErrorCode,
    pub message: String,
}

impl Rejection {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
            message: message.into(),
        }
    }
    pub fn limit(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::LimitExceeded,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRuleSpec {
    pub rule_id: u32,
    pub path: String,
    pub verdict: u8,
}

/// One validated PolicyBundle, with enums already mapped to ABI values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub policy_id: u32,
    pub name: String,
    pub mode: u8,
    pub failure: u8,
    pub exec_default: u8,
    pub net_default: u8,
    pub exec_rules: Vec<ExecRuleSpec>,
}

/// A validated ApplyPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub generation: u64,
    pub bundles: BTreeMap<u32, Bundle>,
    pub net4: BTreeMap<NetKeyV4, RuleValue>,
    pub net6: BTreeMap<NetKeyV6, RuleValue>,
    /// SHA-256 over the canonical set (see `policy_hash`).
    pub hash: [u8; 32],
    pub warnings: Vec<String>,
}

/// Maps the proto Mode to the ABI value (UNSPECIFIED = audit).
pub fn mode_from_proto(v: i32) -> Result<u8, Rejection> {
    match pb::Mode::try_from(v) {
        Ok(pb::Mode::Unspecified | pb::Mode::Audit) => Ok(abi::mode::AUDIT),
        Ok(pb::Mode::Enforce) => Ok(abi::mode::ENFORCE),
        Err(_) => Err(Rejection::invalid(format!("unknown mode {v}"))),
    }
}

pub fn failure_from_proto(v: i32) -> Result<u8, Rejection> {
    match pb::FailurePolicy::try_from(v) {
        Ok(pb::FailurePolicy::Unspecified | pb::FailurePolicy::Open) => Ok(abi::failure::OPEN),
        Ok(pb::FailurePolicy::Closed) => Ok(abi::failure::CLOSED),
        Err(_) => Err(Rejection::invalid(format!("unknown failure policy {v}"))),
    }
}

pub fn global_mode_from_proto(v: i32) -> Result<u32, Rejection> {
    match pb::GlobalMode::try_from(v) {
        Ok(pb::GlobalMode::Unspecified | pb::GlobalMode::Normal) => Ok(abi::global_mode::NORMAL),
        Ok(pb::GlobalMode::AuditOnly) => Ok(abi::global_mode::AUDIT_ONLY),
        Ok(pb::GlobalMode::Detached) => Ok(abi::global_mode::DETACHED),
        Err(_) => Err(Rejection::invalid(format!("unknown global mode {v}"))),
    }
}

pub fn global_mode_to_proto(v: u32) -> pb::GlobalMode {
    match v {
        abi::global_mode::AUDIT_ONLY => pb::GlobalMode::AuditOnly,
        abi::global_mode::DETACHED => pb::GlobalMode::Detached,
        _ => pb::GlobalMode::Normal,
    }
}

/// Default verdicts: UNSPECIFIED means allow (ABI NONE).
fn default_verdict(v: i32) -> Result<u8, Rejection> {
    match pb::Verdict::try_from(v) {
        Ok(pb::Verdict::Unspecified) => Ok(abi::verdict::NONE),
        Ok(pb::Verdict::Allow) => Ok(abi::verdict::ALLOW),
        Ok(pb::Verdict::Deny) => Ok(abi::verdict::DENY),
        Err(_) => Err(Rejection::invalid(format!("unknown verdict {v}"))),
    }
}

/// Rule verdicts must be explicit.
fn rule_verdict(v: i32, what: &str) -> Result<u8, Rejection> {
    match pb::Verdict::try_from(v) {
        Ok(pb::Verdict::Allow) => Ok(abi::verdict::ALLOW),
        Ok(pb::Verdict::Deny) => Ok(abi::verdict::DENY),
        _ => Err(Rejection::invalid(format!(
            "{what}: verdict must be ALLOW or DENY"
        ))),
    }
}

/// Validates an absolute path without `..`/NUL, as sent in ExecRule.path.
pub fn validate_exec_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(format!(
            "path length {} outside 1..={MAX_PATH_LEN}",
            path.len()
        ));
    }
    if !path.starts_with('/') {
        return Err("path must be absolute".into());
    }
    if path.contains('\0') {
        return Err("path contains NUL".into());
    }
    if path.split('/').any(|c| c == "..") {
        return Err("path contains '..'".into());
    }
    Ok(())
}

/// Parses "addr/len" and requires the host bits to be zero.
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| format!("{s:?}: missing prefix length"))?;
    let addr: IpAddr = addr.parse().map_err(|_| format!("{s:?}: bad address"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| format!("{s:?}: bad prefix length"))?;
    let (bits, max) = match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)) << 96, 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    if len > max {
        return Err(format!("{s:?}: prefix length > {max}"));
    }
    let host_mask = if len == 0 {
        u128::MAX
    } else {
        u128::MAX >> len
    };
    if bits & host_mask != 0 {
        return Err(format!("{s:?}: host bits set (not canonical)"));
    }
    Ok((addr, len))
}

/// Inserts a rule key, resolving duplicates: DENY wins, then the lowest rule_id.
pub fn insert_rule<K: Ord>(map: &mut BTreeMap<K, RuleValue>, key: K, value: RuleValue) -> bool {
    match map.get_mut(&key) {
        None => {
            map.insert(key, value);
            false
        }
        Some(cur) => {
            let better = (value.verdict == u32::from(abi::verdict::DENY)
                && cur.verdict != value.verdict)
                || (value.verdict == cur.verdict && value.rule_id < cur.rule_id);
            if better {
                *cur = value;
            }
            true
        }
    }
}

/// Validates and compiles an ApplyPolicy. `enforce_supported` is false when
/// the guest cannot enforce (bpf LSM inactive); ENFORCE bundles are then refused.
pub fn compile(
    req: &pb::ApplyPolicy,
    enforce_supported: bool,
) -> Result<CompiledPolicy, Rejection> {
    if req.generation == 0 {
        return Err(Rejection::invalid("generation must be > 0"));
    }
    if req.bundles.len() > MAX_BUNDLES {
        return Err(Rejection::limit(format!(
            "{} bundles > {MAX_BUNDLES}",
            req.bundles.len()
        )));
    }
    let mut bundles = BTreeMap::new();
    let mut net4 = BTreeMap::new();
    let mut net6 = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut exec_total = 0usize;

    for b in &req.bundles {
        let pid = b.policy_id;
        if pid == 0 || pid > abi::MAX_POLICIES {
            return Err(Rejection::invalid(format!(
                "policy_id {pid} outside 1..={}",
                abi::MAX_POLICIES
            )));
        }
        if bundles.contains_key(&pid) {
            return Err(Rejection::invalid(format!("duplicate policy_id {pid}")));
        }
        let ctx = format!("policy {pid}");
        if b.name.len() > MAX_NAME_LEN {
            return Err(Rejection::invalid(format!(
                "{ctx}: name longer than {MAX_NAME_LEN} bytes"
            )));
        }
        if b.schema_version != SCHEMA_VERSION {
            return Err(Rejection::invalid(format!(
                "{ctx}: schema_version {} (want {SCHEMA_VERSION})",
                b.schema_version
            )));
        }
        let mode = mode_from_proto(b.mode)?;
        if mode == abi::mode::ENFORCE && !enforce_supported {
            return Err(Rejection::invalid(format!(
                "{ctx}: MODE_ENFORCE requested but the guest cannot enforce (bpf LSM not active)"
            )));
        }
        let failure = failure_from_proto(b.failure)?;

        let exec = b.exec.clone().unwrap_or_default();
        if exec.rules.len() > MAX_EXEC_RULES_PER_BUNDLE {
            return Err(Rejection::limit(format!(
                "{ctx}: {} exec rules > {MAX_EXEC_RULES_PER_BUNDLE}",
                exec.rules.len()
            )));
        }
        exec_total += exec.rules.len();
        let mut exec_rules = Vec::with_capacity(exec.rules.len());
        for r in &exec.rules {
            if r.rule_id == 0 {
                return Err(Rejection::invalid(format!(
                    "{ctx}: exec rule_id must be > 0"
                )));
            }
            validate_exec_path(&r.path)
                .map_err(|e| Rejection::invalid(format!("{ctx}: exec rule {}: {e}", r.rule_id)))?;
            let verdict = rule_verdict(r.verdict, &format!("{ctx}: exec rule {}", r.rule_id))?;
            exec_rules.push(ExecRuleSpec {
                rule_id: r.rule_id,
                path: r.path.clone(),
                verdict,
            });
        }

        let net = b.net.clone().unwrap_or_default();
        if net.egress.len() > MAX_NET_RULES_PER_BUNDLE {
            return Err(Rejection::limit(format!(
                "{ctx}: {} net rules > {MAX_NET_RULES_PER_BUNDLE}",
                net.egress.len()
            )));
        }
        for r in &net.egress {
            let rctx = format!("{ctx}: net rule {}", r.rule_id);
            if r.rule_id == 0 {
                return Err(Rejection::invalid(format!(
                    "{ctx}: net rule_id must be > 0"
                )));
            }
            let (addr, len) =
                parse_cidr(&r.cidr).map_err(|e| Rejection::invalid(format!("{rctx}: {e}")))?;
            let protocol = match pb::Protocol::try_from(r.protocol) {
                Ok(p) => p as i32 as u8,
                Err(_) => {
                    return Err(Rejection::invalid(format!(
                        "{rctx}: unknown protocol {}",
                        r.protocol
                    )))
                }
            };
            if r.ports.len() > MAX_PORTS {
                return Err(Rejection::limit(format!(
                    "{rctx}: {} ports > {MAX_PORTS}",
                    r.ports.len()
                )));
            }
            let mut ports = BTreeSet::new();
            for &p in &r.ports {
                let p = u16::try_from(p).ok().filter(|p| *p != 0).ok_or_else(|| {
                    Rejection::invalid(format!("{rctx}: port {p} outside 1..=65535"))
                })?;
                ports.insert(p);
            }
            if ports.is_empty() {
                ports.insert(0);
            }
            let value = RuleValue {
                verdict: u32::from(rule_verdict(r.verdict, &rctx)?),
                rule_id: r.rule_id,
            };
            let prefixlen = abi::NET_KEY_FIXED_BITS + u32::from(len);
            for port in ports {
                let port = port.to_be_bytes();
                let dup = match addr {
                    IpAddr::V4(a) => insert_rule(
                        &mut net4,
                        NetKeyV4 {
                            prefixlen,
                            policy_id: pid,
                            protocol,
                            _pad0: 0,
                            port,
                            addr: a.octets(),
                        },
                        value,
                    ),
                    IpAddr::V6(a) => insert_rule(
                        &mut net6,
                        NetKeyV6 {
                            prefixlen,
                            policy_id: pid,
                            protocol,
                            _pad0: 0,
                            port,
                            addr: a.octets(),
                        },
                        value,
                    ),
                };
                if dup {
                    warnings.push(format!(
                        "{rctx}: overlaps an earlier rule for the same key; deny wins"
                    ));
                }
            }
        }
        bundles.insert(
            pid,
            Bundle {
                policy_id: pid,
                name: b.name.clone(),
                mode,
                failure,
                exec_default: default_verdict(exec.default_verdict)?,
                net_default: default_verdict(net.default_egress)?,
                exec_rules,
            },
        );
    }
    if exec_total > abi::MAX_EXEC_RULES {
        return Err(Rejection::limit(format!(
            "{exec_total} exec rules > {}",
            abi::MAX_EXEC_RULES
        )));
    }
    if net4.len() > abi::MAX_NET_RULES || net6.len() > abi::MAX_NET_RULES {
        return Err(Rejection::limit(format!(
            "net rule keys (v4 {}, v6 {}) exceed {} per family",
            net4.len(),
            net6.len(),
            abi::MAX_NET_RULES
        )));
    }
    Ok(CompiledPolicy {
        generation: req.generation,
        bundles,
        net4,
        net6,
        hash: policy_hash(req),
        warnings,
    })
}

/// SHA-256 of the canonical applied set: the protobuf encoding of
/// `ApplyPolicy{generation: 0, bundles}` with bundles sorted by policy_id and
/// everything else as sent. The host computes the same over what it sent.
pub fn policy_hash(req: &pb::ApplyPolicy) -> [u8; 32] {
    let mut bundles = req.bundles.clone();
    bundles.sort_by_key(|b| b.policy_id);
    let canonical = pb::ApplyPolicy {
        generation: 0,
        bundles,
    };
    Sha256::digest(canonical.encode_to_vec()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn bundle(id: u32) -> pb::PolicyBundle {
        pb::PolicyBundle {
            policy_id: id,
            name: format!("ns/p{id}"),
            mode: pb::Mode::Audit as i32,
            failure: pb::FailurePolicy::Open as i32,
            exec: Some(pb::ExecRules {
                default_verdict: pb::Verdict::Allow as i32,
                rules: vec![pb::ExecRule {
                    rule_id: 1,
                    path: "/usr/bin/curl".into(),
                    verdict: pb::Verdict::Deny as i32,
                }],
            }),
            net: Some(pb::NetRules {
                default_egress: pb::Verdict::Unspecified as i32,
                egress: vec![pb::NetRule {
                    rule_id: 2,
                    cidr: "10.0.0.0/8".into(),
                    ports: vec![443, 80],
                    protocol: pb::Protocol::Tcp as i32,
                    verdict: pb::Verdict::Deny as i32,
                }],
            }),
            schema_version: 1,
        }
    }

    fn apply(generation: u64, bundles: Vec<pb::PolicyBundle>) -> pb::ApplyPolicy {
        pb::ApplyPolicy {
            generation,
            bundles,
        }
    }

    #[test]
    fn compiles_net_keys_per_port() {
        let c = compile(&apply(1, vec![bundle(5)]), true).unwrap();
        assert_eq!(c.net4.len(), 2);
        let k = c.net4.keys().next().unwrap();
        assert_eq!(k.prefixlen, 64 + 8);
        assert_eq!(k.policy_id, 5);
        assert_eq!(k.protocol, 6);
        assert_eq!(k.addr, [10, 0, 0, 0]);
        let ports: BTreeSet<u16> = c.net4.keys().map(|k| u16::from_be_bytes(k.port)).collect();
        assert_eq!(ports, BTreeSet::from([80, 443]));
        let b = &c.bundles[&5];
        assert_eq!(
            (b.mode, b.failure, b.exec_default, b.net_default),
            (0, 0, 1, 0)
        );
        assert_eq!(b.exec_rules[0].verdict, abi::verdict::DENY);
    }

    #[test]
    fn empty_ports_means_any_and_v6() {
        let mut b = bundle(1);
        let net = b.net.as_mut().unwrap();
        net.egress[0].ports.clear();
        net.egress[0].cidr = "2001:db8::/32".into();
        net.egress[0].protocol = pb::Protocol::Any as i32;
        let c = compile(&apply(1, vec![b]), true).unwrap();
        assert!(c.net4.is_empty());
        let k = c.net6.keys().next().unwrap();
        assert_eq!((k.prefixlen, k.protocol, k.port), (64 + 32, 0, [0, 0]));
    }

    #[test]
    fn rejections() {
        let cases: Vec<(pb::ApplyPolicy, ErrorCode)> = vec![
            (apply(0, vec![]), ErrorCode::InvalidArgument),
            (apply(1, vec![bundle(0)]), ErrorCode::InvalidArgument),
            (apply(1, vec![bundle(1025)]), ErrorCode::InvalidArgument),
            (
                apply(1, vec![bundle(1), bundle(1)]),
                ErrorCode::InvalidArgument,
            ),
            (
                apply(1, (1..=257).map(bundle).collect()),
                ErrorCode::LimitExceeded,
            ),
        ];
        for (req, code) in cases {
            assert_eq!(compile(&req, true).unwrap_err().code, code);
        }
        let mut b = bundle(1);
        b.schema_version = 2;
        assert!(compile(&apply(1, vec![b]), true).is_err());
        let mut b = bundle(1);
        b.mode = 99;
        assert!(compile(&apply(1, vec![b]), true).is_err());
        let mut b = bundle(1);
        b.mode = pb::Mode::Enforce as i32;
        assert!(compile(&apply(1, vec![b.clone()]), false).is_err());
        assert!(compile(&apply(1, vec![b]), true).is_ok());
    }

    #[test]
    fn rejects_bad_exec_rules() {
        for path in ["relative", "/a/../b", "/a\0b", ""] {
            let mut b = bundle(1);
            b.exec.as_mut().unwrap().rules[0].path = path.into();
            assert!(compile(&apply(1, vec![b]), true).is_err(), "{path:?}");
        }
        let mut b = bundle(1);
        b.exec.as_mut().unwrap().rules[0].verdict = pb::Verdict::Unspecified as i32;
        assert!(compile(&apply(1, vec![b]), true).is_err());
        let mut b = bundle(1);
        b.exec.as_mut().unwrap().rules[0].rule_id = 0;
        assert!(compile(&apply(1, vec![b]), true).is_err());
    }

    #[test]
    fn rejects_bad_net_rules() {
        type Mutation = Box<dyn Fn(&mut pb::NetRule)>;
        let mut bad: Vec<Mutation> = vec![
            Box::new(|r| r.cidr = "10.0.0.1/8".into()),
            Box::new(|r| r.cidr = "10.0.0.0".into()),
            Box::new(|r| r.cidr = "10.0.0.0/33".into()),
            Box::new(|r| r.cidr = "nope/8".into()),
            Box::new(|r| r.ports = vec![0]),
            Box::new(|r| r.ports = vec![65536]),
            Box::new(|r| r.ports = (1..=65).collect()),
            Box::new(|r| r.protocol = 1),
            Box::new(|r| r.verdict = 0),
        ];
        for (i, f) in bad.iter_mut().enumerate() {
            let mut b = bundle(1);
            f(&mut b.net.as_mut().unwrap().egress[0]);
            assert!(compile(&apply(1, vec![b]), true).is_err(), "case {i}");
        }
    }

    #[test]
    fn duplicate_keys_deny_wins() {
        let mut b = bundle(1);
        let net = b.net.as_mut().unwrap();
        let mut allow = net.egress[0].clone();
        allow.rule_id = 1;
        allow.verdict = pb::Verdict::Allow as i32;
        net.egress.insert(0, allow);
        let c = compile(&apply(1, vec![b]), true).unwrap();
        assert!(c
            .net4
            .values()
            .all(|v| v.verdict == u32::from(abi::verdict::DENY) && v.rule_id == 2));
        assert!(!c.warnings.is_empty());
    }

    #[test]
    fn cidr_parsing() {
        assert!(parse_cidr("0.0.0.0/0").is_ok());
        assert!(parse_cidr("::/0").is_ok());
        assert!(parse_cidr("192.168.1.1/32").is_ok());
        assert!(parse_cidr("2001:db8::1/64").is_err());
        assert!(parse_cidr("1.2.3.4/-1").is_err());
    }

    #[test]
    fn hash_is_order_independent_and_generation_free() {
        let a = compile(&apply(1, vec![bundle(1), bundle(2)]), true).unwrap();
        let b = compile(&apply(9, vec![bundle(2), bundle(1)]), true).unwrap();
        assert_eq!(a.hash, b.hash);
        let c = compile(&apply(1, vec![bundle(1)]), true).unwrap();
        assert_ne!(a.hash, c.hash);
    }

    #[test]
    fn enum_mappings() {
        assert_eq!(global_mode_from_proto(0), Ok(abi::global_mode::NORMAL));
        assert_eq!(global_mode_from_proto(3), Ok(abi::global_mode::DETACHED));
        assert!(global_mode_from_proto(4).is_err());
        assert_eq!(
            global_mode_to_proto(abi::global_mode::AUDIT_ONLY),
            pb::GlobalMode::AuditOnly
        );
        assert_eq!(failure_from_proto(2), Ok(abi::failure::CLOSED));
    }
}
