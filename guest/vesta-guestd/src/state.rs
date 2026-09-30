// SPDX-License-Identifier: Apache-2.0
//! Policy engine: applied policy, container bindings, and the map state they
//! imply. Every change recomputes the desired map contents and diffs them
//! against what is installed, writing new/changed rules before cgroup
//! entries and deleting stale cgroup entries before their rules.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{bail, Context};

use crate::abi::{self, CgroupPolicy, ExecKey, NetKeyV4, NetKeyV6, RuleValue};
use crate::cgroup::{guest_cgroup_path, pod_cgroup_path, validate_container_id};
use crate::policy::{self, CompiledPolicy, Rejection};
use crate::proto::channel::{self as pb, ErrorCode};
use crate::resolve::{ExecResolver, FileId};

/// Ack.warnings limits (control.proto).
pub const MAX_WARNINGS: usize = 64;
pub const MAX_WARNING_LEN: usize = 256;

/// Writes to the policy maps. Implemented over the pinned BPF maps and by a
/// fake in tests. Deleting a missing key must succeed.
pub trait PolicyMaps {
    fn put_cgroup(&mut self, id: u64, v: &CgroupPolicy) -> anyhow::Result<()>;
    fn del_cgroup(&mut self, id: u64) -> anyhow::Result<()>;
    fn put_exec(&mut self, k: &ExecKey, v: &RuleValue) -> anyhow::Result<()>;
    fn del_exec(&mut self, k: &ExecKey) -> anyhow::Result<()>;
    fn put_net4(&mut self, k: &NetKeyV4, v: &RuleValue) -> anyhow::Result<()>;
    fn del_net4(&mut self, k: &NetKeyV4) -> anyhow::Result<()>;
    fn put_net6(&mut self, k: &NetKeyV6, v: &RuleValue) -> anyhow::Result<()>;
    fn del_net6(&mut self, k: &NetKeyV6) -> anyhow::Result<()>;
    fn set_policy_ready(&mut self, generation: u64) -> anyhow::Result<()>;
    fn set_global_mode(&mut self, mode: u32) -> anyhow::Result<()>;
}

/// Map contents as last written (or as found at startup).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MapState {
    pub cgroups: HashMap<u64, CgroupPolicy>,
    pub exec: HashMap<ExecKey, RuleValue>,
    pub net4: HashMap<NetKeyV4, RuleValue>,
    pub net6: HashMap<NetKeyV6, RuleValue>,
}

/// Mode/failure used for bindings whose policy generation is not applied yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Baseline {
    pub mode: u8,
    pub failure: u8,
}

#[derive(Debug, Clone)]
struct Resolved {
    policy_generation: u64,
    ids: Vec<(FileId, RuleValue)>,
}

#[derive(Debug, Clone)]
struct Binding {
    cgroup_id: Option<u64>,
    policy_id: u32,
    /// Generation from BindContainer; 0 = whatever is applied.
    generation: u64,
    rootfs_type: u8,
    epoch: u64,
    resolved: Option<Resolved>,
    /// A re-bind of a live binding, waiting for its cgroup. The live fields
    /// stay in force until it completes, so a re-bind never opens a gap.
    next: Option<Rebind>,
}

#[derive(Debug, Clone, Copy)]
struct Rebind {
    policy_id: u32,
    generation: u64,
    rootfs_type: u8,
    epoch: u64,
}

/// Handle for a bind whose cgroup is still being waited for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindTicket {
    pub container_id: String,
    pub cgroup_path: PathBuf,
    epoch: u64,
}

/// Pending entry on the pod-level cgroup for container cgroups that are not
/// bound (control.proto SetSandboxDefault).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDefault {
    pub path: PathBuf,
    pub cgroup_id: u64,
    pub mode: u8,
    pub failure: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    pub generation: u64,
    pub warnings: Vec<String>,
}

/// Failure after validation: the request was valid but could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Rejected(#[from] Rejection),
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

#[derive(Debug)]
pub struct Engine<M> {
    maps: M,
    resolver: Box<dyn ExecResolver>,
    baseline: Baseline,
    enforce_supported: bool,
    /// Latest ApplyPolicy that validated; `applied_generation` says whether it is in force.
    target: Option<CompiledPolicy>,
    applied_generation: u64,
    applied_hash: Vec<u8>,
    global_mode: u32,
    bindings: BTreeMap<String, Binding>,
    /// cgroup_policy entries found at startup that no binding owns yet.
    orphans: HashMap<u64, CgroupPolicy>,
    /// Rule entries found at startup. They stay installed for as long as an
    /// orphan still references their policy_id.
    adopted: MapState,
    /// policy_ready found at startup. ApplyPolicy below it is rejected until
    /// a generation is applied, so generations never go backwards in a boot.
    adopted_generation: u64,
    /// Relative cgroup paths a bind must not cover (guestd, kata-agent).
    protected_cgroups: Vec<PathBuf>,
    sandbox_default: Option<SandboxDefault>,
    installed: MapState,
    next_epoch: u64,
}

impl std::fmt::Debug for dyn ExecResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExecResolver")
    }
}

fn push_warning(w: &mut Vec<String>, msg: String) {
    if w.len() < MAX_WARNINGS {
        let mut msg = msg;
        if msg.len() > MAX_WARNING_LEN {
            let mut cut = MAX_WARNING_LEN;
            while !msg.is_char_boundary(cut) {
                cut -= 1;
            }
            msg.truncate(cut);
        }
        w.push(msg);
    }
}

impl<M: PolicyMaps> Engine<M> {
    pub fn new(
        maps: M,
        resolver: Box<dyn ExecResolver>,
        baseline: Baseline,
        enforce_supported: bool,
    ) -> Self {
        Self {
            maps,
            resolver,
            baseline,
            enforce_supported,
            target: None,
            applied_generation: 0,
            applied_hash: Vec::new(),
            global_mode: abi::global_mode::NORMAL,
            bindings: BTreeMap::new(),
            orphans: HashMap::new(),
            adopted: MapState::default(),
            adopted_generation: 0,
            protected_cgroups: Vec::new(),
            sandbox_default: None,
            installed: MapState::default(),
            next_epoch: 1,
        }
    }

    /// Adopts map contents left by a previous guestd in this boot: entries
    /// keep enforcing until the host re-binds (cgroups) or re-applies (rules).
    pub fn adopt(&mut self, found: MapState, global_mode: u32, policy_ready: u64) {
        self.orphans = found.cgroups.clone();
        self.adopted = MapState {
            cgroups: HashMap::new(),
            ..found.clone()
        };
        self.installed = found;
        self.global_mode = global_mode;
        self.adopted_generation = policy_ready;
    }

    pub fn adopted_generation(&self) -> u64 {
        self.adopted_generation
    }

    /// Adopted cgroup entries no binding has claimed, by cgroup id.
    pub fn adopted_cgroups(&self) -> Vec<pb::AdoptedCgroup> {
        let mut v: Vec<_> = self
            .orphans
            .iter()
            .map(|(&id, p)| pb::AdoptedCgroup {
                cgroup_id: id,
                policy_id: p.policy_id,
                generation: p.generation,
            })
            .collect();
        v.sort_unstable_by_key(|a| a.cgroup_id);
        v
    }

    /// Cgroups (relative to the cgroup2 root) that must never be bound, nor
    /// any of their ancestors: the policy would then apply to guestd or
    /// kata-agent through the BPF ancestor lookup.
    pub fn set_protected_cgroups(&mut self, paths: Vec<PathBuf>) {
        self.protected_cgroups = paths;
    }

    fn check_not_protected(&self, cgroup_path: &std::path::Path) -> Result<(), Rejection> {
        match self
            .protected_cgroups
            .iter()
            .find(|p| p.starts_with(cgroup_path))
        {
            Some(p) => Err(Rejection::invalid(format!(
                "cgroup {} contains protected cgroup {}",
                cgroup_path.display(),
                p.display()
            ))),
            None => Ok(()),
        }
    }

    /// Validates a SetSandboxDefault. `Ok(None)` clears the default; otherwise
    /// the caller resolves the path to a cgroup id and calls `set_sandbox_default`.
    pub fn sandbox_default_prepare(
        &self,
        req: &pb::SetSandboxDefault,
    ) -> Result<Option<(PathBuf, u8, u8)>, Rejection> {
        let mode = policy::mode_from_proto(req.mode)?;
        let failure = policy::failure_from_proto(req.failure)?;
        if failure != abi::failure::CLOSED {
            return Ok(None);
        }
        if mode == abi::mode::ENFORCE && !self.enforce_supported {
            return Err(Rejection::invalid(
                "enforce mode is not supported by this guest",
            ));
        }
        let path =
            pod_cgroup_path(&req.cgroup_parent).map_err(|e| Rejection::invalid(e.to_string()))?;
        self.check_not_protected(&path)?;
        Ok(Some((path, mode, failure)))
    }

    /// Installs (or with `None` removes) the sandbox default entry.
    pub fn set_sandbox_default(
        &mut self,
        d: Option<SandboxDefault>,
    ) -> Result<Outcome, EngineError> {
        let previous = std::mem::replace(&mut self.sandbox_default, d);
        let orphan = self.sandbox_default.as_ref().and_then(|sd| {
            self.orphans
                .remove(&sd.cgroup_id)
                .map(|o| (sd.cgroup_id, o))
        });
        if let Err(e) = self.reconcile() {
            self.sandbox_default = previous;
            if let Some((id, o)) = orphan {
                self.orphans.insert(id, o);
            }
            return Err(EngineError::Failed(
                e.context("installing the sandbox default"),
            ));
        }
        Ok(Outcome {
            generation: self.applied_generation,
            warnings: Vec::new(),
        })
    }

    pub fn sandbox_default(&self) -> Option<&SandboxDefault> {
        self.sandbox_default.as_ref()
    }

    pub fn applied_generation(&self) -> u64 {
        self.applied_generation
    }

    pub fn policy_hash(&self) -> &[u8] {
        &self.applied_hash
    }

    pub fn global_mode(&self) -> u32 {
        self.global_mode
    }

    pub fn enforce_supported(&self) -> bool {
        self.enforce_supported
    }

    /// cgroup id -> container id, for event attribution.
    pub fn container_names(&self) -> HashMap<u64, String> {
        self.bindings
            .iter()
            .filter_map(|(cid, b)| b.cgroup_id.map(|id| (id, cid.clone())))
            .collect()
    }

    pub fn bound_containers(&self) -> Vec<pb::BoundContainer> {
        self.bindings
            .iter()
            .map(|(cid, b)| {
                let v = self.cgroup_value(b);
                pb::BoundContainer {
                    container_id: cid.clone(),
                    cgroup_id: b.cgroup_id.unwrap_or(0),
                    policy_id: v.policy_id,
                    generation: v.generation,
                    pending: b.cgroup_id.is_none() || v.flags & abi::CGF_PENDING != 0,
                }
            })
            .collect()
    }

    fn applied(&self) -> Option<&CompiledPolicy> {
        self.target
            .as_ref()
            .filter(|t| t.generation == self.applied_generation)
    }

    /// (pending, bundle whose mode/defaults apply) for a binding.
    fn binding_policy(&self, b: &Binding) -> (bool, Option<&policy::Bundle>) {
        if b.policy_id == 0 {
            return (false, None);
        }
        let want = if b.generation == 0 {
            self.applied_generation
        } else {
            b.generation
        };
        let bundle = self.applied().and_then(|p| p.bundles.get(&b.policy_id));
        (
            want > self.applied_generation || self.applied_generation == 0,
            bundle,
        )
    }

    fn cgroup_value(&self, b: &Binding) -> CgroupPolicy {
        let (pending, bundle) = self.binding_policy(b);
        let mut v = CgroupPolicy {
            generation: if pending && b.generation != 0 {
                b.generation
            } else {
                self.applied_generation
            },
            rootfs_type: b.rootfs_type,
            ..Default::default()
        };
        match (bundle, pending) {
            (Some(bd), _) => {
                v.policy_id = b.policy_id;
                v.mode = bd.mode;
                v.failure = bd.failure;
                v.exec_default = bd.exec_default;
                v.net_default = bd.net_default;
            }
            (None, true) => {
                v.policy_id = b.policy_id;
                v.mode = self.baseline.mode;
                v.failure = self.baseline.failure;
            }
            // Monitor-only, or the policy was removed by a later ApplyPolicy.
            (None, false) => {}
        }
        if pending {
            v.flags |= abi::CGF_PENDING;
        }
        v
    }

    fn desired(&self) -> MapState {
        let mut d = MapState {
            cgroups: self.orphans.clone(),
            ..Default::default()
        };
        let mut exec = BTreeMap::new();
        for b in self.bindings.values() {
            let Some(id) = b.cgroup_id else { continue };
            d.cgroups.insert(id, self.cgroup_value(b));
            let (pending, bundle) = self.binding_policy(b);
            if pending || bundle.is_none() {
                continue;
            }
            if let Some(r) = b
                .resolved
                .as_ref()
                .filter(|r| r.policy_generation == self.applied_generation)
            {
                for ((dev, ino), v) in &r.ids {
                    policy::insert_rule(
                        &mut exec,
                        ExecKey {
                            policy_id: b.policy_id,
                            dev: *dev,
                            ino: *ino,
                        },
                        *v,
                    );
                }
            }
        }
        d.exec = exec.into_iter().collect();
        if let Some(sd) = &self.sandbox_default {
            // A binding on the same cgroup is more specific and wins.
            d.cgroups.entry(sd.cgroup_id).or_insert(CgroupPolicy {
                generation: self.applied_generation,
                mode: sd.mode,
                failure: sd.failure,
                flags: abi::CGF_PENDING,
                ..Default::default()
            });
        }
        if let Some(p) = self.applied() {
            d.net4 = p.net4.iter().map(|(k, v)| (*k, *v)).collect();
            d.net6 = p.net6.iter().map(|(k, v)| (*k, *v)).collect();
        }
        // Rules adopted from a previous guestd keep enforcing for the orphans
        // that reference them. Exec rules are per rootfs, so they stay even
        // when the policy_id is re-applied; net rules are per policy and are
        // superseded by an applied bundle with the same id.
        let referenced: HashSet<u32> = self
            .orphans
            .values()
            .map(|v| v.policy_id)
            .filter(|&id| id != 0)
            .collect();
        if !referenced.is_empty() {
            let reapplied = |id: u32| self.applied().is_some_and(|p| p.bundles.contains_key(&id));
            for (k, v) in &self.adopted.exec {
                if referenced.contains(&k.policy_id) {
                    d.exec.entry(*k).or_insert(*v);
                }
            }
            for (k, v) in &self.adopted.net4 {
                if referenced.contains(&k.policy_id) && !reapplied(k.policy_id) {
                    d.net4.entry(*k).or_insert(*v);
                }
            }
            for (k, v) in &self.adopted.net6 {
                if referenced.contains(&k.policy_id) && !reapplied(k.policy_id) {
                    d.net6.entry(*k).or_insert(*v);
                }
            }
        }
        d
    }

    fn reconcile(&mut self) -> anyhow::Result<()> {
        let d = self.desired();
        if d.cgroups.len() > abi::MAX_CGROUPS || d.exec.len() > abi::MAX_EXEC_RULES {
            bail!(
                "desired state exceeds map capacity ({} cgroups, {} exec rules)",
                d.cgroups.len(),
                d.exec.len()
            );
        }
        let (maps, inst) = (&mut self.maps, &mut self.installed);
        macro_rules! upsert {
            ($field:ident, $put:ident) => {
                for (k, v) in &d.$field {
                    if inst.$field.get(k) != Some(v) {
                        maps.$put(k, v)
                            .with_context(|| format!("writing {}", stringify!($field)))?;
                        inst.$field.insert(*k, *v);
                    }
                }
            };
        }
        macro_rules! remove {
            ($field:ident, $del:ident) => {
                let stale: Vec<_> = inst
                    .$field
                    .keys()
                    .filter(|k| !d.$field.contains_key(k))
                    .copied()
                    .collect();
                for k in stale {
                    maps.$del(&k)
                        .with_context(|| format!("deleting from {}", stringify!($field)))?;
                    inst.$field.remove(&k);
                }
            };
        }
        upsert!(exec, put_exec);
        upsert!(net4, put_net4);
        upsert!(net6, put_net6);
        for (k, v) in &d.cgroups {
            if inst.cgroups.get(k) != Some(v) {
                maps.put_cgroup(*k, v).context("writing cgroup_policy")?;
                inst.cgroups.insert(*k, *v);
            }
        }
        let stale: Vec<u64> = inst
            .cgroups
            .keys()
            .filter(|k| !d.cgroups.contains_key(k))
            .copied()
            .collect();
        for k in stale {
            maps.del_cgroup(k).context("deleting from cgroup_policy")?;
            inst.cgroups.remove(&k);
        }
        remove!(exec, del_exec);
        remove!(net4, del_net4);
        remove!(net6, del_net6);
        Ok(())
    }

    /// Resolves the exec rules of `cid`'s policy in its rootfs.
    fn resolve_binding(&self, cid: &str, warnings: &mut Vec<String>) -> Option<Resolved> {
        let b = self.bindings.get(cid)?;
        let (pending, bundle) = self.binding_policy(b);
        if pending || b.cgroup_id.is_none() {
            return None;
        }
        let mut ids = Vec::new();
        for r in bundle
            .map(|bd| bd.exec_rules.as_slice())
            .unwrap_or_default()
        {
            match self.resolver.resolve(cid, &r.path) {
                Ok(id) => ids.push((
                    id,
                    RuleValue {
                        verdict: u32::from(r.verdict),
                        rule_id: r.rule_id,
                    },
                )),
                Err(e) => push_warning(
                    warnings,
                    format!("container {cid}: exec rule {}: {e}", r.rule_id),
                ),
            }
        }
        Some(Resolved {
            policy_generation: self.applied_generation,
            ids,
        })
    }

    fn resolve_all(&mut self, warnings: &mut Vec<String>) {
        let cids: Vec<String> = self.bindings.keys().cloned().collect();
        for cid in cids {
            let r = self.resolve_binding(&cid, warnings);
            if let Some(b) = self.bindings.get_mut(&cid) {
                b.resolved = r;
            }
        }
    }

    /// Exec lookups needed if `bindings` all resolve against `target`.
    fn resolution_cost(&self, target: &CompiledPolicy) -> usize {
        self.resolution_cost_excluding(target, None)
    }

    fn resolution_cost_excluding(&self, target: &CompiledPolicy, skip: Option<&str>) -> usize {
        self.bindings
            .iter()
            .filter(|(cid, b)| b.cgroup_id.is_some() && Some(cid.as_str()) != skip)
            .filter_map(|(_, b)| target.bundles.get(&b.policy_id))
            .map(|bd| bd.exec_rules.len())
            .sum()
    }

    pub fn apply(&mut self, req: &pb::ApplyPolicy) -> Result<Outcome, EngineError> {
        let compiled = policy::compile(req, self.enforce_supported)?;
        let generation = compiled.generation;
        if generation < self.applied_generation {
            return Err(Rejection::invalid(format!(
                "generation {generation} is older than the applied generation {}",
                self.applied_generation
            ))
            .into());
        }
        if self.applied_generation == 0 && generation < self.adopted_generation {
            return Err(Rejection::invalid(format!(
                "generation {generation} is older than generation {} adopted from the previous guestd",
                self.adopted_generation
            ))
            .into());
        }
        if generation == self.applied_generation {
            return Ok(Outcome {
                generation,
                warnings: Vec::new(),
            });
        }
        if self.resolution_cost(&compiled) > abi::MAX_EXEC_RULES {
            return Err(Rejection::limit(
                "bound containers x exec rules exceeds the exec_rules map",
            )
            .into());
        }
        let mut warnings = compiled.warnings.clone();
        let hash = compiled.hash.to_vec();
        let previous = (
            self.target.replace(compiled),
            self.applied_generation,
            self.applied_hash.clone(),
        );
        // Resolve against the new generation before it becomes visible.
        self.applied_generation = generation;
        self.applied_hash = hash;
        self.resolve_all(&mut warnings);
        let res = self
            .reconcile()
            .and_then(|()| self.maps.set_policy_ready(generation));
        if let Err(e) = res {
            // Not in force: an ApplyPolicy with the same generation is retried, not a no-op.
            (self.target, self.applied_generation, self.applied_hash) = previous;
            let mut ignored = Vec::new();
            self.resolve_all(&mut ignored);
            if let Err(revert) = self.reconcile() {
                tracing::warn!(error = %format!("{revert:#}"), "reverting a failed ApplyPolicy failed; maps are mixed until the next change");
            }
            return Err(EngineError::Failed(
                e.context(format!("applying generation {generation}")),
            ));
        }
        for b in self.bindings.values() {
            if b.cgroup_id.is_some() && b.policy_id != 0 && self.binding_policy(b).1.is_none() {
                push_warning(
                    &mut warnings,
                    format!(
                        "policy {} is no longer defined; its containers are monitor-only",
                        b.policy_id
                    ),
                );
            }
        }
        Ok(Outcome {
            generation,
            warnings,
        })
    }

    /// Validates a BindContainer and registers it as pending until its cgroup
    /// exists. A re-bind of a live container leaves the live binding in force
    /// until `bind_complete` swaps it.
    pub fn bind_prepare(&mut self, req: &pb::BindContainer) -> Result<BindTicket, Rejection> {
        validate_container_id(&req.container_id).map_err(|e| Rejection::invalid(e.to_string()))?;
        let cgroup_path = guest_cgroup_path(&req.cgroup_path, &req.container_id)
            .map_err(|e| Rejection::invalid(e.to_string()))?;
        self.check_not_protected(&cgroup_path)?;
        let rootfs_type = pb::RootfsType::try_from(req.rootfs)
            .map_err(|_| Rejection::invalid(format!("unknown rootfs type {}", req.rootfs)))?
            as i32 as u8;
        if req.policy_id > abi::MAX_POLICIES {
            return Err(Rejection::invalid(format!(
                "policy_id {} outside 0..={}",
                req.policy_id,
                abi::MAX_POLICIES
            )));
        }
        let want = if req.generation == 0 {
            self.applied_generation
        } else {
            req.generation
        };
        if req.policy_id != 0 && want <= self.applied_generation && self.applied_generation != 0 {
            let known = self
                .applied()
                .is_some_and(|p| p.bundles.contains_key(&req.policy_id));
            if !known {
                return Err(Rejection {
                    code: ErrorCode::NotFound,
                    message: format!(
                        "policy_id {} is not in applied generation {}",
                        req.policy_id, self.applied_generation
                    ),
                });
            }
        }
        if !self.bindings.contains_key(&req.container_id) && self.bindings.len() >= abi::MAX_CGROUPS
        {
            return Err(Rejection::limit(format!(
                "more than {} bound containers",
                abi::MAX_CGROUPS
            )));
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        match self.bindings.get_mut(&req.container_id) {
            Some(live) if live.cgroup_id.is_some() => {
                live.next = Some(Rebind {
                    policy_id: req.policy_id,
                    generation: req.generation,
                    rootfs_type,
                    epoch,
                });
            }
            _ => {
                self.bindings.insert(
                    req.container_id.clone(),
                    Binding {
                        cgroup_id: None,
                        policy_id: req.policy_id,
                        generation: req.generation,
                        rootfs_type,
                        epoch,
                        resolved: None,
                        next: None,
                    },
                );
            }
        }
        Ok(BindTicket {
            container_id: req.container_id.clone(),
            cgroup_path,
            epoch,
        })
    }

    /// Whether `t` is the current bind of its container, and whether it is a
    /// re-bind of a live binding.
    fn ticket_kind(&self, t: &BindTicket) -> Option<bool> {
        let b = self.bindings.get(&t.container_id)?;
        if b.next.is_some_and(|n| n.epoch == t.epoch) {
            Some(true)
        } else if b.cgroup_id.is_none() && b.epoch == t.epoch {
            Some(false)
        } else {
            None
        }
    }

    pub fn ticket_is_current(&self, t: &BindTicket) -> bool {
        self.ticket_kind(t).is_some()
    }

    /// Drops the pending part of `t`: a fresh bind is removed, a re-bind is
    /// discarded and the live binding kept.
    fn drop_ticket(&mut self, t: &BindTicket, rebind: bool) {
        if rebind {
            if let Some(b) = self.bindings.get_mut(&t.container_id) {
                b.next = None;
            }
        } else {
            self.bindings.remove(&t.container_id);
        }
    }

    /// Completes a bind once the cgroup exists.
    pub fn bind_complete(
        &mut self,
        t: &BindTicket,
        cgroup_id: u64,
    ) -> Result<Outcome, EngineError> {
        let rebind = self
            .ticket_kind(t)
            .ok_or_else(|| Rejection::invalid("bind superseded by a newer BindContainer"))?;
        let previous = self
            .bindings
            .get(&t.container_id)
            .cloned()
            .ok_or_else(|| Rejection::invalid("binding vanished"))?;
        let (policy_id, generation, rootfs_type, epoch) = match previous.next {
            Some(n) if rebind => (n.policy_id, n.generation, n.rootfs_type, n.epoch),
            _ => (
                previous.policy_id,
                previous.generation,
                previous.rootfs_type,
                previous.epoch,
            ),
        };
        if let Some((other, _)) = self
            .bindings
            .iter()
            .find(|(c, o)| **c != t.container_id && o.cgroup_id == Some(cgroup_id))
        {
            let msg = format!("cgroup {cgroup_id} is already bound to container {other}");
            self.drop_ticket(t, rebind);
            return Err(Rejection::invalid(msg).into());
        }
        let target = self.target.clone().unwrap_or_else(empty_policy);
        let extra = target
            .bundles
            .get(&policy_id)
            .map_or(0, |bd| bd.exec_rules.len());
        if self.resolution_cost_excluding(&target, Some(&t.container_id)) + extra
            > abi::MAX_EXEC_RULES
        {
            self.drop_ticket(t, rebind);
            return Err(Rejection::limit(
                "bound containers x exec rules exceeds the exec_rules map",
            )
            .into());
        }
        let orphan = self.orphans.remove(&cgroup_id);
        self.bindings.insert(
            t.container_id.clone(),
            Binding {
                cgroup_id: Some(cgroup_id),
                policy_id,
                generation,
                rootfs_type,
                epoch,
                resolved: None,
                next: None,
            },
        );
        let mut warnings = Vec::new();
        if let Some(sd) = &self.sandbox_default {
            if t.cgroup_path.parent() != Some(sd.path.as_path()) {
                push_warning(
                    &mut warnings,
                    format!(
                        "container cgroup {} is not directly under the pod cgroup {}; the sandbox default does not match this layout",
                        t.cgroup_path.display(),
                        sd.path.display()
                    ),
                );
            }
        }
        let r = self.resolve_binding(&t.container_id, &mut warnings);
        let value = match self.bindings.get_mut(&t.container_id) {
            Some(b) => {
                b.resolved = r;
                let b = b.clone();
                self.cgroup_value(&b)
            }
            None => return Err(Rejection::invalid("binding vanished").into()),
        };
        if let Err(e) = self.reconcile() {
            // Put back what was in force before this bind.
            if rebind {
                self.bindings.insert(
                    t.container_id.clone(),
                    Binding {
                        next: None,
                        ..previous
                    },
                );
            } else {
                self.bindings.remove(&t.container_id);
            }
            if let Some(o) = orphan {
                self.orphans.insert(cgroup_id, o);
            }
            if let Err(revert) = self.reconcile() {
                tracing::warn!(error = %format!("{revert:#}"), "reverting a failed bind failed; maps are mixed until the next change");
            }
            return Err(EngineError::Failed(
                e.context(format!("binding {}", t.container_id)),
            ));
        }
        // A pending binding runs on the guest baseline, not on the policy the
        // host asked for: ack the applied generation so the host's gate sees
        // the mismatch and applies the policy's failure policy.
        let generation = if value.flags & abi::CGF_PENDING != 0 {
            push_warning(
                &mut warnings,
                format!(
                    "policy generation {} not applied (applied {}); the guest baseline applies",
                    value.generation, self.applied_generation
                ),
            );
            self.applied_generation
        } else {
            value.generation
        };
        Ok(Outcome {
            generation,
            warnings,
        })
    }

    /// Drops a bind that timed out or failed (if it was not superseded).
    pub fn bind_abort(&mut self, t: &BindTicket) {
        if let Some(rebind) = self.ticket_kind(t) {
            self.drop_ticket(t, rebind);
        }
    }

    pub fn unbind(&mut self, container_id: &str) -> Result<Outcome, EngineError> {
        validate_container_id(container_id).map_err(|e| Rejection::invalid(e.to_string()))?;
        let mut warnings = Vec::new();
        if self.bindings.remove(container_id).is_none() {
            push_warning(
                &mut warnings,
                format!("container {container_id} was not bound"),
            );
        }
        self.reconcile()
            .map_err(|e| EngineError::Failed(e.context(format!("unbinding {container_id}"))))?;
        Ok(Outcome {
            generation: self.applied_generation,
            warnings,
        })
    }

    pub fn set_global_mode(&mut self, mode: u32) -> anyhow::Result<()> {
        self.maps
            .set_global_mode(mode)
            .context("writing global_mode")?;
        self.global_mode = mode;
        Ok(())
    }

    /// Removes bindings and orphans whose cgroup no longer exists.
    pub fn gc(&mut self, existing: &HashSet<u64>) -> anyhow::Result<usize> {
        let before = self.bindings.len() + self.orphans.len();
        self.bindings
            .retain(|_, b| b.cgroup_id.is_none_or(|id| existing.contains(&id)));
        self.orphans.retain(|id, _| existing.contains(id));
        let mut removed = before - self.bindings.len() - self.orphans.len();
        if self
            .sandbox_default
            .as_ref()
            .is_some_and(|sd| !existing.contains(&sd.cgroup_id))
        {
            self.sandbox_default = None;
            removed += 1;
        }
        if removed > 0 {
            self.reconcile()?;
        }
        Ok(removed)
    }
}

fn empty_policy() -> CompiledPolicy {
    CompiledPolicy {
        generation: 0,
        bundles: BTreeMap::new(),
        net4: BTreeMap::new(),
        net6: BTreeMap::new(),
        hash: [0; 32],
        warnings: Vec::new(),
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;

    #[derive(Debug, Default)]
    pub struct FakeMaps {
        pub state: MapState,
        pub policy_ready: u64,
        pub global_mode: u32,
        pub writes: usize,
        /// Fail the n-th write from now (1-based).
        pub fail_after: Option<usize>,
    }

    impl FakeMaps {
        fn write(&mut self) -> anyhow::Result<()> {
            self.writes += 1;
            if let Some(n) = self.fail_after.as_mut() {
                *n -= 1;
                if *n == 0 {
                    self.fail_after = None;
                    bail!("injected map failure");
                }
            }
            Ok(())
        }
    }

    impl PolicyMaps for FakeMaps {
        fn put_cgroup(&mut self, id: u64, v: &CgroupPolicy) -> anyhow::Result<()> {
            self.write()?;
            self.state.cgroups.insert(id, *v);
            Ok(())
        }
        fn del_cgroup(&mut self, id: u64) -> anyhow::Result<()> {
            self.write()?;
            self.state.cgroups.remove(&id);
            Ok(())
        }
        fn put_exec(&mut self, k: &ExecKey, v: &RuleValue) -> anyhow::Result<()> {
            self.write()?;
            self.state.exec.insert(*k, *v);
            Ok(())
        }
        fn del_exec(&mut self, k: &ExecKey) -> anyhow::Result<()> {
            self.write()?;
            self.state.exec.remove(k);
            Ok(())
        }
        fn put_net4(&mut self, k: &NetKeyV4, v: &RuleValue) -> anyhow::Result<()> {
            self.write()?;
            self.state.net4.insert(*k, *v);
            Ok(())
        }
        fn del_net4(&mut self, k: &NetKeyV4) -> anyhow::Result<()> {
            self.write()?;
            self.state.net4.remove(k);
            Ok(())
        }
        fn put_net6(&mut self, k: &NetKeyV6, v: &RuleValue) -> anyhow::Result<()> {
            self.write()?;
            self.state.net6.insert(*k, *v);
            Ok(())
        }
        fn del_net6(&mut self, k: &NetKeyV6) -> anyhow::Result<()> {
            self.write()?;
            self.state.net6.remove(k);
            Ok(())
        }
        fn set_policy_ready(&mut self, generation: u64) -> anyhow::Result<()> {
            self.write()?;
            self.policy_ready = generation;
            Ok(())
        }
        fn set_global_mode(&mut self, mode: u32) -> anyhow::Result<()> {
            self.write()?;
            self.global_mode = mode;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeMaps;
    use super::*;
    use crate::resolve::fake::FakeResolver;

    const BASE: Baseline = Baseline {
        mode: abi::mode::AUDIT,
        failure: abi::failure::OPEN,
    };
    const CG_PATH: &str = "kubepods-pod1.slice:cri-containerd:c1";

    fn engine(resolver: FakeResolver) -> Engine<FakeMaps> {
        Engine::new(FakeMaps::default(), Box::new(resolver), BASE, true)
    }

    fn bundle(id: u32, mode: pb::Mode, failure: pb::FailurePolicy) -> pb::PolicyBundle {
        pb::PolicyBundle {
            policy_id: id,
            name: format!("ns/p{id}"),
            mode: mode as i32,
            failure: failure as i32,
            exec: Some(pb::ExecRules {
                default_verdict: pb::Verdict::Allow as i32,
                rules: vec![
                    pb::ExecRule {
                        rule_id: 10,
                        path: "/usr/bin/curl".into(),
                        verdict: pb::Verdict::Deny as i32,
                    },
                    pb::ExecRule {
                        rule_id: 11,
                        path: "/missing".into(),
                        verdict: pb::Verdict::Deny as i32,
                    },
                ],
            }),
            net: Some(pb::NetRules {
                default_egress: pb::Verdict::Deny as i32,
                egress: vec![pb::NetRule {
                    rule_id: 20,
                    cidr: "10.0.0.0/8".into(),
                    ports: vec![],
                    protocol: pb::Protocol::Any as i32,
                    verdict: pb::Verdict::Allow as i32,
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

    fn bind(cid: &str, policy_id: u32, generation: u64) -> pb::BindContainer {
        pb::BindContainer {
            container_id: cid.into(),
            cgroup_path: CG_PATH.replace("c1", cid),
            policy_id,
            rootfs: pb::RootfsType::VirtioFs as i32,
            generation,
        }
    }

    fn resolver() -> FakeResolver {
        FakeResolver::default()
            .with("c1", "/usr/bin/curl", (5, 100))
            .with("c2", "/usr/bin/curl", (6, 200))
    }

    #[test]
    fn apply_bind_unbind_lifecycle() {
        let mut e = engine(resolver());
        let out = e
            .apply(&apply(
                1,
                vec![bundle(7, pb::Mode::Enforce, pb::FailurePolicy::Closed)],
            ))
            .unwrap();
        assert_eq!(out.generation, 1);
        assert_eq!(e.maps.policy_ready, 1);
        assert_eq!(e.maps.state.net4.len(), 1);
        assert!(e.maps.state.exec.is_empty(), "no container bound yet");

        let t = e.bind_prepare(&bind("c1", 7, 1)).unwrap();
        assert_eq!(
            t.cgroup_path,
            PathBuf::from("kubepods.slice/kubepods-pod1.slice/cri-containerd-c1.scope")
        );
        let out = e.bind_complete(&t, 1000).unwrap();
        assert_eq!(
            out.warnings.len(),
            1,
            "missing path is a warning: {:?}",
            out.warnings
        );
        let cg = e.maps.state.cgroups[&1000];
        assert_eq!(
            (cg.policy_id, cg.mode, cg.failure, cg.flags, cg.generation),
            (7, 1, 1, 0, 1)
        );
        assert_eq!((cg.exec_default, cg.net_default, cg.rootfs_type), (1, 2, 2));
        let k = ExecKey {
            policy_id: 7,
            dev: 5,
            ino: 100,
        };
        assert_eq!(
            e.maps.state.exec[&k],
            RuleValue {
                verdict: 2,
                rule_id: 10
            }
        );
        assert_eq!(e.container_names()[&1000], "c1");

        e.unbind("c1").unwrap();
        assert!(e.maps.state.cgroups.is_empty());
        assert!(e.maps.state.exec.is_empty());
        assert_eq!(
            e.maps.state.net4.len(),
            1,
            "net rules belong to the policy, not the binding"
        );
    }

    #[test]
    fn generation_rules() {
        let mut e = engine(resolver());
        e.apply(&apply(
            5,
            vec![bundle(1, pb::Mode::Audit, pb::FailurePolicy::Open)],
        ))
        .unwrap();
        let writes = e.maps.writes;
        // Equal generation: no-op ack even with different content.
        assert_eq!(e.apply(&apply(5, vec![])).unwrap().generation, 5);
        assert_eq!(e.maps.writes, writes);
        let err = e.apply(&apply(4, vec![])).unwrap_err();
        assert!(matches!(
            err,
            EngineError::Rejected(Rejection {
                code: ErrorCode::InvalidArgument,
                ..
            })
        ));
        // Higher generation replaces the whole set.
        e.apply(&apply(6, vec![])).unwrap();
        assert!(e.maps.state.net4.is_empty());
        assert_eq!(e.maps.policy_ready, 6);
    }

    #[test]
    fn pending_bind_until_generation_applied() {
        let mut e = engine(resolver());
        let t = e.bind_prepare(&bind("c1", 7, 3)).unwrap();
        let out = e.bind_complete(&t, 1000).unwrap();
        assert_eq!(
            out.generation, 0,
            "a pending bind acks the applied generation, not the requested one"
        );
        assert!(out.warnings.iter().any(|w| w.contains("baseline")));
        let cg = e.maps.state.cgroups[&1000];
        assert_eq!(cg.flags, abi::CGF_PENDING);
        assert_eq!(cg.generation, 3);
        assert_eq!(
            (cg.mode, cg.failure, cg.policy_id),
            (BASE.mode, BASE.failure, 7)
        );
        assert!(e.bound_containers()[0].pending);

        e.apply(&apply(
            3,
            vec![bundle(7, pb::Mode::Enforce, pb::FailurePolicy::Closed)],
        ))
        .unwrap();
        let cg = e.maps.state.cgroups[&1000];
        assert_eq!((cg.flags, cg.mode, cg.generation), (0, 1, 3));
        assert_eq!(e.maps.state.exec.len(), 1);
    }

    #[test]
    fn bind_to_unknown_policy_is_not_found() {
        let mut e = engine(resolver());
        e.apply(&apply(
            1,
            vec![bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open)],
        ))
        .unwrap();
        let err = e.bind_prepare(&bind("c1", 8, 1)).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(
            e.bind_prepare(&bind("c1", 0, 0)).is_ok(),
            "policy 0 = monitor only"
        );
    }

    #[test]
    fn monitor_only_binding() {
        let mut e = engine(resolver());
        e.apply(&apply(2, vec![])).unwrap();
        let t = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        e.bind_complete(&t, 42).unwrap();
        let cg = e.maps.state.cgroups[&42];
        assert_eq!(
            (cg.policy_id, cg.mode, cg.flags, cg.generation),
            (0, 0, 0, 2)
        );
    }

    #[test]
    fn removed_policy_degrades_to_monitor_only() {
        let mut e = engine(resolver());
        e.apply(&apply(
            1,
            vec![bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open)],
        ))
        .unwrap();
        let t = e.bind_prepare(&bind("c1", 7, 1)).unwrap();
        e.bind_complete(&t, 1000).unwrap();
        let out = e.apply(&apply(2, vec![])).unwrap();
        assert!(out.warnings.iter().any(|w| w.contains("monitor-only")));
        assert_eq!(e.maps.state.cgroups[&1000].policy_id, 0);
        assert!(e.maps.state.exec.is_empty());
    }

    #[test]
    fn shared_file_across_containers_deny_wins() {
        let r = FakeResolver::default()
            .with("c1", "/usr/bin/curl", (5, 100))
            .with("c2", "/usr/bin/curl", (5, 100));
        let mut e = engine(r);
        let mut b = bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open);
        b.exec.as_mut().unwrap().rules.push(pb::ExecRule {
            rule_id: 3,
            path: "/usr/bin/curl".into(),
            verdict: pb::Verdict::Allow as i32,
        });
        e.apply(&apply(1, vec![b])).unwrap();
        for (cid, cg) in [("c1", 1u64), ("c2", 2)] {
            let t = e.bind_prepare(&bind(cid, 7, 1)).unwrap();
            e.bind_complete(&t, cg).unwrap();
        }
        assert_eq!(e.maps.state.exec.len(), 1);
        assert_eq!(e.maps.state.exec.values().next().unwrap().verdict, 2);
        e.unbind("c1").unwrap();
        assert_eq!(e.maps.state.exec.len(), 1, "still used by c2");
    }

    #[test]
    fn superseded_and_aborted_binds() {
        let mut e = engine(resolver());
        let old = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        let new = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        assert!(!e.ticket_is_current(&old));
        assert!(e.bind_complete(&old, 1).is_err());
        e.bind_abort(&old);
        assert!(
            e.ticket_is_current(&new),
            "aborting a stale ticket keeps the new bind"
        );
        e.bind_abort(&new);
        assert!(e.bound_containers().is_empty());
    }

    #[test]
    fn duplicate_cgroup_rejected() {
        let mut e = engine(resolver());
        let t1 = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        e.bind_complete(&t1, 9).unwrap();
        let t2 = e.bind_prepare(&bind("c2", 0, 0)).unwrap();
        assert!(e.bind_complete(&t2, 9).is_err());
        assert_eq!(e.container_names()[&9], "c1");
    }

    #[test]
    fn failed_apply_is_retryable() {
        let mut e = engine(resolver());
        e.maps.fail_after = Some(1);
        assert!(matches!(
            e.apply(&apply(
                1,
                vec![bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open)]
            )),
            Err(EngineError::Failed(_))
        ));
        assert_eq!(e.applied_generation(), 0);
        assert_eq!(e.maps.policy_ready, 0);
        e.apply(&apply(
            1,
            vec![bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open)],
        ))
        .unwrap();
        assert_eq!(e.maps.policy_ready, 1);
        assert_eq!(e.maps.state.net4.len(), 1);
    }

    #[test]
    fn adopted_orphans_survive_until_gc() {
        let mut e = engine(resolver());
        let mut found = MapState::default();
        found.cgroups.insert(
            77,
            CgroupPolicy {
                policy_id: 3,
                ..Default::default()
            },
        );
        e.maps.state = found.clone();
        e.adopt(found, abi::global_mode::NORMAL, 0);
        e.apply(&apply(1, vec![])).unwrap();
        assert!(e.maps.state.cgroups.contains_key(&77));
        assert_eq!(e.gc(&HashSet::from([1])).unwrap(), 1);
        assert!(e.maps.state.cgroups.is_empty());
    }

    #[test]
    fn adopted_generation_is_a_floor_until_applied() {
        let mut e = engine(resolver());
        let mut found = MapState::default();
        found.cgroups.insert(
            77,
            CgroupPolicy {
                policy_id: 3,
                generation: 40,
                ..Default::default()
            },
        );
        e.maps.state = found.clone();
        e.maps.policy_ready = 40;
        e.adopt(found, abi::global_mode::NORMAL, 40);
        assert_eq!(e.adopted_generation(), 40);
        assert_eq!(e.applied_generation(), 0);
        assert_eq!(
            e.adopted_cgroups(),
            vec![pb::AdoptedCgroup {
                cgroup_id: 77,
                policy_id: 3,
                generation: 40
            }]
        );

        // An agent with an older generation must not move policy_ready back.
        assert!(e.apply(&apply(39, vec![])).is_err());
        assert_eq!(e.maps.policy_ready, 40);
        assert_eq!(e.applied_generation(), 0);

        // The same generation is applied, not treated as a no-op.
        e.apply(&apply(40, vec![])).unwrap();
        assert_eq!(e.applied_generation(), 40);
        assert_eq!(e.maps.policy_ready, 40);
        // Orphans are still listed until re-bound or collected.
        assert_eq!(e.adopted_cgroups().len(), 1);
    }

    fn sandbox_default_req(
        parent: &str,
        mode: pb::Mode,
        failure: pb::FailurePolicy,
    ) -> pb::SetSandboxDefault {
        pb::SetSandboxDefault {
            cgroup_parent: parent.into(),
            mode: mode as i32,
            failure: failure as i32,
        }
    }

    fn install_default(e: &mut Engine<FakeMaps>, id: u64) {
        let (path, mode, failure) = e
            .sandbox_default_prepare(&sandbox_default_req(
                "kubepods-pod1.slice",
                pb::Mode::Enforce,
                pb::FailurePolicy::Closed,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(path, PathBuf::from("kubepods.slice/kubepods-pod1.slice"));
        e.set_sandbox_default(Some(SandboxDefault {
            path,
            cgroup_id: id,
            mode,
            failure,
        }))
        .unwrap();
    }

    #[test]
    fn sandbox_default_covers_unbound_cgroups_until_bound() {
        let mut e = engine(resolver());
        e.apply(&apply(
            1,
            vec![bundle(7, pb::Mode::Enforce, pb::FailurePolicy::Closed)],
        ))
        .unwrap();
        install_default(&mut e, 500);
        let cg = e.maps.state.cgroups[&500];
        assert_eq!(
            (cg.policy_id, cg.mode, cg.failure, cg.flags, cg.generation),
            (
                0,
                abi::mode::ENFORCE,
                abi::failure::CLOSED,
                abi::CGF_PENDING,
                1
            ),
            "pending + Closed: BPF denies exec/connect below the pod cgroup"
        );

        // A bound container has its own, nearer entry; the default stays for the rest.
        let t = e.bind_prepare(&bind("c1", 7, 1)).unwrap();
        let out = e.bind_complete(&t, 1000).unwrap();
        assert!(
            out.warnings.iter().all(|w| !w.contains("pod cgroup")),
            "container is directly under the pod cgroup: {:?}",
            out.warnings
        );
        assert_eq!(e.maps.state.cgroups[&1000].policy_id, 7);
        assert!(e.maps.state.cgroups.contains_key(&500));

        // Open clears it.
        let cleared = e
            .sandbox_default_prepare(&sandbox_default_req(
                "kubepods-pod1.slice",
                pb::Mode::Enforce,
                pb::FailurePolicy::Open,
            ))
            .unwrap();
        assert!(cleared.is_none());
        e.set_sandbox_default(None).unwrap();
        assert!(!e.maps.state.cgroups.contains_key(&500));
        assert!(e.maps.state.cgroups.contains_key(&1000));
    }

    #[test]
    fn sandbox_default_validation_and_gc() {
        let mut e = engine(resolver());
        e.set_protected_cgroups(vec![PathBuf::from("system.slice/kata-agent.service")]);
        for (parent, why) in [
            ("system.slice", "contains kata-agent"),
            ("", "cgroup root"),
            ("/a/../b", "escape"),
        ] {
            assert!(
                e.sandbox_default_prepare(&sandbox_default_req(
                    parent,
                    pb::Mode::Audit,
                    pb::FailurePolicy::Closed
                ))
                .is_err(),
                "{why}"
            );
        }
        install_default(&mut e, 500);
        assert_eq!(e.sandbox_default().unwrap().cgroup_id, 500);
        assert_eq!(e.gc(&HashSet::from([1])).unwrap(), 1);
        assert!(e.sandbox_default().is_none());
        assert!(e.maps.state.cgroups.is_empty());
    }

    #[test]
    fn sandbox_default_replaces_an_adopted_entry() {
        let mut e = engine(resolver());
        let mut found = MapState::default();
        found.cgroups.insert(500, CgroupPolicy::default());
        e.maps.state = found.clone();
        e.adopt(found, abi::global_mode::NORMAL, 0);
        install_default(&mut e, 500);
        assert!(e.adopted_cgroups().is_empty());
        assert_eq!(e.maps.state.cgroups[&500].flags, abi::CGF_PENDING);
    }

    #[test]
    fn bind_outside_the_pod_cgroup_is_warned() {
        let mut e = engine(resolver());
        install_default(&mut e, 500);
        let mut b = bind("c9", 0, 0);
        b.cgroup_path = "/elsewhere/c9".into();
        let t = e.bind_prepare(&b).unwrap();
        let out = e.bind_complete(&t, 900).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.contains("pod cgroup")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn no_floor_without_adoption() {
        let mut e = engine(resolver());
        e.apply(&apply(1, vec![])).unwrap();
        assert_eq!(e.adopted_generation(), 0);
        assert!(e.adopted_cgroups().is_empty());
    }

    #[test]
    fn gc_removes_dead_bindings() {
        let mut e = engine(resolver());
        let t = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        e.bind_complete(&t, 5).unwrap();
        assert_eq!(e.gc(&HashSet::from([5])).unwrap(), 0);
        assert_eq!(e.gc(&HashSet::new()).unwrap(), 1);
        assert!(e.maps.state.cgroups.is_empty());
    }

    #[test]
    fn invalid_binds() {
        let mut e = engine(resolver());
        let mut b = bind("c1", 0, 0);
        b.cgroup_path = "/../x".into();
        assert!(e.bind_prepare(&b).is_err());
        let mut b = bind("c1", 0, 0);
        b.container_id = "../x".into();
        assert!(e.bind_prepare(&b).is_err());
        let mut b = bind("c1", 0, 0);
        b.rootfs = 9;
        assert!(e.bind_prepare(&b).is_err());
        let b = bind("c1", 2000, 0);
        assert!(e.bind_prepare(&b).is_err());
    }

    #[test]
    fn warnings_are_bounded() {
        let mut w = Vec::new();
        for _ in 0..100 {
            push_warning(&mut w, "é".repeat(300));
        }
        assert_eq!(w.len(), MAX_WARNINGS);
        assert!(w.iter().all(|m| m.len() <= MAX_WARNING_LEN));
    }

    fn adopted_state() -> MapState {
        let mut found = MapState::default();
        found.cgroups.insert(
            77,
            CgroupPolicy {
                policy_id: 3,
                mode: abi::mode::ENFORCE,
                generation: 9,
                ..Default::default()
            },
        );
        found.exec.insert(
            ExecKey {
                policy_id: 3,
                dev: 1,
                ino: 2,
            },
            RuleValue {
                verdict: 2,
                rule_id: 5,
            },
        );
        // Not referenced by any orphan: dropped on the first reconcile.
        found.exec.insert(
            ExecKey {
                policy_id: 4,
                dev: 1,
                ino: 3,
            },
            RuleValue {
                verdict: 2,
                rule_id: 6,
            },
        );
        found.net4.insert(
            NetKeyV4 {
                prefixlen: 72,
                policy_id: 3,
                ..Default::default()
            },
            RuleValue {
                verdict: 2,
                rule_id: 7,
            },
        );
        found
    }

    #[test]
    fn adopted_rules_survive_unrelated_changes() {
        let mut e = engine(resolver());
        let found = adopted_state();
        e.maps.state = found.clone();
        e.adopt(found, abi::global_mode::NORMAL, 0);

        let t = e.bind_prepare(&bind("c9", 0, 0)).unwrap();
        e.bind_complete(&t, 500).unwrap();
        assert!(e.maps.state.cgroups.contains_key(&77));
        assert_eq!(e.maps.state.exec.len(), 1, "orphan's exec rule kept");
        assert_eq!(e.maps.state.net4.len(), 1, "orphan's net rule kept");

        // A new policy set without policy 3 keeps the orphan's rules too.
        e.apply(&apply(
            10,
            vec![bundle(7, pb::Mode::Audit, pb::FailurePolicy::Open)],
        ))
        .unwrap();
        assert!(e.maps.state.net4.values().any(|v| v.rule_id == 7));
        assert!(e.maps.state.exec.values().any(|v| v.rule_id == 5));

        // Once the orphan is gone, its rules go too.
        assert_eq!(e.gc(&HashSet::from([500])).unwrap(), 1);
        assert!(!e.maps.state.exec.values().any(|v| v.rule_id == 5));
        assert!(!e.maps.state.net4.values().any(|v| v.rule_id == 7));
    }

    #[test]
    fn reapplied_policy_replaces_adopted_net_rules() {
        let mut e = engine(resolver());
        let found = adopted_state();
        e.maps.state = found.clone();
        e.adopt(found, abi::global_mode::NORMAL, 0);
        e.apply(&apply(
            10,
            vec![bundle(3, pb::Mode::Enforce, pb::FailurePolicy::Closed)],
        ))
        .unwrap();
        assert!(!e.maps.state.net4.values().any(|v| v.rule_id == 7));
        assert!(e.maps.state.net4.values().any(|v| v.rule_id == 20));
        assert!(e.maps.state.exec.values().any(|v| v.rule_id == 5));
    }

    #[test]
    fn rebind_keeps_live_binding_until_complete() {
        let mut e = engine(resolver());
        e.apply(&apply(
            1,
            vec![bundle(7, pb::Mode::Enforce, pb::FailurePolicy::Closed)],
        ))
        .unwrap();
        let t = e.bind_prepare(&bind("c1", 7, 1)).unwrap();
        e.bind_complete(&t, 1000).unwrap();
        let before = e.maps.state.clone();
        let writes = e.maps.writes;

        let t2 = e.bind_prepare(&bind("c1", 7, 1)).unwrap();
        assert_eq!(e.maps.state, before, "prepare must not touch the maps");
        assert!(e.ticket_is_current(&t2));
        assert!(!e.ticket_is_current(&t));
        let out = e.bind_complete(&t2, 1000).unwrap();
        assert_eq!(out.generation, 1);
        assert_eq!(e.maps.state, before);
        assert_eq!(e.maps.writes, writes, "identical re-bind writes nothing");

        // A re-bind that times out keeps the live binding.
        let t3 = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        e.bind_abort(&t3);
        assert_eq!(e.maps.state, before);
        assert_eq!(e.container_names()[&1000], "c1");

        // A re-bind whose map write fails reverts to the live binding.
        let t4 = e.bind_prepare(&bind("c1", 0, 0)).unwrap();
        e.maps.fail_after = Some(1);
        assert!(matches!(
            e.bind_complete(&t4, 1000),
            Err(EngineError::Failed(_))
        ));
        assert_eq!(e.maps.state, before);
        assert_eq!(e.bound_containers()[0].policy_id, 7);
    }

    #[test]
    fn protected_cgroups_cannot_be_bound() {
        let mut e = engine(resolver());
        e.set_protected_cgroups(vec![
            PathBuf::from("system.slice/vesta-guestd.service"),
            PathBuf::from("system.slice/kata-agent.service"),
        ]);
        for p in [
            "/system.slice",
            "/system.slice/kata-agent.service",
            "system.slice:vesta-guestd:x",
        ] {
            let mut b = bind("c1", 0, 0);
            b.cgroup_path = p.into();
            if p.contains(':') {
                // Maps to system.slice/vesta-guestd-x.scope: a sibling, allowed.
                assert!(e.bind_prepare(&b).is_ok(), "{p}");
            } else {
                assert!(e.bind_prepare(&b).is_err(), "{p}");
            }
        }
        let mut b = bind("c2", 0, 0);
        b.cgroup_path = "::".into();
        assert!(
            e.bind_prepare(&b).is_ok(),
            "kata-agent's default container scope"
        );
    }
}
