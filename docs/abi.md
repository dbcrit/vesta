---
title: BPF ABI
parent: Reference
nav_order: 4
---

# vesta BPF ABI (version 1)

The source of truth is [`bpf/include/vesta_abi.h`]({{ site.vesta_repo_url }}/blob/main/bpf/include/vesta_abi.h). This page explains that header. BPF programs and vesta-guestd share the ABI, and guestd mirrors it with `#[repr(C)]`. Nothing in this ABI crosses to the host: guestd converts records to `vesta.event.v1.Event`.

## Rules

- Only fixed-width integer types are used, in guest byte order. The exceptions are fields typed `__be16` and the `addr`/`daddr` byte arrays, which are network order.
- Every struct is explicitly padded. Padding is in `_padN` fields, and writers must zero it, because hash and LPM keys compare every byte.
- `_Static_assert`s pin sizes and key offsets. `hack/check-abi.sh` builds the header with `-Wpadded -Werror` for x86_64, aarch64 and `bpf`.
- **`VESTA_ABI_VERSION` = 1.** Any layout change bumps it and needs a new guest image. guestd refuses to load objects whose `.rodata` ABI version differs from its own, and reports `abi_version` in `HelloReply`. Map values do **not** carry a per-value schema version (a deviation from ARCHITECTURE §2.4's sketch). The single version in `config` and in the objects is enough, because layouts only change together with the image.
- `dev` values use the kernel's internal `s_dev` encoding, `(major << 20) | minor`. That is **not** `stat(2)`'s `st_dev`. guestd converts with `major(st_dev) << 20 | minor(st_dev)`.

## Enums

| Enum | Values | Note |
|---|---|---|
| `vesta_event_type` | 0 UNSPEC, 1 EXEC, 2 CONNECT, 3-15 reserved (SENDMSG ... TAMPER), 16 `VESTA_EVENT_TYPE_MAX` | Same numbers as `vesta.event.v1.EventType` |
| `vesta_action` | 0 UNSPEC, 1 AUDITED, 2 DENIED, 3 ALLOWED | = `event.v1.Action` |
| `vesta_hook` | 0, 1 SCHED_PROCESS_EXEC, 2 BPRM_CHECK_SECURITY, 3 CGROUP_CONNECT4, 4 CGROUP_CONNECT6 | = `event.v1.Hook` |
| `vesta_mode` | 0 AUDIT, 1 ENFORCE | proto `Mode`: AUDIT=1, ENFORCE=2, UNSPECIFIED→AUDIT |
| `vesta_failure_policy` | 0 OPEN, 1 CLOSED | proto `FailurePolicy`: OPEN=1, CLOSED=2, UNSPECIFIED→OPEN |
| `vesta_global_mode` | 0 NORMAL, 1 AUDIT_ONLY, 2 DETACHED | proto `GlobalMode`: NORMAL=1, AUDIT_ONLY=2, DETACHED=3, UNSPECIFIED→NORMAL |
| `vesta_verdict` | 0 NONE (treated as allow), 1 ALLOW, 2 DENY | = `channel.v1.Verdict`, `event.v1.RuleVerdict` |
| `vesta_rootfs_type` | 0 UNKNOWN, 1 GUEST_OVERLAY, 2 VIRTIO_FS, 3 BLOCK | = `channel.v1.RootfsType` |

In every ABI enum, zero is the safe value: audit, fail-open, normal, allow.

Event flags (`VESTA_EVF_*`, bit *n* = `event.v1.EventFlag` value *n*+1): PATH_TRUNCATED, ARGV_TRUNCATED, CGROUP_UNBOUND, POLICY_PENDING, WOULD_DENY, GLOBAL_AUDIT_ONLY, EXE_UNLINKED, EXE_OUTSIDE_ROOT. The last two mark exec paths that `d_path()` would decorate: EXE_UNLINKED for an executable with no link left (deleted after open, memfd, `O_TMPFILE`) or a pseudo file, EXE_OUTSIDE_ROOT when the path walk reached the global root without meeting the task's root, so the path is not one the process could open. New flag bits do not change any layout and do not bump `VESTA_ABI_VERSION`.

## Ring buffer records (`events`, RINGBUF, default 4 MiB)

Each record is one fixed-size struct: header plus payload, with no variable-length tail. This keeps `bpf_ringbuf_reserve` sizes constant for the verifier. A consumer must check `hdr.size >= 88` and then `hdr.size == sizeof(record for hdr.type)` before reading the payload. A mismatch is dropped and counted, and must not cause a panic.

`struct vesta_event_header` (88 bytes):

| Off | Field | Type | Meaning |
|---|---|---|---|
| 0 | abi_version | u16 | `VESTA_ABI_VERSION` |
| 2 | type | u16 | `vesta_event_type` |
| 4 | size | u16 | full record size |
| 6 | action | u8 | `vesta_action` |
| 7 | hook | u8 | `vesta_hook` |
| 8 | ktime_boot_ns | u64 | `bpf_ktime_get_boot_ns()` |
| 16 | cgroup_id | u64 | `bpf_get_current_cgroup_id()` |
| 24 | policy_generation | u64 | from `cgroup_policy`, 0 if unbound |
| 32 | pid | u32 | tid |
| 36 | tgid | u32 | |
| 40 | ppid | u32 | `real_parent->tgid` |
| 44 | uid / 48 gid | u32 | effective, init user ns |
| 52 | policy_id | u32 | 0 if unbound |
| 56 | rule_id | u32 | matching rule, 0 if none |
| 60 | flags | u32 | `VESTA_EVF_*` |
| 64 | comm | char[16] | |
| 80 | ns_tgid | u32 | tgid in the task's pid namespace |
| 84 | _pad0 | u32 | |

`struct vesta_exec_event` = header + `vesta_exec_payload` (1304 bytes) = **1392 bytes**:

| Off | Field | Type |
|---|---|---|
| 0 | exe_dev | u32 (s_dev) |
| 4 | argc | u32 (original count) |
| 8 | exe_ino | u64 |
| 16 | path_len | u16 (bytes, excluding NUL) |
| 18 | argv_len | u16 (valid bytes) |
| 20 | _pad0 | u32 |
| 24 | path | char[256], NUL-terminated, truncation sets PATH_TRUNCATED |
| 280 | argv | char[1024], NUL-separated, truncation sets ARGV_TRUNCATED |

guestd must treat `path_len`/`argv_len` as untrusted: clamp them to the array sizes and decode lossily as UTF-8.

`struct vesta_connect_event` = header + `vesta_connect_payload` (32 bytes) = **120 bytes**:

| Off | Field | Type |
|---|---|---|
| 0 | family | u16 (AF_INET 2 / AF_INET6 10) |
| 2 | protocol | u8 (IPPROTO_*) |
| 3 | verdict | u8 (`vesta_verdict` of the matching rule or default) |
| 4 | dport | __be16 |
| 6 | _pad0 | u16 |
| 8 | daddr | u8[16], network order, IPv4 in bytes 0-3 |
| 24 | sock_cookie | u64 |

## Maps

The names are the BPF object names (≤ 15 chars) and the pin names under `/sys/fs/bpf/vesta/maps/`.

| Map | Type | Key | Value | Max entries | Writer |
|---|---|---|---|---|---|
| `config` | ARRAY | u32 0 | `vesta_config` (32 B) | 1 | guestd at boot, then `bpf_map_freeze()` |
| `global_mode` | ARRAY | u32 0 | `vesta_global_mode_value` (8 B) | 1 | guestd (kill switch) |
| `policy_ready` | ARRAY | u32 0 | `vesta_policy_ready_value` (8 B) | 1 | guestd |
| `cgroup_policy` | HASH | u64 cgroup id | `vesta_cgroup_policy` (24 B) | 4096 | guestd |
| `exec_rules` | HASH | `vesta_exec_key` (16 B) | `vesta_rule_value` (8 B) | 65536 | guestd |
| `net_rules_v4` | LPM_TRIE, `BPF_F_NO_PREALLOC` | `vesta_net_key_v4` (16 B) | `vesta_rule_value` | 16384 | guestd |
| `net_rules_v6` | LPM_TRIE, `BPF_F_NO_PREALLOC` | `vesta_net_key_v6` (28 B) | `vesta_rule_value` | 16384 | guestd |
| `events` | RINGBUF | - | records above | 4 MiB | BPF |
| `drop_counters` | PERCPU_ARRAY | u32 event type | u64 | 16 | BPF (failed reserve) |

`vesta_config`: `abi_version`, `flags` (`VESTA_CFG_EXEC_ARGV`), `guestd_cgroup_id`, `guestd_exe_ino`, `guestd_exe_dev`, `heartbeat_interval_ms`.

`vesta_cgroup_policy`: `generation` (u64), `policy_id`, `mode`, `failure`, `rootfs_type`, `flags` (`VESTA_CGF_PENDING`), `exec_default`, `net_default` (`vesta_verdict`), plus padding. guestd copies the per-policy defaults into every bound cgroup, so the BPF fast path does one lookup.

**Net rule keys.** `prefixlen = 64 + CIDR length`. The fixed 64 bits are `policy_id` (32), `protocol` (8), `_pad0` (8) and `port` (16), and are matched exactly. `port` = 0 means any port, and `protocol` = 0 means any protocol. For each rule, guestd inserts one key per (protocol, port) pair. A NetRule with *k* ports becomes *k* keys, or one key with port 0. The program looks up, in order, `(proto, port)`, `(proto, 0)`, `(0, port)`, `(0, 0)`, and the first hit wins. That is at most 4 lookups per family.

## Decision logic (MVP, P2 and N1)

1. `global_mode == DETACHED`: guestd has detached the programs, so nothing runs.
2. Look up `cgroup_policy` for the current cgroup, then for its ancestors (nearest first, up to 15 levels, `bpf_get_current_ancestor_cgroup_id`). The nearest bound cgroup wins and its id is reported in `hdr.cgroup_id`, so a workload cannot leave its policy by creating a child cgroup. No entry on the whole chain: allow, emit nothing from LSM/cgroup programs, set CGROUP_UNBOUND on P1 exec audit events. This covers kata-agent, guestd and systemd. guestd refuses a BindContainer whose cgroup is guestd's own or kata-agent's cgroup or one of their ancestors, so the ancestor lookup cannot put either under a container policy.

   There is no sandbox-wide default entry (a deviation from ARCHITECTURE §2.5): a container cgroup that was never bound is unenforced. `failurePolicy: Closed` is instead enforced on the host, where the NRI start gate refuses to start a container whose bind was not acked (§2.9).
3. Entry has `VESTA_CGF_PENDING`, or `policy_ready == 0`: `failure == CLOSED` yields a DENY verdict, otherwise allow and audit. Both carry POLICY_PENDING. The DENY verdict then goes through step 5 like any other: it is enforced only if `mode == ENFORCE` and `global_mode == NORMAL`, and is reported as AUDITED with WOULD_DENY otherwise.
4. Look up the rule (exec by `(policy_id, dev, ino)`, net by LPM). If there is no rule, use `exec_default`/`net_default`.
5. Verdict DENY: deny only if `mode == ENFORCE` and `global_mode == NORMAL`. Otherwise action is AUDITED with WOULD_DENY, plus GLOBAL_AUDIT_ONLY when the kill switch caused it. An LSM deny returns `-EPERM`, and a cgroup/connect deny returns 0.
6. If `drop_counters[type]` gets incremented because the ringbuf reserve fails, the verdict is still applied. Enforcement never depends on event delivery.
