---
title: BPF programs
parent: Components
nav_order: 4
---

# BPF programs

All vesta BPF code is one CO-RE object built from [`bpf/vesta.bpf.c`]({{ site.vesta_repo_url }}/blob/main/bpf/vesta.bpf.c). It contains three programs: **P1** records every exec, **P2** allows or denies an exec through the BPF LSM, and **N1** (two sections, IPv4 and IPv6) allows or denies outgoing `connect()` calls. The programs read policy from maps that vesta-guestd writes, and write fixed-size records to a ring buffer that guestd drains. This page describes each program, the decision logic, and every map, as the code implements it. The byte-level layouts are in the [BPF ABI](../abi.md) page, whose source of truth is [`bpf/include/vesta_abi.h`]({{ site.vesta_repo_url }}/blob/main/bpf/include/vesta_abi.h).

> **Status:** the programs have been loaded, attached and exercised by the privileged smoke test (`make bpf-smoke`) on the Docker Desktop linuxkit 7.0.12 kernel. They have **not** run on the vesta 6.18 guest kernel or on the 6.1 minimum. See [Implementation status](../IMPLEMENTATION_STATUS.md).

## Programs

| ID | Program name | Section (hook) | Emits | Can deny |
|---|---|---|---|---|
| P1 | `vesta_exec` | `tp_btf/sched_process_exec` | An `EXEC` record for every exec in a bound cgroup (and in unbound cgroups when `audit_unbound_exec` is set) | No |
| P2 | `vesta_bprm_check` | `lsm/bprm_check_security` | An `EXEC` record only for a deny or would-deny verdict | Yes, returns `-EPERM` |
| N1 | `vesta_connect4` | `cgroup/connect4` | A `CONNECT` record for every connect from a bound cgroup | Yes, returns `0` |
| N1 | `vesta_connect6` | `cgroup/connect6` | Same, for IPv6 sockets | Yes, returns `0` |

guestd reports the programs in `HelloReply`, `Status` and heartbeats with the IDs `P1`, `P2`, `N1-connect4` and `N1-connect6`, and derives these feature strings from the programs that are attached: `exec_audit` (P1), `exec_lsm` (P2), `net_egress4`, `net_egress6`.

P1, P2 and the tracing hooks attach through libbpf's automatic attach. The two `cgroup/connect*` programs attach to the **root** of the guest cgroup2 hierarchy (`cgroup_root`, `/sys/fs/cgroup`), so they run for every process in the guest. Whether a connect is decided by a policy is then settled by the binding lookup below.

### P1: exec audit

`tp_btf/sched_process_exec` runs after an exec has succeeded, with typed arguments `(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)`. The design named `tp/sched/sched_process_exec`; `tp_btf` was chosen for the typed arguments (deviation 1 on the status page).

1. If `global_mode` is `DETACHED`, return.
2. Look up the binding (below). If there is none and `audit_unbound_exec` is false, return.
3. Read the executable's `(s_dev, i_ino)` from `bprm->file`.
4. If bound and the policy is pending, set `POLICY_PENDING`. Otherwise look up `exec_rules[(policy_id, dev, ino)]` and copy the matching `rule_id` into the record. P1 never decides: the action is always `AUDITED`.
5. Emit an exec record with hook `SCHED_PROCESS_EXEC`. argv is captured from `mm->arg_start..arg_end` only if `config.flags` has `VESTA_CFG_EXEC_ARGV` (guestd sets it from `capture_argv`, default true).

### P2: exec allow/deny

`lsm/bprm_check_security` runs before the new image is committed.

1. If an earlier LSM already returned an error, return it unchanged.
2. If `global_mode` is `DETACHED`, allow.
3. Look up the binding. Unbound: allow and emit nothing.
4. Read `(s_dev, i_ino)`. If the policy is not pending, look up `exec_rules[(policy_id, dev, ino)]`.
5. Decide with the common logic below, using `exec_default` when no rule matches.
6. If the verdict is not `DENY`, allow and emit nothing. Otherwise emit an exec record (without argv: the new image's argv is not in `mm` yet) and return `-EPERM` only when the decision is an enforced deny.

P2 needs `bpf` in the active LSM list. guestd does not even try to load it when `/sys/kernel/security/lsm` lacks `bpf`, and reports it as `FAILED` with that reason.

### N1: egress connect

`cgroup/connect4` and `cgroup/connect6` share `handle_connect`.

1. If `global_mode` is `DETACHED`, allow (return 1).
2. Look up the binding. Unbound: allow and emit nothing.
3. Read `protocol`, `user_port` (network order) and the destination address. On an IPv6 socket, a `::ffff:a.b.c.d` destination is looked up against the **IPv4** rules (deviation 7).
4. If not pending, look up the LPM trie for the family, trying `(proto, port)`, `(proto, any)`, `(any, port)`, `(any, any)` in that order. The first hit wins. That is at most four lookups.
5. Decide with the common logic, using `net_default` when nothing matches.
6. Emit a connect record for every connect from a bound cgroup, carrying the matched verdict and `bpf_get_socket_cookie()`. Return 0 (the kernel then fails `connect()` with `EPERM`) only for an enforced deny, else 1.

## Binding lookup

Every program first finds the `cgroup_policy` entry that applies to the current task (`lookup_binding`):

1. Look up the task's own cgroup id (`bpf_get_current_cgroup_id()`).
2. If there is no entry, walk the ancestors from level 15 down to level 1 with `bpf_get_current_ancestor_cgroup_id(level)`, skipping levels that do not exist or equal the task's own cgroup. The **nearest** bound ancestor wins. The root (level 0) is never consulted. `MAX_CGROUP_LEVEL` is 16.
3. The record's `cgroup_id` is the **bound** cgroup's id, not the task's own.

This means a workload cannot leave its policy by creating a child cgroup, and kata-agent's per-container `init` sub-cgroup inherits the container's policy (deviation 2). guestd refuses a bind that would cover its own cgroup or kata-agent's (see [vesta-guestd](vesta-guestd.md#bind-lifecycle)), so the ancestor walk cannot put either under a container policy. Tasks with no bound cgroup on their chain (systemd, kata-agent, guestd) are never decided on.

## Decision logic

`is_pending(cgp)` is true when the entry has `VESTA_CGF_PENDING` or `policy_ready` is 0. `decide()` then works as follows:

| Situation | Verdict | Flags set |
|---|---|---|
| Pending, `failure == CLOSED` | `DENY` | `POLICY_PENDING` |
| Pending, `failure == OPEN` | `NONE` (allow) | `POLICY_PENDING` |
| Not pending, rule matched | the rule's verdict, `rule_id` recorded | |
| Not pending, no rule | `exec_default` or `net_default` | |

A `DENY` verdict becomes an enforced deny only when the binding's `mode` is `ENFORCE` **and** `global_mode` is `NORMAL`:

| Verdict | `mode` | `global_mode` | Action in record | Extra flags | Return |
|---|---|---|---|---|---|
| `DENY` | ENFORCE | NORMAL | `DENIED` | | P2 `-EPERM`, N1 `0` |
| `DENY` | ENFORCE | AUDIT_ONLY | `AUDITED` | `WOULD_DENY`, `GLOBAL_AUDIT_ONLY` | allow |
| `DENY` | AUDIT | any | `AUDITED` | `WOULD_DENY` | allow |
| `ALLOW` or `NONE` | ENFORCE | any | `ALLOWED` | | allow |
| `ALLOW` or `NONE` | AUDIT | any | `AUDITED` | | allow |

In every ABI enum, zero is the safe value: `AUDIT`, `OPEN`, `NORMAL`, `NONE`. A zeroed or missing map value therefore never denies. A pending `Closed` binding is still only enforced in `ENFORCE` mode and `NORMAL` global mode.

### Global mode (kill switch)

`global_mode` is a one-element array that guestd writes on `SetMode`:

| Value | Programs |
|---|---|
| `NORMAL` (0) | Normal operation |
| `AUDIT_ONLY` (1) | Never deny. Deny verdicts are reported as `AUDITED` with `WOULD_DENY` and `GLOBAL_AUDIT_ONLY` |
| `DETACHED` (2) | Every program returns at once and emits nothing. guestd also detaches the programs (unpins and closes their links) after writing the value |

### Failure policy and `policy_ready`

`policy_ready` holds the ApplyPolicy generation guestd last applied, or 0 before any. While it is 0, every bound cgroup is pending and its `failure` field decides. guestd sets `VESTA_CGF_PENDING` on a binding whose requested policy generation is not applied yet, and fills that entry's `mode` and `failure` from its `[baseline]` config (default audit, open).

Enforcement never depends on event delivery: if `bpf_ringbuf_reserve` fails, the program increments `drop_counters[type]` and still applies its verdict.

## Records

Each record is one fixed-size struct, so the reserve size is a constant for the verifier:

| Record | Size | Content |
|---|---|---|
| `vesta_event_header` | 88 bytes | ABI version, type, size, action, hook, `ktime_boot_ns`, bound `cgroup_id`, policy generation, pid/tgid/ppid, euid/egid, `policy_id`, `rule_id`, flags, `comm`, `ns_tgid` |
| `vesta_exec_event` | 1392 bytes | Header plus exe `dev`/`ino`, original `argc`, `path[256]`, `argv[1024]` |
| `vesta_connect_event` | 120 bytes | Header plus family, protocol, matched verdict, `dport`, `daddr[16]`, socket cookie |

Unbound records (P1 with `audit_unbound_exec`) carry `CGROUP_UNBOUND` and zero `policy_id`/generation.

**Exe path.** `bpf_d_path()` is not available to `tp_btf` programs, so `read_exe_path` rebuilds the path by walking dentries and mount points relative to the task's root, bounded by 32 components and a 1 KiB per-CPU scratch buffer. It keeps the deepest components and sets `PATH_TRUNCATED` when the path does not fit in 255 bytes. Where `d_path()` would decorate the path, flags are set instead:

- `EXE_UNLINKED`: the file has no link left (deleted after open, `memfd`, `O_TMPFILE`) or is a pseudo file whose dentry is its own parent;
- `EXE_OUTSIDE_ROOT`: the walk reached the global root (or a detached mount) without meeting the task's root, so the path is not one the process could open.

**argv.** Read from user memory `mm->arg_start..arg_end`, capped at 1024 bytes with `ARGV_TRUNCATED` on overflow. Only P1 reads argv.

**Padding.** Exec records zero the header and scalar fields but not the `path`/`argv` bytes past `path_len`/`argv_len` (1392 bytes is too large to `memset` inline). Readers must bound the arrays by the lengths, which guestd clamps (deviation 8). Connect records are zeroed in full.

## Maps

The first nine maps are the ABI. guestd pins them under `/sys/fs/bpf/vesta/maps/<name>`.

| Map | Type | Key | Value | Max entries | Flags | Writer |
|---|---|---|---|---|---|---|
| `config` | ARRAY | `u32` 0 | `vesta_config` (32 B) | 1 | `BPF_F_RDONLY_PROG` | guestd once at load, then `bpf_map_freeze()` |
| `global_mode` | ARRAY | `u32` 0 | `vesta_global_mode_value` (8 B) | 1 | `BPF_F_RDONLY_PROG` | guestd (`SetMode`) |
| `policy_ready` | ARRAY | `u32` 0 | `vesta_policy_ready_value` (8 B) | 1 | `BPF_F_RDONLY_PROG` | guestd (after each ApplyPolicy) |
| `cgroup_policy` | HASH | `u64` cgroup id | `vesta_cgroup_policy` (24 B) | 4096 | `BPF_F_RDONLY_PROG`, `BPF_F_NO_PREALLOC` | guestd (bind, unbind, apply, GC) |
| `exec_rules` | HASH | `vesta_exec_key` (16 B): `policy_id`, `dev`, `ino` | `vesta_rule_value` (8 B) | 65536 | `BPF_F_RDONLY_PROG`, `BPF_F_NO_PREALLOC` | guestd |
| `net_rules_v4` | LPM_TRIE | `vesta_net_key_v4` (16 B) | `vesta_rule_value` | 16384 | `BPF_F_RDONLY_PROG`, `BPF_F_NO_PREALLOC` | guestd |
| `net_rules_v6` | LPM_TRIE | `vesta_net_key_v6` (28 B) | `vesta_rule_value` | 16384 | `BPF_F_RDONLY_PROG`, `BPF_F_NO_PREALLOC` | guestd |
| `events` | RINGBUF | | records above | 4 MiB default | | BPF programs |
| `drop_counters` | PERCPU_ARRAY | `u32` event type | `u64` | 16 | | BPF programs (failed reserve) |

Notes:

- `BPF_F_RDONLY_PROG` on the policy maps and `BPF_F_NO_PREALLOC` on the hash maps go beyond the ABI table in the design (deviation 4). The layouts are unchanged. The programs cannot write any policy map.
- guestd sizes `events` from its `ringbuf_bytes` setting (a power of two, at least the page size, at most 256 MiB) before load.
- `cgroup_policy` values carry the per-policy `mode`, `failure`, `exec_default` and `net_default`, copied by guestd into every bound cgroup so the fast path does one lookup.
- **Net rule keys.** `prefixlen = 64 + CIDR length`. The fixed 64 bits are `policy_id` (32), `protocol` (8), padding (8) and `port` (16), matched exactly. `port` 0 means any port and `protocol` 0 means any protocol. A rule with *k* ports becomes *k* keys, or one key with port 0.
- `dev` values use the kernel's internal `s_dev` encoding, `(major << 20) | minor`, not `stat(2)`'s `st_dev`. guestd converts.

### Non-ABI state

| Item | Kind | Purpose |
|---|---|---|
| `vesta_abi_version` | `.rodata` `const volatile u32` | Set to `VESTA_ABI_VERSION` (1). guestd refuses an object whose value differs from its own. |
| `audit_unbound_exec` | `.rodata` `const volatile bool` | Set by guestd before load from its config (default false). |
| `path_scratch` | PERCPU_ARRAY, 1 entry of 1 KiB | Scratch buffer for the exe path walk. Not pinned. |
| `state/event_seq` | ARRAY (1 x `u64`), created by guestd | Highest reserved event seq, pinned at `/sys/fs/bpf/vesta/state/event_seq`. Not part of the object and never read by the programs. |

## Build, CO-RE and kernel requirements

- **Build.** `make bpf` runs `make -C bpf check` in the builder image (`guest/Dockerfile.build`: clang 21, libbpf 1.7.0 headers, bpftool). Flags: `-g -O2 -target bpf -mcpu=v3 -std=gnu11 -Wall -Wextra -Werror`. It produces `bpf/.output/x86_64/vesta.bpf.o` and `bpf/.output/arm64/vesta.bpf.o`, strips DWARF with `llvm-strip -g`, and `check` verifies that the BTF parses and all four program sections exist. vesta-guestd's `build.rs` compiles the same source with the same flags into its libbpf-rs skeleton, so the object guestd loads is **embedded in the guestd binary**.
- **CO-RE.** Every kernel structure read goes through `BPF_CORE_READ` or `bpf_core_field_offset` (for `struct mount`). The types come from `bpf/vmlinux/<arch>/vmlinux.h`, generated from the BTF of Debian's signed `linux-image-6.18.9+deb13-cloud-{amd64,arm64}-unsigned` packages (version `6.18.9-1~bpo13+1`) with `bpf/scripts/gen-vmlinux.sh` and `btf-carve.py`. Kata's stock kernel is not used because it has no BTF. At load time libbpf relocates against the running guest kernel's `/sys/kernel/btf/vmlinux`, which the vesta kernel provides (`CONFIG_DEBUG_INFO_BTF=y`). Provenance and hashes are in [`bpf/include/README.md`]({{ site.vesta_repo_url }}/blob/main/bpf/include/README.md).
- **Name clash.** 6.18's BTF contains `typedef struct config_s config`, which clashes with the ABI map `config`, so `vesta.bpf.c` renames that typedef while including `vmlinux.h`.
- **Verifier.** All loops are bounded (16 cgroup levels, 32 path components, 4 LPM lookups). Helpers used were checked against the v6.1 and v6.18 helper tables.
- **License.** The source is `GPL-2.0-only OR BSD-2-Clause`, and the object declares `char LICENSE[] SEC("license") = "Dual BSD/GPL"`, which the GPL-only helpers require.
- **Kernel requirements.** Linux 6.1 or newer (6.18 LTS is the target) with `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`, `CONFIG_BPF_LSM`, `bpf` in the active LSM list (for P2), `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_EVENTS`, and cgroup v2 mounted at `/sys/fs/cgroup`. The vesta kernel fragment sets these; see [Guest image](guest-image.md#kernel-config-fragment).

## Related pages

- [BPF ABI](../abi.md): struct offsets, enum values and the full decision steps.
- [vesta-guestd](vesta-guestd.md): how the object is loaded, pinned and fed.
- [Implementation status](../IMPLEMENTATION_STATUS.md): deviations 1, 2, 4 to 9 concern these programs.
