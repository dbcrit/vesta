# bpf/

BPF programs in C, CO-RE, licensed `GPL-2.0-only OR BSD-2-Clause` (`char LICENSE[] SEC("license") = "Dual BSD/GPL";`).

**Owner:** the BPF implementer. Built in Docker with clang 21, libbpf 1.7.0 headers and bpftool. The image is `guest/Dockerfile.build`.

| File | What it is |
|---|---|
| `include/vesta_abi.h` | Kernel/userspace contract, documented in [docs/abi.md](../docs/abi.md). `hack/check-abi.sh` compile-checks it. |
| `vesta.bpf.c` | All MVP programs and maps, in one object |
| `vmlinux/<arch>/vmlinux.h` | CO-RE types for `x86_64` and `arm64`. Provenance and regeneration are in [include/README.md](include/README.md). |
| `scripts/gen-vmlinux.sh`, `scripts/btf-carve.py` | Regenerate `vmlinux.h` |
| `Makefile` | `make -C bpf` builds `.output/<arch>/vesta.bpf.o`; `make -C bpf check` also checks BTF and program sections |

```sh
guest/hack/in-builder.sh make -C bpf check
```

vesta-guestd's `build.rs` compiles the same source with the same flags into its libbpf-rs skeleton.

## Programs (ARCHITECTURE §2.4, phase 1)

| ID | SEC | Behaviour |
|---|---|---|
| P1 | `tp_btf/sched_process_exec` | Exec audit (AUDITED). The exe path is rebuilt by a bounded dentry/mount walk relative to the task's root, because `bpf_d_path` is not allowed in tracing programs. argv comes from `mm->arg_start..arg_end` when `config.flags & VESTA_CFG_EXEC_ARGV` is set. `rule_id` is filled from `exec_rules`. It never denies. |
| P2 | `lsm/bprm_check_security` | Exec decision by `(policy_id, s_dev, ino)` (docs/abi.md, steps 3-5). Emits an event only for a deny or would-deny. Returns `-EPERM` only for ENFORCE policies while `global_mode == NORMAL`. |
| N1 | `cgroup/connect4`, `cgroup/connect6` | Egress decision through the LPM lookup order (proto, port) → (proto, 0) → (0, port) → (0, 0). `::ffff:a.b.c.d` on a dual-stack socket is looked up against the IPv4 rules. Emits an event for every connect from a bound cgroup. Returns 0 (EPERM) only when enforcing. |

Common rules:

- **Binding lookup.** The binding comes from the task's own cgroup, or else from the nearest bound ancestor, searching up to 15 levels. A workload cannot escape its policy by creating a child cgroup, and neither can kata-agent's `init` sub-cgroup. `hdr.cgroup_id` is the **bound** cgroup's id.
- **Unbound cgroups** allow and emit nothing. P1 emits for them only when guestd sets `.rodata audit_unbound_exec`.
- **`global_mode`.** `DETACHED` makes every program a no-op. `AUDIT_ONLY` never denies.
- **Pending policy.** When `policy_ready == 0` or `VESTA_CGF_PENDING` is set, the binding's `failure` decides. The deny is still gated on ENFORCE mode and NORMAL global mode.
- **Ring buffer.** A failed ringbuf reserve increments `drop_counters[type]`. The verdict is applied regardless.
- **Map flags.** Policy maps are `BPF_F_RDONLY_PROG`. The hash maps are `BPF_F_NO_PREALLOC`, so memory scales with the rules. Record layouts are unchanged.
- **Internal map.** `path_scratch` (per-CPU, 1 KiB) is not part of the ABI and is not pinned.

Loops are bounded. Every kernel read is CO-RE (`BPF_CORE_READ`, `bpf_core_field_offset` for `struct mount`). Helpers were checked against v6.1 and v6.18 (`sock_addr_func_proto`, `cgroup_current_func_proto`, `bpf_tracing_func_proto`, `bpf_base_func_proto`).
