---
title: Status
nav_order: 8
---

# Implementation status

State of the tree against [ARCHITECTURE.md](ARCHITECTURE.md), as of 2026-09-30. Upstream targets: Kata Containers 4.2.0, containerd 2.4.1, NRI v0.12.3, libbpf 1.7.0 / libbpf-rs 0.27.2, mdlayher/vsock v1.3.0, guest kernel 6.18 LTS (minimum 6.1).

## Roadmap phases (§8)

| Phase | State |
|---|---|
| **0: Decisions + guest foundation** | Mostly built, not run end to end. The kernel fragment merges into Kata 4.2.0's `build-kernel.sh setup` for 6.18.35. The osbuilder recipe, systemd units, `vesta-install` and the RuntimeClass exist. Not done: the ADRs for Q1/Q2/Q5, the upstream Kata issue, a full kernel and rootfs build, and booting the image under QEMU. Boot time and memory deltas are not measured. |
| **1: MVP, audit, QEMU** | Implemented and unit-tested: P1, P2 and N1, the CTRL and EVT channel with handshake, heartbeats and drop counters, cgroup v2 attribution, static policy from a file, the `AuditOnly`/`Detached` kill switch, JSON-lines export, and Prometheus metrics. Not done: the OTLP exporter, the k3s+Kata e2e suite, and the performance budget check. |
| **2: Policy API** | Partial. The NRI start gate, generation acks and the `VestaPolicy` v1alpha1 types (static file only) exist. Not done: CRD controllers and informers, `VestaConfig`, status conditions, rootfs-type detection, and policy hot-reload (a policy change needs an agent restart). |
| **3: Enforce** | Partial. Exec allow/deny and egress CIDR deny in `ENFORCE` mode and `failurePolicy` work, and enforcement survives a guestd kill (pinned links). Not done: drift prevention, P3, S1, S2, self-protection (T programs), load shedding, and the tamper suite. |
| **4, 5** | Not started. |

## Components

- **BPF (`bpf/vesta.bpf.c`).** P1 `tp_btf/sched_process_exec`, P2 `lsm/bprm_check_security`, N1 `cgroup/connect4`/`connect6`. One CO-RE object under "Dual BSD/GPL". All loops are bounded. Exec events carry `EXE_UNLINKED`/`EXE_OUTSIDE_ROOT` where `d_path()` would decorate the path.
- **vesta-guestd (`guest/`).**
  - Startup and programs: load, write and freeze `config`, read adopted state, then attach and pin. Pinned maps and links are reused across restarts.
  - Policy: policy maps with diff-based reconcile.
  - Container binding: `BindContainer` with confined cgroup lookup. A re-bind never unbinds a running container. guestd's and kata-agent's cgroups are protected.
  - Event path: bounded ring buffer consumption, and event seqs persisted per guest boot. The replay buffer is bounded by approximate heap size, not encoded size.
  - Channel: CTRL and EVT over vsock with bounded frames and deadlines.
- **vesta-agent (`host/cmd/vesta-agent`).**
  - NRI and gating: NRI plugin with `StartContainer` gate. Guest writes made from NRI hooks are bounded by the hook's gate context, and sandbox teardown is asynchronous.
  - Guest sessions: per-sandbox sessions with reconnect, and CTRL requests reclaimed on timeout. EVT frames and heartbeats are rate limited per sandbox, and tamper-alert logs are rate limited.
  - Events and metrics: validated, NRI-enriched JSON-lines export. Metrics are served on loopback by default.
- **vesta-install (`host/cmd/vesta-install`).** Installs guest assets with SHA-256 checks and an atomic `current` switch, and generates the runtime config. It writes the containerd drop-in and enables the NRI default validator. If containerd fails to come back after the restart, it restores the previous config. It also labels the node, and has an uninstall mode.
- **Chart (`deploy/helm/vesta`).**
  - Workloads and runtime: DaemonSet with installer init container, RuntimeClass.
  - Access control: RBAC, and a node-label ValidatingAdmissionPolicy.
  - Opt-in modes: an optional ValidatingAdmissionPolicy that requires the NRI required-plugins annotation on vesta pods, and an `uninstall.enabled` node-cleanup mode.

## Deviations from ARCHITECTURE.md

1. **Exec tracepoint:** P1 attaches to `tp_btf/sched_process_exec` rather than `tp/sched/sched_process_exec`, for typed arguments.
2. **Ancestor lookup:** the programs use the nearest bound ancestor cgroup, up to 15 levels ([abi.md](abi.md) step 2). A workload cannot leave its policy by creating a child cgroup.
3. **No sandbox default policy (§2.5).** A never-bound container cgroup is unenforced. `Closed` is enforced by the host start gate instead: a container whose bind is not acked at the requested generation does not start. A bind that is only pending on the guest (its policy generation is not applied) is acked with the applied generation, so the gate treats it as not confirmed. This is documented in §2.5 and abi.md.
4. **Map flags beyond the abi.md table:** `BPF_F_RDONLY_PROG` on the policy maps, and `BPF_F_NO_PREALLOC` on `cgroup_policy` and `exec_rules`. The layouts are unchanged.
5. **Extra BPF state:** non-ABI `.rodata` (`vesta_abi_version`, `audit_unbound_exec`), an unpinned per-CPU scratch map, and a guestd-owned pinned `state/event_seq` map. The BPF programs never read the seq map.
6. **P2 events:** P2 emits only on deny or would-deny, and without argv. P1 audits every exec.
7. **IPv4-mapped destinations:** a `::ffff:a.b.c.d` destination on an IPv6 socket is matched against the IPv4 rules.
8. **Exec record padding:** exec records do not zero the path/argv bytes past `path_len`/`argv_len`. guestd reads only up to the (clamped) lengths.
9. **vmlinux.h source:** vmlinux.h comes from Debian 6.18.9 cloud kernel BTF, because Kata's kernel has no BTF. CO-RE relocates against the guest's BTF at load time.
10. **vsock peer check:** guestd accepts vsock connections only from CID 2 (`allowed_peer_cid`).
11. **Event seq after a guestd restart.** Event seqs are monotonic per guest boot (events.proto), reserved in blocks of 1024 in a pinned map. After a crash the host sees a gap of up to one block; the lost replay buffer makes that gap real. A `Subscribe.from_seq` beyond anything assigned restarts the stream from the oldest buffered event.
12. **Rootfs type:** `BindContainer.rootfs` is always `ROOTFS_TYPE_UNKNOWN`, because snapshotter detection is Phase 2.
13. **Bind ack wait:** `CreateContainer` does not wait for the bind ack; `StartContainer` does. The guest acks only after kata-agent creates the cgroup.
14. **Generation after an agent restart:** the agent's policy generation continues above the guest's applied generation after an agent restart with an older clock.
15. **Uninstall (§2.2):** there is no `preStop` hook and no pre-delete Job. Uninstall is a chart mode (`uninstall.enabled`) that runs `vesta-install uninstall` per node, with extra RBAC granted only in that mode.
16. **NRI plugin registration (§2.9 addition):** NRI skips unregistered plugins. vesta-install enables containerd's NRI default validator. Pods annotated `required-plugins.noderesource.dev/pod: '["vesta"]'` then cannot create containers while the plugin is not registered. The chart can require the annotation (`nri.requirePluginAnnotation`). Unannotated `Closed` pods get an agent warning.
17. **Kernel command line:** no `lsm=` parameter. `CONFIG_LSM` puts `bpf` in the active list, and Kata 4.2's default params already select cgroup v2. The drop-in adds only `lockdown=integrity`.
18. **Capabilities:** guestd has no `CAP_SYS_ADMIN`. Its unit grants `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` and `CAP_DAC_READ_SEARCH`.
19. **Seccomp:** the agent runs under a `Localhost` seccomp profile, which is containerd's default plus `socket(AF_VSOCK)`.
20. **Host paths:** hosts where `/opt` is a symlink are refused, because host writes use `O_NOFOLLOW` on every component.
21. **metricsAddr:** the agent's `metricsAddr` defaults to `127.0.0.1:9464`. The chart binds it to the node IP only when metrics are exposed.
22. **Guest-asserted attributes:** export attributes are not all prefixed `vesta.guest.*`. The docs now list the few host-set attributes; everything else is guest-asserted.

## Open items

- **Guest adoption after a restart:**
  - After a guestd restart, adopted map state keeps enforcing: orphan cgroups and the rules they reference.
  - HelloReply still reports `applied_generation = 0` until the host re-applies, and `Status` does not list orphans.
  - `policy_ready` keeps the old generation meanwhile.
- **Missing guest features:**
  - The process ancestry chain (`Event.chain`) is not filled.
  - BindContainer waits for the cgroup by polling. There is no inotify watch and no `cgroup_mkdir` program.
- **guestd resource use:** the cgroup GC walk is synchronous on guestd's single thread. It now tolerates cgroups vanishing mid-walk, and is bounded to 65536 entries.
- **Builds not done:**
  - No arm64 `vesta-guestd` build (no musl cross toolchain in the builder). The arm64 BPF object builds.
  - The full guest kernel build, the osbuilder rootfs image and the `vesta-install` image have not been built here.
- **Host agent:**
  - Load shedding (§2.2), the OTLP exporter, CRD controllers, `VestaConfig`, and policy hot-reload are not done.
  - No outstanding-request metric for CTRL.
  - `cmd/*`, `httpserver` and `metrics` have no dedicated unit tests.
- **Dependencies and CI:**
  - `google.golang.org/grpc` is v1.84.0, the newest release. Its advisory GO-2026-6443 is fixed only in a v1.85.0 development pseudo-version, and govulncheck reports it as not reachable. `golang.org/x/mod` stays at v0.40.0, because v0.41.0 needs Go 1.26. govulncheck is pinned to v1.1.4, the newest that runs on Go 1.25.
  - Image digests pinned inside shell scripts are not tracked by Dependabot.
  - The new CI steps (`make go-vulncheck`, and `make bpf-smoke` with privileged Docker on the GitHub runner) have not run in GitHub Actions yet.
- **Operations and upstream checks:**
  - `vesta-install` does not stagger containerd restarts across nodes on first install. The chart README documents the blast radius, including the k3s/RKE2 control-plane restart.
  - `SECURITY.md` has placeholder contact details.
  - Upstream API details were checked against the module and crate sources in the local caches (NRI v0.12.3, containerd v2.4.1, libbpf-rs 0.27.2, libbpf-sys 1.7.0). They were not re-fetched from the web in this pass.

## Not verified locally

- **No end-to-end run:** no KVM, so nothing ran inside a Kata 4.2 VM. The pieces that have never run are:
  - the vsock dial;
  - the shim-monitor `/agent-url` discovery;
  - guestd under systemd in the vesta guest image, including its capability set and `SystemCallFilter` in the real guest;
  - kata-agent's cgroup layout and rootfs paths (`/run/kata-containers/<cid>/rootfs`);
  - the systemd D-Bus containerd restart and its rollback on a real node;
  - containerd actually applying the NRI default validator from vesta's drop-in.
- **LSM enforcement in a real guest kernel.** The smoke test (`make bpf-smoke`) loaded, attached and exercised P1, P2 and N1 on the Docker Desktop linuxkit 7.0.12 kernel with the bpf LSM active. It covered exec deny, the kill switch, egress deny, `EXE_UNLINKED`, pin reuse and the event seq map. The test thread held only the guestd unit's four capabilities. It has not run on the vesta 6.18 guest kernel, and not on the 6.1 minimum that §5 requires verifier tests for.
- **Admission policies:** the NRI required-plugin ValidatingAdmissionPolicy was checked with server-side dry runs on a throwaway k3s v1.34.1 container (annotated pods admitted; missing or wrong annotation denied; other RuntimeClasses untouched). The node-label policy was checked in an earlier pass. Neither has run on a real multi-node cluster.
