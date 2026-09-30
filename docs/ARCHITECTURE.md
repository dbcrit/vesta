---
title: Architecture
parent: Design
nav_order: 1
---

# vesta: eBPF Security Monitoring and Enforcement for Kata Containers Guest Kernels

Status: design draft, v0.3. Upstream facts re-checked against Kata 4.2.0, containerd 2.4.1 and NRI v0.12.3 in [docs/compat/kata-4.2.md](compat/kata-4.2.md). The shared contract (protobuf in `api/proto`, BPF ABI in [docs/abi.md](abi.md)) is laid down. Components are not implemented yet.
Audience: engineers building and reviewing vesta.

vesta takes the approach of Ant Group's AntCWPP: load eBPF programs into the **guest kernel** of each Kata Containers pod rather than the host kernel. It then adds its own choices for transport, program lifecycle, threat model and Kubernetes API. This document keeps the two apart:

- **[AntCWPP]** marks something the AntCWPP whitepaper states, with section or page references.
- **[vesta]** marks a vesta design decision. The whitepaper does not specify it.
- **[verify]** marks a claim about upstream Kata, the kernel or other projects that reviewers could not check against live sources. Confirm it before depending on it. See [Open Questions](#9-open-questions).

---

## 1. Scope

### 1.1 Problem

Kata runs each pod in a lightweight VM with its own guest kernel. eBPF tools on the host (Falco, Tetragon, Tracee and similar) attach to the host kernel. From there they see the VMM process (QEMU, Cloud Hypervisor and so on) and virtio traffic. They do not see guest OS semantics: process creation, file access or socket calls made by the workload.

[AntCWPP] The main idea of AntCWPP is to load eBPF programs into the guest kernel of the Kata pod. A node security agent drives them over a channel called "veBPF". Through it the agent loads and unloads programs, modifies maps and collects alert logs (whitepaper sec. 4.2.4, 4.3, 5; pp. 18-20).

vesta is an open-source implementation of that idea. Where the whitepaper says nothing, vesta supplies the missing pieces: transport, guest endpoint, protocol, threat model, API and testing.

### 1.2 In scope

Mode semantics: **audit** records the event and allows the action. **enforce** denies the action and records it. [AntCWPP] Monitoring is the default, and engineers enable interception per application (p. 21). [vesta] vesta follows this: every policy defaults to `mode: Audit`.

| Domain | Capability | Mechanism [vesta] (see §2.4 for the full program table) | Deny possible? | AntCWPP equivalent |
|---|---|---|---|---|
| Process | Exec auditing: resolved path, argv, process chain | `tp/sched/sched_process_exec` | no (audit) | tracepoint `sys_enter_execve` (p. 21) |
| Process | Exec allow/deny list | `lsm/bprm_check_security` | yes | `security_bprm_check` |
| Process | Drift prevention (block binaries not in the image) | `lsm/bprm_check_security` + `lsm/mmap_file` + `lsm/file_mprotect`, gated on rootfs type (§2.6) | yes | overlayfs upper-layer check at exec (p. 26) |
| Process | Allowlist learning (observe a pod, then propose an allowlist) | audit events aggregated on the host | n/a | "allowlist obtained by observing the business Pod" (sec. 6.2) |
| Network | Per-container egress control (5-tuple / CIDR+port) | `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6` | yes | "mainly selected the LSM and TC layer" (pp. 21-22) |
| Network | Inbound control | `lsm/socket_bind`, `lsm/inet_conn_request`, `cgroup_skb/ingress` | yes | LSM + TC |
| Network | DNS auditing (queries and answers) | port 53 payload parse in `cgroup_skb` (or TC), correlated by socket cookie | no (audit) | DNS logged by default with process chain; hook not stated (pp. 19, 25-26) |
| File | Sensitive-file read/write protection | `lsm/file_open`, `lsm/file_permission` | yes | `security_file_open`, `security_inode_permission` |
| File | FIM, ransomware bait files | `lsm/inode_unlink`, `lsm/inode_rename`, `lsm/inode_setattr`, `lsm/path_*` | yes | bait-file monitoring (sec. 6.2) |
| Syscall | ptrace | `lsm/ptrace_access_check`, `lsm/ptrace_traceme` | yes | "prefer LSM, else tracepoint" (p. 24) |
| Syscall | User-namespace creation (unshare/clone) | `lsm/userns_create` (Linux 6.1+) | yes | whitepaper says unshare has no LSM hook (p. 24). **Outdated**, see §1.5 |
| Syscall | mount | `lsm/sb_mount`, `lsm/move_mount` | yes | mount-call auditing (sec. 6.2) |
| Syscall | setuid transitions | `lsm/task_fix_setuid` | yes | - |
| Syscall | `memfd_create`, unshare of non-user namespaces | `tp/syscalls/sys_enter_memfd_create`, `tp/syscalls/sys_enter_unshare` | **no** (audit only; see below) | tracepoints |
| Detection | Reverse shell (socket fd dup'ed onto fd 0/1/2) | `tp/syscalls/sys_enter_dup2`/`dup3` + fd-type check | no (audit) | sec. 6.2 |
| Detection | `LD_PRELOAD` at exec | env scan in `sched_process_exec` | no (audit) | sec. 6.2 |
| Detection | Abnormal SSH sessions (children of sshd) | exec events + process chain | no (audit) | sec. 6.2 |

Notes:

- **No LSM hook** exists for `memfd_create` or for unshare of non-user namespaces. These are audit-only. Fileless execution can still be blocked at `lsm/bprm_check_security` by denying exec when `bprm->file` lives on memfd or anonymous shmem. The other ways to block a syscall are `bpf_override_return` (needs `CONFIG_BPF_KPROBE_OVERRIDE` and the error-injection allowlist), `bpf_send_signal` (racy, kills the task), or a seccomp profile in the OCI spec. vesta does not use any of them in v1.
- Some detections (reverse shell, LD_PRELOAD, SSH, allowlist learning) are **deferred** to Phase 4 or later. They are listed so the event schema accounts for them.
- The Kata guest runs its own `kata-agent`. It appears in the process chain of AntCWPP's sample log (p. 26). Policies are keyed by container cgroup (§2.5), so agent-internal activity in the guest root cgroup does not fall under container policy. Processes started with `kubectl exec` (agent `ExecProcess`) join the container cgroup and **are** subject to it.

### 1.3 Out of scope

- Host-kernel monitoring. Use Falco, Tetragon or Tracee on the host.
- Other sandbox runtimes (gVisor/runsc is a user-space kernel with no eBPF support; firecracker-containerd without Kata). Non-Linux guests.
- Guest kernel integrity and rootkit detection. Defending against a compromised guest kernel (§1.4).
- DPI and L7 parsing beyond DNS. DoH, DoT, and DNS on non-standard ports.
- FQDN-based egress allowlists (these need a resolver cache; revisit after DNS auditing).
- A management UI or console. [AntCWPP] has a Policy Service Center and an Asset Management Console. vesta exposes CRDs, status, metrics and event export only.
- **Confidential Containers (CoCo) / TEE pods in v1.** The host agent must skip sandboxes whose RuntimeClass is a CoCo class. A CoCo design sketch is in §1.4.3 and Phase 5.

### 1.4 Threat model and trust boundaries [vesta]

The whitepaper does not discuss a threat model. This section is entirely vesta's.

#### 1.4.1 Actors and boundaries

```
  +--------------------+      +------------------------+      +----------------------------------+
  | Control plane      |  B3  | Host node              |  B2  | Kata guest VM                    |
  | kube-apiserver,    |<---->| vesta-agent, containerd|<====>| vesta-guestd, kata-agent         |
  | CRDs, RBAC         |      | kata shim, VMM         | vsock|  +----------+  +----------+      |
  +--------------------+      +------------------------+      |  |container |  |container | B1   |
                                                              |  +----------+  +----------+      |
                                                              |  ------------ guest kernel ----- |
                                                              +----------------------------------+
  B1: container <-> guest kernel / guest root   (the boundary vesta enforces)
  B2: guest <-> host over vsock                 (vesta adds a new channel here)
  B3: host agent <-> API server                 (standard k8s RBAC)
```

Actors:

- **A1: untrusted workload.** It may get code execution in a container and may escalate to root in the guest.
- **A2: host/node operator and host agent.** Trusted in standard Kata. **Untrusted in CoCo.**
- **A3: control plane / policy authors.** Trusted, and constrained by RBAC.

Goals:

- **G1.** Workload actions covered by policy are audited or denied inside the guest kernel.
- **G2.** Root in the guest cannot *silently* disable enforcement. At minimum the host detects tampering within a bounded time (heartbeat interval × 2).
- **G3.** The vesta channel does not weaken VM isolation. A malicious guest cannot use it to affect the host or other sandboxes beyond its own sandbox's vesta state.
- **G4.** (CoCo mode, Phase 5 only.) The host cannot inject code into the guest or read confidential event content.

Non-goals:

- Surviving a guest kernel exploit. After kernel code execution, vesta can at best be tamper-*evident*.
- Defending against a malicious hypervisor outside CoCo.

Guest-kernel enforcement is weaker than host enforcement in one respect: it runs in the same kernel as the attacker. It is stronger in another: it has full guest OS semantics. Keep coarse host-side controls (network policy on the host, resource limits) as defense in depth.

#### 1.4.2 Tamper resistance inside the guest (A1 gets guest root)

1. **Container defaults.** Deny `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_MODULE` and `CAP_SYS_PTRACE` to workloads, or alert on pods that request them. Do not mount bpffs, `/sys/kernel/security` or tracefs into containers. Set `kernel.unprivileged_bpf_disabled=2` (`CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`). Do not delegate BPF tokens (6.9+) to workload mounts.
2. **BPF LSM self-protection.** Programs in the Phase 3 program table (§2.4, group T):
   - `lsm/bpf` denies `BPF_PROG_LOAD`, `BPF_LINK_DETACH`, `BPF_PROG_DETACH`, and `BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` on vesta maps, plus `BPF_OBJ_GET` on vesta pins. It denies them for every task except vesta-guestd. The daemon is identified by its cgroup id and exe (dev, ino), recorded at first load.
   - `lsm/bpf_map` and `lsm/bpf_prog` gate FD acquisition.
   - `lsm/task_kill` and `lsm/ptrace_access_check` protect the daemon.
   - `lsm/inode_unlink` and `lsm/sb_umount` protect the pins under `/sys/fs/bpf/vesta`.
   - `lsm/kernel_module_request` and `lsm/kernel_read_file` block module loading. Better still, build with `CONFIG_MODULES=n` or set `kernel.modules_disabled=1` after boot. Also block `kexec_load` and `/dev/mem`.
3. **Attachment survives the daemon.** Programs attach through `bpf_link`s pinned in bpffs. Killing vesta-guestd does not detach enforcement.
4. **Read-only static maps.** Use `BPF_F_RDONLY_PROG` and `bpf_map_freeze()` on configuration that does not change after load. Mutable policy maps are guarded by `lsm/bpf`.
5. **Lockdown.** Boot with `lockdown=integrity`, which blocks `bpf_probe_write_user`, `/dev/mem` and unsigned kexec. `bpf_probe_read_kernel` is blocked only in `confidentiality` mode, which vesta does not use.
6. **Host-side tamper evidence.** vesta-guestd sends a heartbeat (§2.3.3) with program IDs and tags, link IDs, policy generation hash, sequence number and drop counters. The host alerts on a missing heartbeat, a tag or link mismatch, or a sequence gap.

This is tamper-evident, not tamper-proof. A guest kernel exploit defeats all of it.

#### 1.4.3 Host-side hardening (G3)

- Treat every guest message as untrusted input. Use strict length-prefixed framing, a protobuf schema, a maximum message size (1 MiB), per-sandbox rate limits and bounded queues. Parse defensively.
- Guest data never selects host actions. The host agent never runs commands, opens paths or makes API calls based on guest-supplied strings.
- Use one connection per sandbox. A guest can affect only its own sandbox's state and metrics. A flooding guest gets rate-limited and dropped, with counted drops and an alert. It must not starve other sandboxes or the node agent.
- The host agent runs with least privilege. It needs access to the Kata sandbox vsock (the AF_VSOCK CID or the hybrid-vsock UDS), the shim management sockets (`/run/kata`, `/run/vc/sbs`) and the NRI socket. It never passes guest-supplied strings to these paths: the sandbox ID comes from NRI and is validated before any path is built. It does **not** need `CAP_BPF` on the host.
- Events from the guest are labeled *guest-asserted* in the schema (§2.7). Host enrichment (pod, namespace, image) comes only from CRI/NRI and the API server.

#### 1.4.4 Confidential Containers (deferred; Phase 5)

In CoCo the host is untrusted. Pushing code from host to guest is exactly what CoCo forbids. Kata agent policy (Rego generated by genpolicy, evaluated in kata-agent with regorus) denies unknown RPCs. genpolicy's `rules.rego` defaults `ExecProcessRequest` and `CopyFileRequest` to false and allows only requests that match generated rules (`src/tools/genpolicy/rules.rego`, Kata 4.2.0). A CoCo mode would require all of the following:

1. vesta-guestd and the BPF objects are part of the **measured guest image**, so attestation covers them. This is already the baseline design (§2.2).
2. Policy comes from the **tenant**: signed with a tenant key that is verified in the guest, or fetched through CDH/KBS. It does not come from the host agent.
3. Events may contain tenant data (argv, paths, IPs). They are encrypted to a tenant-controlled sink or redacted before they cross to the host.
4. A new vesta vsock listener is a host-reachable API that **Kata agent policy does not cover**, because that policy only evaluates kata-agent ttRPC requests. vesta must either route through kata-agent (new RPCs plus policy rules, which needs upstream agreement) or authenticate every message on its own port.

### 1.5 Whitepaper claims vesta does not adopt

| Whitepaper claim | Correction |
|---|---|
| "In Linux kernel 4.15, LSM began supporting eBPF" (p. 12) | BPF LSM (KRSI, `BPF_PROG_TYPE_LSM`) merged in **5.7** (commit fc611f47f218). |
| unshare has no LSM hook (p. 24) | `userns_create` exists since **6.1** and covers user-namespace creation via unshare/clone. Other namespace types still have no hook. |
| `security_bprm_execve` (sec. 7.3, p. 30) | Not an LSM hook. `bprm_execve` is an exec-path function. Use `bprm_check_security` or `bprm_creds_for_exec`. |
| LSM hooks named `security_*` | Those are the kernel's wrapper functions (`security/security.c`). BPF attaches by hook name from `include/linux/lsm_hook_defs.h`, e.g. `SEC("lsm/bprm_check_security")`. |

The whitepaper publishes **no performance numbers**. It makes only qualitative statements, such as that a tracepoint for exec audit "reduces performance overhead" and that inode maps avoid path-processing cost. Any number vesta quotes must come from its own benchmarks (§5).

---

## 2. Architecture

### 2.1 Overview

```
 Kubernetes control plane
 +-----------------------------------------------------------------------------+
 | kube-apiserver: VestaPolicy / ClusterVestaPolicy (CRD), VestaConfig         |
 |                 (kill switch, defaults), RuntimeClass, Pods                 |
 +--------------------------------------+--------------------------------------+
                                        | informers (watch), status patches
 Host node                              v
 +-----------------------------------------------------------------------------+
 | vesta-agent (DaemonSet, Go)                                                 |
 |   policy compiler    sandbox registry     NRI plugin (synchronous gate)     |
 |   channel Dialer (vhost-vsock | hybrid-vsock UDS)                           |
 |   event pipeline -> JSON lines / OTLP;  Prometheus metrics                  |
 |        ^ NRI                                                                |
 |   containerd --CRI--> containerd-shim-kata-v2 --> VMM (QEMU / CLH / ...)    |
 +------------+----------------------------------------+-----------------------+
              | vsock 1024: ttRPC (kata-agent, stock)  | vsock CTRL + EVT ports (vesta)
 ============ | ============= VM boundary ============ | =======================
 Kata guest   v                                        v
 +-----------------------------------------------------------------------------+
 | guest userspace (measured/baked guest image)                                |
 |   kata-agent                              vesta-guestd (Rust, libbpf-rs)    |
 |    - creates container cgroups (v2)        - loads baked-in BPF objects at  |
 |    - runs containers (rustjail)              boot, pins links + maps        |
 |                                            - writes policy maps (from host) |
 |   +-----------+  +-----------+  +-------+  - binds cgroup_id -> policy      |
 |   | container |  | container |  | pause |  - drains ringbuf -> EVT stream  |
 |   +-----------+  +-----------+  +-------+  - heartbeat, self-status         |
 |-----------------------------------------------------------------------------|
 | guest kernel (Kata kernel + vesta config fragment, lsm=...,bpf)             |
 |   BPF LSM progs | cgroup progs (connect/sendmsg/skb) | tracepoints | TC opt |
 |   maps: cgroup_policy, exec_rules, net_rules, file_rules, config,           |
 |         policy_ready, ringbuf, drop_counters                                |
 +-----------------------------------------------------------------------------+
```

The main difference from the draft is that **something in guest userspace must call `bpf()`**. A host process cannot load or attach programs in the guest kernel. Remote `bpf()` is not workable, for these reasons:

- `bpf_attr` carries user pointers (instructions, BTF, log buffers, map keys).
- FDs are local to the calling guest process.
- CO-RE relocation happens in userspace against the running kernel's BTF, before `BPF_PROG_LOAD`.
- The verifier runs in the guest regardless.

vesta therefore has a guest-side daemon, **vesta-guestd**. The channel carries high-level operations. It does not carry syscalls.

### 2.2 Components

#### Control plane [vesta]

- **CRDs.** `VestaPolicy` (namespaced) and `ClusterVestaPolicy` (§2.8).
- **VestaConfig.** A cluster singleton holding the global **degradation / kill switch** (`Normal | AuditOnly | Detached`), defaults, and the export sink. [AntCWPP] keeps a cluster-wide degradation switch and agent config in ConfigMaps (sec. 4.1, 4.2.3). Whether vesta uses a CR or a ConfigMap is an open question.
- **Staged rollout with approval.** [AntCWPP] pre-checks, then staged delivery with manual confirmation (sec. 4.2). [vesta] This arrives in Phase 5 as `spec.rollout` plus an approval condition. It is not in the MVP.

#### Host: vesta-agent (DaemonSet, Go) [vesta unless marked]

| Subcomponent | Responsibility |
|---|---|
| Deployment scope | A separate DaemonSet scheduled **only on Kata nodes**, via a `nodeSelector`/node affinity on the label kata-deploy sets (`katacontainers.io/kata-runtime=true`, confirmed in [compat](compat/kata-4.2.md) §5); the same label is used by the Kata RuntimeClasses' `scheduling.nodeSelector`. Non-Kata nodes run no vesta pod. The label is configurable in the Helm chart for clusters that install Kata another way. The DaemonSet's `vesta-install` init container installs the vesta guest runtime on the node ("Guest image distribution" below). |
| Policy watcher | Informers on VestaPolicy, ClusterVestaPolicy, VestaConfig, Pods and RuntimeClass. [AntCWPP] Informer-based policy watch (sec. 4.2.1). |
| Kata pod identification | NRI reports the runtime handler directly (`PodSandbox.runtime_handler`, [compat](compat/kata-4.2.md) §6). vesta acts only on its own handler (`kata-qemu-vesta`) and returns immediately for every other pod. The RuntimeClass informer is still used for policy status and eligibility. CoCo handlers are skipped in v1. |
| NRI plugin | Replaces the draft's "Pod Lifecycle Monitor (containerd events)". NRI `RunPodSandbox`, `CreateContainer` and `StartContainer` hooks are synchronous, so vesta can gate container start on the policy ack (§2.9). Async containerd events cannot give that ordering. There are two constraints: the default plugin request timeout is 2 s, and the NRI adaptation serializes all plugin calls node-wide. vesta therefore bounds every wait (default 1500 ms) ([compat](compat/kata-4.2.md) §6). [AntCWPP] used containerd events. |
| Sandbox registry | sandbox ID → vsock endpoint. It is discovered with `GET /agent-url` on the shim management socket: `/run/kata/<sid>/shim-monitor.sock` (runtime-rs) or `/run/vc/sbs/<sid>/shim-monitor.sock` (Go runtime). The plain-text reply is `vsock://<cid>:1024` or `hvsock://<uds>:1024`. vesta uses the CID or UDS and its own port ([compat](compat/kata-4.2.md) §2). |
| Channel Dialer | An interface with two implementations. **vhost-vsock** (QEMU): host AF_VSOCK to the guest CID. **Hybrid vsock** (Cloud Hypervisor, Firecracker, Dragonball): connect to the per-sandbox UDS, send `CONNECT <port>\n` and require a reply line starting `OK ` ([compat](compat/kata-4.2.md) §2). The guest side is AF_VSOCK in both cases. |
| Policy compiler | CRD → typed, versioned map entries per container (resolving selectors and containerSelector). Pure function, unit tested. |
| Eligibility pre-check | Per sandbox: guest image version, protocol version, `bpf` present in active LSMs, cgroup v2, rootfs type per container, kernel release. Policies bind only to eligible sandboxes. The result is reported in policy status. [AntCWPP] reports per-pod eligibility, and the platform delivers only to eligible apps (sec. 4.2.1). |
| Heartbeat / asset tracking | Tracks guest heartbeats. Reports cluster/node/pod/kernel version/active policies. Alerts on missing heartbeats and policy anomalies (applied generation ≠ desired). [AntCWPP] heartbeat, asset reporting including "Kata pod kernel version", and a platform-side policy anomaly check (sec. 4.2.3, 4.3). |
| Load shedding / offload | Degrades a sandbox to audit-only or detaches noisy audit programs when guest-reported overhead exceeds its budget. It **never auto-offloads `failurePolicy: Closed` enforcement**, because otherwise an attacker could generate load to switch enforcement off. [AntCWPP] offloads policies per pod based on resource utilization, with node- and cluster-level degrade (sec. 4.2.3). |
| Event pipeline | Validates and bounds guest events, enriches them from CRI/NRI and the API server, exports JSON lines and OTLP logs, exposes Prometheus metrics (§2.7). |

#### Channel [vesta] (AntCWPP calls it "veBPF")

[AntCWPP] veBPF is the channel between the node security agent and the Kata pod. It is used to load and unload programs, modify maps and collect event and alert logs (sec. 4.2.4, 4.3, 5). "Kata Pods expose eBPF operation interfaces to the host." The whitepaper does **not** specify the transport, the wire protocol, or whether the guest endpoint is kata-agent or a separate daemon.

[vesta] The transport is vsock only. **virtio-serial is not an option**: Kata 2.0 removed the kata-proxy/virtio-serial path. The protocol is specified in §2.3.

#### Guest: vesta-guestd [vesta]

The guest endpoint options were:

| Option | Pros | Cons |
|---|---|---|
| A. New kata-agent RPCs (`LoadBpfObject`, `UpdateMap`, ...) in `agent.proto` | Always present. In CoCo it is measured with the agent, and agent policy can govern it. | Needs upstream buy-in and agent-policy rules. Enlarges the agent. Upstream kata-agent has no eBPF RPC (checked in Kata 4.2.0 `agent.proto`). |
| **B. Separate vesta-guestd baked into the guest image, listening on its own vsock ports** | Decoupled from Kata releases. Same pattern as the debug console (vsock 1026) and the CoCo guest components (attestation-agent, CDH). | Needs a custom guest rootfs/initrd (osbuilder). Its port is not covered by agent policy. |
| C. Privileged sidecar or init container in the pod | No Kata changes. | Lives inside the workload's pod and can be reached with pod-level privilege. Cannot start before the workload's containers are created. Weakest option. |
| D. Forward raw `bpf()` syscalls | - | **Rejected** (see §2.1). |

**Baseline: option B**, optionally with a thin option-A bootstrap RPC later if upstream agrees (open question Q1). Its responsibilities:

1. Start from guest init **before kata-agent serves `CreateContainer`** (§2.9).
2. Load the **baked-in** CO-RE BPF objects, relocating against `/sys/kernel/btf/vmlinux`. Attach them and pin links and maps under `/sys/fs/bpf/vesta/`. Load the baked-in baseline policy and set `config.mode`.
3. Serve the control port: apply policy bundles, bind containers to policies, report status and verifier logs.
4. Map cgroup_id → container_id. It learns container IDs and cgroup paths from the host `BindContainer` message, observes cgroup creation (`tp/cgroup/cgroup_mkdir` or an inotify watch on the kata-agent cgroup tree), and writes `cgroup_policy[cgroup_id]`.
5. Drain the ringbuf with epoll and stream batches on the event port. Maintain a process-ancestry cache for the `chain` field.
6. Send a heartbeat with self-status.

**Program delivery [vesta baseline]: programs ship in the guest image. They are not pushed over the channel.** The host → guest channel carries only declarative, schema-validated policy data and control verbs. This choice:

- removes "host injects code into the guest kernel" from the attack surface,
- fits CoCo measurement,
- guarantees programs are attached before any container exists, and
- limits verifier and kernel compatibility testing to the kernels vesta ships with.

The cost is that program upgrades ride on guest image upgrades. This departs from AntCWPP, which loads and unloads programs over veBPF. Whether to add opt-in dynamic loading (signed objects, verifier log returned over the channel) is open question Q2.

**Language split (decided, resolves Q3).** Go on the host, Rust in the guest. The BPF programs are C in `bpf/`, shared by both.

- **vesta-agent (host): Go.** It is a Kubernetes component. client-go/controller-runtime (informers, CRDs, status), the NRI plugin stub (`github.com/containerd/nri/pkg/stub`), the CRI and containerd clients, Prometheus and OTLP exporters are all Go-first. The operator ecosystem (kubebuilder, controller-gen, envtest) is also Go.
- **vesta-guestd (guest): Rust with libbpf-rs.** It runs inside the Kata VM next to kata-agent, which is Rust. That brings:
  - a small static binary with no GC, which suits the memory-constrained guest where every MiB is per pod;
  - reuse of Kata's Rust crates (`protocols`, ttrpc-rust, vsock), and a realistic path to an in-agent RPC later (Q1);
  - libbpf itself for CO-RE relocation, so the guest uses the reference loader against its own BTF.

  libbpf-rs is preferred over aya because the BPF programs stay in C. C is the language kernel BPF reviewers read, and it keeps the BPF code independent of the userspace language.
- **Shared contract.** The protobuf definitions in `api/` generate Go code (host) and Rust code via prost (guest). Protocol compatibility is tested in CI from both sides.

Rejected: all-Go (cilium/ebpf in the guest works, but Go's runtime and GC add memory per pod and the binary is larger) and all-Rust (kube-rs is viable but the NRI, controller and CRD tooling is weaker than in Go).

#### Guest image distribution [vesta] (decided)

vesta-guestd is not a Kubernetes workload. It is a binary inside the Kata guest image, next to kata-agent, and starts when a Kata VM boots from that image. Getting it onto a node means installing the vesta guest assets there.

**Baseline: vesta ships its own Kata runtime alongside stock Kata.** Kata itself is still installed by upstream kata-deploy, unchanged. vesta adds one extra runtime handler that uses the vesta guest kernel and image.

| Artifact | Built from | Installed to (node) |
|---|---|---|
| vesta guest kernel (`vmlinux-vesta`) | Kata kernel sources + `images/guest/vesta.conf` fragment (§3) | `/opt/vesta/kata/` |
| vesta guest image (rootfs image; initrd variant later, Q7) | osbuilder recipe in `images/guest/`: stock kata-agent + vesta-guestd + BPF objects + init ordering unit | `/opt/vesta/kata/` |
| Kata runtime config `configuration-qemu-vesta.toml` + `config.d/` | Copy of the installed runtime-rs `configuration-qemu-runtime-rs.toml` and its kata-deploy `config.d/` drop-ins, plus `config.d/90-vesta.toml`. That drop-in overrides `kernel` and `image`, appends `lockdown=integrity` to the effective `kernel_params`, and removes `kernel`, `image`, `initrd`, `kernel_params`, `firmware` and `path` from `enable_annotations` ([compat](compat/kata-4.2.md) §1, §7) | `/opt/vesta/kata/<version>/` |
| containerd runtime handler `kata-qemu-vesta` | `runtime_type = "io.containerd.kata-qemu-vesta.v2"`, `runtime_path = /opt/kata/runtime-rs/bin/containerd-shim-kata-v2`, `options.ConfigPath = /opt/vesta/kata/current/configuration-qemu-vesta.toml`. Not `KATA_CONF_FILE`, which only accepts shipped config paths. | containerd config drop-in, located as kata-deploy does it ([compat](compat/kata-4.2.md) §5) |
| RuntimeClass `kata-qemu-vesta` | `handler: kata-qemu-vesta`, `scheduling.nodeSelector` on the vesta-ready node label, pod `overhead` raised for guestd | cluster (Helm chart) |

**Installer.** An init container (`vesta-install`) in the vesta-agent DaemonSet, so there is still one vesta DaemonSet per Kata node:

1. Check that Kata is installed on the node (runtime-rs shim binary and base config present) and record its version. If it is missing or its version is outside the supported range (Kata 4.x, tested against 4.2.0; containerd ≥ 2.0), do not install and report it (the node is not labelled vesta-ready).
2. Copy the kernel and image to `/opt/vesta/kata/` (versioned directory plus a `current` symlink, switched atomically), and generate `configuration-qemu-vesta.toml` from the node's Kata base config.
3. Add the containerd runtime handler via a config drop-in and restart containerd only if the config changed, using the same locations kata-deploy uses: `/etc/containerd/conf.d/` on containerd ≥ 2.2, otherwise an `imports` entry, and `config-v3.toml.d/` on k3s/RKE2. kata-deploy 4.x can register custom runtimes itself (`customRuntimes`: handler, base config, drop-in, RuntimeClass). This is supported as an optional integration mode, but it cannot install the vesta kernel and image, so vesta-install still runs ([compat](compat/kata-4.2.md) §5, Q18).
4. Label the node `vesta.dev/guest-ready=<version>`. The RuntimeClass schedules only onto labelled nodes.

Uninstall (a DaemonSet `preStop` hook, or a Helm pre-delete Job) reverses steps 2–4. It refuses while running pods use `kata-qemu-vesta`.
  - **Implementation status (deviation):** neither hook is used. A `preStop` hook also runs on every rolling update, and a pre-delete Job cannot run once per node. The chart has an `uninstall.enabled` mode instead: the DaemonSet's init container runs `vesta-install uninstall` (retrying while vesta pods remain), the agent does not run, and the service account gets the extra `list pods`/`list runtimeclasses` it needs for that mode only. The operator runs `helm upgrade --set uninstall.enabled=true`, waits for the rollout, then `helm uninstall` (deploy/helm/vesta/README.md).
  - If containerd does not come back after the installer's restart, vesta-install restores the previous containerd config, restarts containerd again and fails without labelling the node.

**Opt-in model.** Pods get vesta by using `runtimeClassName: kata-qemu-vesta`. Plain `kata-qemu` pods boot the stock guest and are not monitored (vesta-agent reports them as ineligible). This lets vesta roll out per workload and keeps it off pods that do not ask for it.

**Upgrades.** A new vesta release ships a new kernel and image. Running VMs keep the image they booted from, so the installer never deletes a version still in use. New pods pick up the new `current`. The host agent handles mixed guest versions through the protocol version handshake (§2.3).

**Rejected alternatives.**
- A custom kata-deploy image with vesta's guest assets. It replaces the upstream installer and must be rebuilt for every Kata release.
- Delivering guestd at runtime (shared filesystem, sidecar). It cannot reliably start before the workload's containers and is reachable from the pod (option C above).
- Rewriting the stock `kata-qemu` config in place. It silently changes every Kata pod on the node and conflicts with kata-deploy upgrades.

### 2.3 Channel protocol [vesta]

#### 2.3.1 Transport

| Hypervisor | Host side | Guest side | Phase |
|---|---|---|---|
| QEMU (runtime-rs, the Kata 4.x default; the deprecated Go runtime works the same way) | vhost-vsock, AF_VSOCK to guest CID | AF_VSOCK listen | 1 |
| Cloud Hypervisor, Dragonball | hybrid vsock: per-sandbox UDS + `CONNECT <port>\n` | AF_VSOCK listen | 4 |
| Firecracker | hybrid vsock (as above); no virtio-fs, devmapper snapshotter | AF_VSOCK listen | 4 |

- **Ports** (decided, resolves Q4): **CTRL = 22085**, **EVT = 22086**. They are configurable and baked into the guest image config (`/etc/vesta/guestd.toml`). Kata uses 1024 (agent), 1025 (log), 1026 (debug console) and 1027 (passfd) ([compat](compat/kata-4.2.md) §3).
- The host always initiates connections. This avoids needing a guest → host listener under hybrid vsock.
- One CTRL connection and one EVT connection per sandbox.

#### 2.3.2 Framing and control messages (CTRL)

Each frame is a `u32` big-endian length followed by one protobuf message. Frames larger than 1 MiB are rejected. Each connection and direction has a single envelope type: `ControlRequest`/`ControlResponse` on CTRL, `EventStreamMessage` on EVT. The first exchange is `Hello`, which negotiates versions. Protocol version is 1.0. The normative definitions are in `api/proto/vesta/channel/v1/`, and the sketch below is abbreviated. The host supports protocol versions N and N-1. Whether to use ttRPC instead, for reuse of Kata tooling, is Q5.

```proto
// api/proto/vesta/channel/v1/control.proto  (sketch)
message Hello        { uint32 proto_major = 1; uint32 proto_minor = 2; string agent_version = 3; }
message HelloReply   { uint32 proto_major = 1; uint32 proto_minor = 2;
                       string guest_image_version = 3; string kernel_release = 4;
                       repeated string active_lsms = 5;      // from /sys/kernel/security/lsm
                       bool cgroup_v2 = 6; repeated string features = 7; }

message ApplyPolicy  { uint64 generation = 1; repeated PolicyBundle bundles = 2; }  // idempotent
message PolicyBundle { uint32 policy_id = 1; string name = 2; Mode mode = 3; FailurePolicy failure = 4;
                       ExecRules exec = 5; NetRules net = 6; FileRules file = 7; uint32 schema_version = 8; }
message BindContainer{ string container_id = 1; string cgroup_path = 2; uint32 policy_id = 3;
                       RootfsType rootfs = 4; uint64 generation = 5; }
message Unbind       { string container_id = 1; }
message SetMode      { GlobalMode mode = 1; }   // Normal | AuditOnly | Detached (kill switch)
message GetStatus    {}
message Ack          { uint64 generation = 1; bool ok = 2; string error = 3; bytes verifier_log = 4; }
message Status       { repeated ProgStatus progs = 1; uint64 applied_generation = 2;
                       bytes policy_hash = 3; repeated DropCount drops = 4; // typed, no guest-chosen keys
                       GlobalMode global_mode = 5; repeated BoundContainer containers = 6; }
```

Policy updates are idempotent and generation-numbered. The guest acks with the applied generation, and the host records it in CR status.

#### 2.3.3 Event stream (EVT)

```
 BPF prog --bpf_ringbuf_reserve/submit--> ringbuf (1-8 MiB per guest)
     |  reserve fails -> ++drop_counters[cpu][type]   (never block in BPF)
     v
 vesta-guestd (epoll consumer) --assign seq, attach chain--> batch
     v
 EVT stream: EventBatch{first_seq, events[], drops}  -->  host ack(seq)
```

- `Subscribe{from_seq}` → `EventBatch` ... and `Heartbeat` frames. The host acks by sequence number, and the guest keeps a bounded replay buffer.
- **Backpressure**: when EVT is congested or down, vesta-guestd drops low-priority audit events first and keeps `DENIED` events and heartbeats. Every drop is counted.
- **The enforcement path never depends on the channel.** Decisions are made in-kernel from maps.
- **Heartbeat** (default every 5 s): `{seq, applied_generation, policy_hash, progs:[{id, tag, link_id, attach}], ringbuf_drops, guestd_rss, cpu_ns}`. The host alerts if no heartbeat arrives within 2× the interval, or on a tag, link or generation mismatch.
- The ringbuf is counted against guest memory. Size it relative to the sandbox memory.

### 2.4 BPF programs [vesta]

All programs are CO-RE (`vmlinux.h` per architecture), compiled once, and licensed `"Dual BSD/GPL"` (§6). **Only int-returning LSM hooks can deny.** The program returns `-EPERM` or `-EACCES`, and 0 means allow. Void hooks such as `bprm_committed_creds` are audit-only. Since 6.12, the verifier checks the return-value range per hook (`bpf_lsm_get_retval_range`, absent in 6.11). BPF LSM runs in `lsm=` order alongside the other LSMs, and any denial wins. Sleepable `lsm.s/` programs are allowed only on hooks in the kernel's sleepable set.

| ID | Purpose | Attach (SEC name) | Deny | Phase |
|---|---|---|---|---|
| P1 | Exec audit (resolved path, argv from `mm->arg_start` after commit) | `tp/sched/sched_process_exec` | no | 1 |
| P2 | Exec allow/deny, drift, memfd exec | `lsm/bprm_check_security` | yes | 1 (audit) → 3 (enforce) |
| P3 | Exec via mmap (ld.so direct invocation, uploaded ELF) | `lsm/mmap_file`, `lsm/file_mprotect` (PROT_EXEC) | yes | 3 |
| N1 | Egress connect | `cgroup/connect4`, `cgroup/connect6` | yes (return 0) | 1 (audit) → 3 |
| N2 | Unconnected UDP egress, DNS | `cgroup/sendmsg4`, `cgroup/sendmsg6` | yes | 4 |
| N3 | Inbound | `lsm/socket_bind`, `lsm/inet_conn_request`, `cgroup_skb/ingress` | yes | 4 |
| N4 | DNS payload parse | `cgroup_skb/egress` + `cgroup_skb/ingress` (port 53) | no | 4 |
| N5 | Non-inet or task-context connect audit | `lsm/socket_connect` | yes | optional |
| N6 | Pod-wide L3/L4 filter | TC on guest `eth0` (tcx on 6.6+, else clsact + `sched_cls`) | yes | optional |
| F1 | Protected-file open | `lsm/file_open` (`bpf_d_path` is allowed here) | yes | 4 |
| F2 | Read/write checks | `lsm/file_permission` | yes | 4 |
| F3 | FIM / bait files | `lsm/inode_unlink`, `lsm/inode_rename`, `lsm/inode_setattr`, `lsm/path_*` | yes | 4 |
| S1 | ptrace | `lsm/ptrace_access_check`, `lsm/ptrace_traceme` | yes | 3 |
| S2 | User-namespace creation | `lsm/userns_create` (6.1+) | yes | 3 |
| S3 | mount | `lsm/sb_mount`, `lsm/move_mount` | yes | 4 |
| S4 | setuid | `lsm/task_fix_setuid` | yes | 4 |
| S5 | memfd_create, unshare (non-user ns), dup2/dup3 | `tp/syscalls/sys_enter_*` | no | 4 |
| T | Self-protection | `lsm/bpf`, `lsm/bpf_map`, `lsm/bpf_prog`, `lsm/task_kill`, `lsm/inode_unlink`, `lsm/sb_umount`, `lsm/kernel_module_request`, `lsm/kernel_read_file` | yes | 3 |

Choices that differ from the draft or from AntCWPP, and why:

- **Exec audit uses `sched_process_exec`, not `sys_enter_execve`.** `sys_enter_execve` reads user memory, which is racy (TOCTOU) and can fault on non-resident pages. It also misses `execveat` (fexecve, memfd exec) and fires on failed execs. `sched_process_exec` fires once per successful exec with the resolved binary. If `sys_enter_execve`/`execveat` are used at all, it is only for best-effort argv capture.
- **File control uses `lsm/file_open`, not `inode_permission`.** `inode_permission` runs for every path component of every lookup, can run in RCU-walk (`MAY_NOT_BLOCK`), is not sleepable and has no path context. It is excluded unless benchmarks justify it, and then only as an O(1) `(dev, ino)` hash lookup with early exit. [AntCWPP] uses `security_inode_permission` for file control.
- **Network uses cgroup-v2 hooks first.** They are attached per container cgroup, run in process context, and catch unconnected UDP, which `socket_connect` misses. TC on the guest `eth0` sees all pod traffic as one interface, and on ingress it has no process or cgroup context (`skb->sk` is not yet set). TC is therefore limited to pod-wide L3/L4 filtering. [AntCWPP] "mainly selected the LSM and TC layer". It says bind and connect have hook points but names no symbol.
- **XDP is not used.** Native XDP on guest virtio-net can fail when there are too few TX queues. Generic XDP is ingress-only and adds nothing over cgroup_skb or TC here.
- **Per-cgroup LSM attachment** (`lsm_cgroup/`, `BPF_LSM_CGROUP`, 6.0+) is an alternative to global LSM programs with a cgroup→policy lookup. Baseline: global programs plus the `cgroup_policy` map (simpler, and one attach per hook).

#### Maps (sketch)

| Map | Type | Key → Value | Writer |
|---|---|---|---|
| `config` | ARRAY[1], frozen after boot | `{schema_version, heartbeat_interval, guestd_cgroup_id, guestd_exe(dev,ino)}` | guestd at boot |
| `global_mode` | ARRAY[1] | `Normal / AuditOnly / Detached` | guestd (kill switch) |
| `policy_ready` | ARRAY[1] | generation (0 = no policy yet) | guestd |
| `cgroup_policy` | HASH | `cgroup_id` → `{policy_id, mode, failure, rootfs_type}` | guestd |
| `exec_rules` | HASH | `{policy_id, dev, ino}` → allow/deny | guestd |
| `net_rules_v4/v6` | LPM_TRIE | `{prefixlen, policy_id, proto, pad, port, addr}` → allow/deny | guestd |
| `file_rules` | HASH | `{policy_id, dev, ino}` → access mask | guestd |
| `events` | RINGBUF | - | BPF programs |
| `drop_counters` | PERCPU_ARRAY | event type → count | BPF programs |

The exact layouts are in `bpf/include/vesta_abi.h`, documented in [abi.md](abi.md). Map values do not carry a per-value `schema_version`. One `VESTA_ABI_VERSION` (in `config` and in the objects) covers them, because changing a layout requires a new guest image anyway.

### 2.5 Container attribution inside the guest [vesta]

- All containers in a pod share one guest kernel. kata-agent creates one cgroup per container from the OCI `linux.cgroupsPath`. The pause container is also a container in the guest.
- BPF programs tag events with `bpf_get_current_cgroup_id()`. This requires **cgroup v2** in the guest. Kata 4.x guests already boot cgroup v2: the default `kernel_params` are `cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1`, and kata-agent reads `systemd.unified_cgroup_hierarchy`. There is no `agent.` variant. vesta keeps these params and checks `cgroup_v2` in `HelloReply` ([compat](compat/kata-4.2.md) §4, resolves Q6).
- Mapping: the host sends `BindContainer{container_id, cgroup_path}` at NRI `CreateContainer`, with `cgroup_path` = the OCI `linux.cgroupsPath` verbatim, which Kata passes to the agent unchanged. vesta-guestd derives the guest cgroup directory with kata-agent's rules and confirms it when the cgroup appears. The rules: systemd `slice:prefix:name` becomes `<expanded slices>/<prefix>-<name>.scope`; the cgroupfs form replaces `:` with `/` ([compat](compat/kata-4.2.md) §4). The inode number of the cgroup directory is the cgroup id. guestd then writes `cgroup_policy`.
- Unbound cgroups under the containers subtree fall back to the sandbox default policy. With `failurePolicy: Closed`, exec and connect are denied until the cgroup is bound (§2.9).
  - **Implementation status (deviation):** the MVP has no sandbox default entry. The BPF programs look up the nearest bound ancestor cgroup ([abi.md](abi.md) decision step 2), and a cgroup with no bound ancestor is unenforced. `Closed` is enforced by the host start gate instead: a container whose bind is not acked at the requested generation does not start, so no workload process runs in an unbound container cgroup. The residual gap is a container started while the vesta NRI plugin was not registered (see §2.9, NRI required plugins).
- If cgroup v2 is unavailable, the fallback is mount-namespace or pid-namespace inode (`task->nsproxy` via CO-RE, `bpf_get_ns_current_pid_tgid`). This fallback supports attribution only, not per-container attachment.
- Host enrichment adds sandbox ID, pod name, namespace and UID, container name, image and image digest, and node from CRI/NRI.
- Multi-container pods: each container can bind a different policy through `containerSelector`. Sidecars and pause get the default policy.

### 2.6 Drift prevention and rootfs type [vesta]

[AntCWPP] blocks non-image programs by checking at the LSM exec hook whether the executable is in the overlayfs upper layer (p. 26).

This works only when the container rootfs overlay is assembled **inside the guest**, as with guest-pull, nydus or block-device (devmapper) snapshotters. With Kata's default **virtio-fs shared rootfs** (`shared_fs = virtio-fs` in Kata 4.2 QEMU configs), the overlay lives on the host, the guest sees a virtiofs inode, and the upper-layer check cannot work.

vesta design:

1. The host detects the rootfs type per container from the snapshotter and Kata sandbox config and sends it in `BindContainer.rootfs`.
2. Overlay in the guest: deny exec when `bprm->file`'s inode is on the overlay upper layer, tmpfs, or memfd/anonymous shmem. Key on `(s_dev, i_ino)` and the overlay upper-vs-lower check through the overlay superblock. Do not key on paths.
3. virtio-fs rootfs: fall back to an image-content allowlist. The set of executable `(dev, ino)` pairs (or file hashes) comes from the read-only image layers, resolved **in the guest** at bind time. Inode numbers come from the host, `s_dev` differs per mount, and inode stability and reuse over virtiofs need validation (Q8).
4. Known bypasses need companion hooks: interpreters running scripts (`bash x.sh` never execs `x.sh`; `python -c`), direct `ld.so` invocation and `mmap(PROT_EXEC)` (P3), `LD_PRELOAD` (audit), and ptrace injection (S1).

The same `(dev, ino)` caveats apply to `file_rules`.

### 2.7 Event schema [vesta]

Wire format guest → host: protobuf (`api/proto/vesta/event/v1`). Export from the host: JSON lines and OTLP logs, with attributes named according to the OpenTelemetry semantic conventions (`k8s.pod.name`, `k8s.namespace.name`, `container.id`, `process.executable.path`, ...).

```proto
message Event {
  // guest-asserted: set by BPF / vesta-guestd; untrusted once the guest is compromised
  uint64 seq = 1;                  // per-sandbox monotonic (guestd)
  uint64 ktime_boot_ns = 2;        // bpf_ktime_get_boot_ns()
  int64  guest_wall_unix_ns = 3;   // converted by guestd
  EventType type = 4;              // EXEC, CONNECT, SENDMSG, BIND, DNS, FILE_OPEN, FILE_MODIFY,
                                   // PTRACE, USERNS, MOUNT, SETUID, MEMFD, UNSHARE, DUP_SOCKET, TAMPER
  Action action = 5;               // AUDITED | DENIED | ALLOWED
  PolicyRef policy = 6;            // {name, namespace, uid, generation, rule_id}
  Process process = 7;             // {pid, tgid, ns_pid, uid, gid, comm, exe_path, exe{dev,ino},
                                   //  argv[] (truncated), argv_truncated, start_ktime}
  repeated Ancestor chain = 8;     // up to 8 × {pid, comm, exe_path}
  uint64 cgroup_id = 9;
  string container_id = 10;        // guestd mapping
  oneof detail { Exec exec = 20; Net net = 21; Dns dns = 22; File file = 23; Sys sys = 24; }

  // host-set enrichment (trusted source: CRI/NRI/API server)
  Host host = 50;                  // {node, sandbox_id, pod_name, pod_namespace, pod_uid,
                                   //  container_name, image, image_digest, runtime_class,
                                   //  guest_image_version, kernel_release, received_unix_ns}
}
```

[AntCWPP] event fields map as follows: time, action, policy, process name/path/parent chain/uid, VM ID (→ `host.sandbox_id`), image ID (→ `host.image_digest`) (sample log, p. 26).

Host metrics (Prometheus): `vesta_events_total{type,action}`, `vesta_ringbuf_drops_total{type}`, `vesta_channel_drops_total`, `vesta_guest_heartbeat_age_seconds{namespace,pod,sandbox_id}`, `vesta_policy_generation_lag{namespace,pod,sandbox_id}`, `vesta_channel_throttled_total{kind}`, `vesta_program_load_failures_total`, `vesta_channel_rtt_seconds`, `vesta_sandboxes{state=monitored|unmonitored|ineligible}`.

### 2.8 Kubernetes API (sketch) [vesta]

The API group `vesta.dev` is a placeholder (Q10).

```yaml
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy                 # namespaced; ClusterVestaPolicy adds namespaceSelector
metadata: { name: payments-baseline, namespace: payments }
spec:
  selector:                       # only Kata pods (runtimeClassName resolved to a Kata handler) match
    matchLabels: { app: payments }
  containerSelector:              # optional; default = all containers
    names: [api]
  mode: Audit                     # Audit | Enforce
  failurePolicy: Open             # Open | Closed (see §2.9)
  process:
    denyNonImageExec: true        # requires eligible rootfs type (§2.6)
    allow: [{ path: /usr/bin/app, sha256: "..." }]
    deny:  [{ path: /usr/bin/curl }]
  network:
    egress:
      - { cidr: 10.0.0.0/8, ports: [443], protocol: TCP }
    dnsAudit: true
  file:
    protect:
      - { path: /etc/app/secret.key, access: [read, write] }
  rollout:                        # Phase 5
    nodeSelector: { vesta.dev/canary: "true" }
    requireApproval: true
status:
  observedGeneration: 3
  conditions:                     # Accepted, Programmed, Degraded
    - { type: Programmed, status: "True", reason: AllSandboxesAcked }
  sandboxes: { matched: 12, programmed: 11, ineligible: 1, unmonitored: 0 }
```

Paths are resolved to `(dev, ino)` **in the guest** at bind time, because the host cannot see guest inodes. VestaConfig holds `globalMode`, defaults, export sinks, and heartbeat and budget settings.

### 2.9 Startup ordering and failure semantics [vesta]

#### Ordering

```
 containerd/NRI      vesta-agent (host)         Kata shim/VM              vesta-guestd (guest)
 RunPodSandbox ----> (record sandbox) -------> VM boots
                                                guest init ------------> start guestd, load+attach
                                                                          progs, baseline policy,
                                                                          policy_ready=baseline gen
                                                kata-agent serves ttRPC
                     Hello/ApplyPolicy ---------------------------------> maps written
                     <-------------------------------------------------- Ack(gen G)
 CreateContainer --> BindContainer{cid,cgroup,policy} ------------------> pending bind
                                                kata-agent creates cgroup -> cgroup_mkdir: bind
 StartContainer ---> wait Ack(cid bound, gen G) <------------------------ Ack
   (blocks until ack or timeout -> failurePolicy)
                                                container entrypoint exec  (policy in force)
```

1. vesta-guestd starts from guest init and attaches all programs **before kata-agent serves `CreateContainer`**. On the rootfs image, which uses systemd, it runs as a `Type=notify` unit, `Before=kata-agent.service`, and kata-agent gets a `Wants=`/`After=` drop-in ([compat](compat/kata-4.2.md) §4). The initrd variant (agent as PID 1) is not supported in the MVP (Q7).
2. The host NRI plugin blocks `StartContainer` (or `CreateContainer`) until the guest acks that container's bind at the desired generation.
3. Policy changes after start are best-effort, with a generation ack reflected in status.

#### Failure semantics

| Failure | Behavior |
|---|---|
| vesta-guestd crashes | Pinned links keep programs attached, and the last policy keeps enforcing. Events buffer in the ringbuf, then drop with counts. The host sees the heartbeat stop, marks the sandbox `unmonitored` and alerts. |
| Channel down | Same as above. Enforcement is unaffected. |
| No policy loaded yet (`policy_ready == 0`) or container cgroup unbound | `failurePolicy: Open` means allow and audit. `Closed` means programs deny exec and connect for the affected cgroups. |
| Program load or verifier failure at boot | guestd reports it in `HelloReply`/`Status` with the verifier log. `Closed`: NRI fails `CreateContainer` with a clear error. `Open`: the sandbox runs unmonitored or audit-only, with a `Degraded` condition. |
| NRI ack timeout | `Closed`: fail container start. `Open`: start and mark the sandbox `unmonitored`. |
| vesta NRI plugin not registered (agent down or restarting, containerd restart, NRI dropped the plugin after a timeout) | NRI calls only registered plugins, so no gate runs. Pods annotated `required-plugins.noderesource.dev/pod: '["vesta"]'` fail container creation instead (containerd's NRI default validator, enabled by vesta-install); unannotated pods start ungated. The chart can require the annotation on `kata-qemu-vesta` pods with a ValidatingAdmissionPolicy (`nri.requirePluginAnnotation`). |
| Guest not eligible (no bpf LSM, cgroup v1, old image) | The policy does not bind. `Closed` policies fail pods, `Open` policies report `ineligible`. |
| Kill switch `AuditOnly` / `Detached` | All programs go audit-only (the mode check happens in BPF), or guestd detaches everything except self-protection. |
| VM restart | Everything in the guest is lost. The host reconciles on sandbox start. |

Defaults: `Open` for audit policies. `Closed` is opt-in for enforce policies.

### 2.10 Versioning [vesta]

Three things are versioned independently:

1. The guest image (kernel + vesta-guestd + BPF objects).
2. The host agent.
3. The channel protocol, with a semver handshake. The host supports N and N-1.

Running sandboxes keep the programs they booted with, and upgrades apply to new sandboxes. There is no hot-swap in the MVP. CO-RE plus BTF absorbs minor guest kernel drift. CI verifies the objects against every supported guest kernel (§5).

---

## 3. Guest kernel requirements [vesta]

Kata ships the guest kernel, independent of the host kernel, so vesta chooses a modern floor. The minimum is **6.1 LTS**, and 6.6+ or 6.12 is preferred. Kata 4.2 ships 6.18.35 ([compat](compat/kata-4.2.md) §4). Feature versions: BPF LSM 5.7, ringbuf 5.8, `bpf_d_path` 5.10, sleepable BPF LSM 5.11 (`bpf_lsm_is_sleepable_hook` first appears in 5.11; resolves Q9), per-hook LSM return-range checks 6.12, memcg-based BPF memory accounting 5.11, `BPF_LSM_CGROUP` 6.0, `userns_create` 6.1, tcx 6.6. Supporting 5.10 or 5.15 is a compatibility goal only.

vesta maintains a Kata kernel config fragment (`images/guest/kernel/vesta.conf`), applied as a Kata build type (`configs/fragments/build-type/vesta/`, `build-kernel.sh -b vesta`) and meant to be upstreamable. Kata 4.2's fragments enable `BPF_SYSCALL`/`CGROUP_BPF` (for cgroup-v2 device control), SELinux and Landlock. They do **not** enable `BPF_LSM`, and they enable `DEBUG_INFO_BTF` only in the debug fragment, so a custom guest kernel is required ([compat](compat/kata-4.2.md) §4, resolves Q12's first half). The authoritative fragment is the file in the repo. The listing below is the conceptual full set, including options Kata's common fragments already set.

```
# Core
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
# BTF (pahole >= 1.16 in the Kata kernel build container; >= 1.22-1.25 for 6.x)
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO_BTF=y
# LSM
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_BPF_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LSM="landlock,lockdown,yama,selinux,bpf"   # Kata enables landlock + selinux; bpf must be listed
# Tracing
CONFIG_TRACEPOINTS=y
CONFIG_BPF_EVENTS=y
CONFIG_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y   # fentry/fexit trampolines (arm64: ~6.0+)
# Cgroup / network
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_SOCK_CGROUP_DATA=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_SCH_INGRESS=y            # clsact; not needed with tcx (6.6+)
# Hardening
CONFIG_MODULES=n                    # or kernel.modules_disabled=1 after boot (Q11)
# Optional
# CONFIG_BPF_KPROBE_OVERRIDE=y + CONFIG_FUNCTION_ERROR_INJECTION=y   (not used in v1)
# CONFIG_IKHEADERS=y
```

`CONFIG_BPF_LSM=y` on its own does nothing: **`bpf` must be in the active LSM list**. Otherwise `lsm/` programs load and attach but never run. vesta-guestd reads `/sys/kernel/security/lsm` at boot, reports it in `HelloReply`, and refuses enforce mode if `bpf` is missing.

Guest kernel command line: the vesta drop-in (`config.d/90-vesta.toml`, §2.2) **appends** to the effective `kernel_params`, so stock Kata runtimes are unaffected and Kata's own params are kept:

```
<kata params, incl. cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1> lockdown=integrity
```

vesta passes no `lsm=` param: `CONFIG_LSM` in the fragment already includes `bpf`, and an `lsm=` param would override Kata's LSM order. cgroup v2 comes from Kata's defaults (Q6 resolved).

Cost: `.BTF` adds a few MB to vmlinux and stays resident in guest memory. `DEBUG_INFO` slows the build considerably, so strip DWARF and keep `.BTF`. Measure the vmlinux/vmlinuz size, guest boot time and boot memory against Kata's stock guest kernel (§5).

---

## 4. Workflow [vesta, following AntCWPP's flow]

1. A policy author applies a `VestaPolicy` (`mode: Audit` by default). [AntCWPP] user-defined CRD policy.
2. vesta-agent on each node compiles it for matching Kata sandboxes that pass the eligibility pre-check and sends `ApplyPolicy` / `BindContainer`. With `rollout` (Phase 5), delivery is staged to canary nodes and waits for approval. [AntCWPP] pre-check, then staged delivery with manual confirmation.
3. vesta-guestd writes the maps and acks the generation. Status conditions update.
4. BPF programs in the guest kernel audit or deny. Events stream over EVT to the host agent, which enriches and exports them to the configured sink. [AntCWPP] events return over veBPF to cloud analysis.
5. Heartbeats and drop counters feed tamper and health alerts. The kill switch in VestaConfig forces audit-only or detach cluster-wide. [AntCWPP] degradation switch.

---

## 5. Testing, performance and CI [vesta]

**Test layers**

1. Unit tests: policy compiler (CRD → map entries), protocol framing, event validation (fuzz the host-side decoder).
2. BPF tests: `BPF_PROG_TEST_RUN` where the program type supports it. Verifier load tests for every object against **every supported guest kernel** in CI VMs (little-vm-helper, virtme-ng or vmtest).
3. Integration: boot the vesta guest image under QEMU with vesta-guestd and run a channel conformance suite (handshake, N-1 compatibility, oversized and malformed frames, reconnect, replay).
4. End to end: single-node k3s (or kubeadm) + kata-deploy on a KVM-capable runner. kind+Kata needs nested virtualization and privileged nodes and is fragile, so it is not the primary target.
5. Security tests: guest-root tamper attempts (detach links, update maps, kill guestd, unmount bpffs, load a module) must be denied or detected. Event-flood tests must show the host agent and other sandboxes are unaffected.

CI also runs SAST, gitleaks and SBOM generation, and does a reproducible guest image build.

**Performance budget.** These are initial targets proposed by reviewers. They are not measured and must be validated in Phase 0 and 1:

| Metric | Target |
|---|---|
| exec latency overhead (p99) | < 5% |
| `connect()` overhead | < 2 µs |
| sandbox time-to-ready increase | < 50 ms |
| vesta-guestd RSS | < 20 MiB |
| guest kernel image growth (BTF) | < 5 MiB |
| ringbuf drops at 1k exec/s | 0 |

Benchmarks: a `crictl runp` start loop, fork/exec microbenchmarks (e.g. unixbench spawn/execl), netperf/iperf connect rate, and fio for file hooks. All run against the same Kata guest without vesta. Every roadmap phase includes a budget check.

---

## 6. Licensing and governance [vesta]

- `bpf/`: `"Dual BSD/GPL"` (GPL-2.0-only OR BSD-2-Clause), declared as `char LICENSE[] SEC("license") = "Dual BSD/GPL";`. The verifier rejects `BPF_PROG_TYPE_LSM` programs without a GPL-compatible license (`bpf_lsm_verify_prog`). Tracing helpers such as `bpf_probe_read_*`, `bpf_get_current_task_btf` and `bpf_d_path` are GPL-only.
- Userspace, API and deploy: Apache-2.0, matching Kata, Tetragon, Tracee, Inspektor Gadget and bpfman.
- DCO sign-off. GOVERNANCE.md, MAINTAINERS, SECURITY.md (disclosure process), and CODEOWNERS for `bpf/`.

Proposed repo layout:

```
bpf/                 BPF C, CO-RE, vmlinux.h per arch (Dual BSD/GPL); include/vesta_abi.h
guest/               Cargo workspace; guest/vesta-guestd (Rust, libbpf-rs, prost)
host/cmd/vesta-agent host DaemonSet (Go: client-go, NRI, CRI)
host/cmd/vesta-install installer init container (guest assets, runtime handler, node label)
host/internal/       shared Go packages
api/proto/           protobuf (vesta/channel/v1, vesta/event/v1)
api/gen/go/          generated Go (committed; hack/gen-proto.sh)
api/channel/         wire constants (ports, framedbcritrsions)
images/guest/        osbuilder recipe, kernel config fragment, systemd units
hack/                dev scripts (Docker-based proto gen, ABI check)
deploy/              Helm chart, kustomize, RuntimeClass kata-qemu-vesta
test/abi, test/bpf, test/e2e   test suites
docs/                architecture, threat model, ADRs
go.mod               single Go module github.com/vesta-dev/vesta (placeholder path)
LICENSE (Apache-2.0), LICENSES/ (Apache-2.0, GPL-2.0-only, BSD-2-Clause)
```

---

## 7. Prior art

| Project | Relevance to vesta |
|---|---|
| AntCWPP (Ant Group) | The design vesta follows: guest-kernel eBPF, veBPF channel, CRD-driven policy. It is a whitepaper, not code. |
| libbpf / libbpf-rs | The guest loader (libbpf-rs in vesta-guestd), used **as-is inside the guest**. No adaptation to a remote channel is needed or possible (§2.1). aya and cilium/ebpf were considered and not chosen (§2.2). |
| Tetragon | Has TracingPolicy with LSM hooks and override actions, and sched_process_exec-based exec tracking. **Not pursued for now** (decision): vesta builds its own programs. It stays a reference for hook choice and policy semantics. |
| KubeArmor | BPF-LSM (or AppArmor/SELinux) enforcement with k8s policy CRDs. A reference for the policy model. Its Kata/CoCo support is unknown (not checked; Q16). |
| bpfman (formerly bpfd) | BPF program lifecycle, OCI bytecode images and k8s CRDs. Closest analogue to "agent loads programs + CRD". A reference if dynamic loading (Q2) is adopted. |
| Inspektor Gadget | OCI-packaged image-based gadgets and an eBPF runtime. A reference for packaging and event plumbing. |
| Tracee | Runtime detection with signatures. A reference for the detection-rule set. |
| Falco | Event collection and rules. Detection only, with no enforcement. |
| Kata Containers | kata-agent (Rust, ttRPC over vsock; `src/libs/protocols/protos/agent.proto`), agent policy/genpolicy, osbuilder (guest image), kernel packaging, kata-deploy. For prototyping the channel: the debug console (`debug_console_enabled`, vsock 1026) and `agent-ctl` (`src/tools/agent-ctl`). "Extend the kata-agent API" is only viable with upstream agreement; otherwise it is a fork risk. |
| containerd NRI | The synchronous pod and container lifecycle hooks used for start gating. |

---

## 8. Roadmap (MVP first)

| Phase | Content | Exit criteria |
|---|---|---|
| **0: Decisions + guest foundation** | Resolve Q1, Q2 and Q5 (guest endpoint, program delivery, protocol) as ADRs, record the language decision (§2.2) as an ADR, and open a Kata upstream issue. Build the kernel fragment and the osbuilder guest image with vesta-guestd. Build `vesta-install` and the `kata-qemu-vesta` RuntimeClass. | `vesta-install` sets up `kata-qemu-vesta` on a node with stock kata-deploy, and stock `kata-qemu` pods still work unchanged. The vesta guest kernel and image boot under QEMU. `bpftool prog` shows the exec and connect programs attached **before kata-agent starts**. `/sys/kernel/security/lsm` contains `bpf`. Boot time and memory deltas are measured. |
| **1: MVP, audit only, QEMU only** | P1, P2 (audit), N1 (audit). CTRL + EVT channel with handshake, heartbeat and drop counters. Container attribution via cgroup v2. Static policy (flag or ConfigMap). **Kill switch** (`AuditOnly`/`Detached`). JSON/OTLP export and metrics. | Exec and connect events with pod and container metadata reach the host sink. Heartbeat and drop metrics work. e2e is green in CI on k3s+Kata. The performance budget is checked. |
| **2: Policy API** | VestaPolicy v1alpha1 (audit), eligibility pre-check, NRI start gate, generation acks, status conditions, rootfs-type detection. | A policy change is reflected in status with an acked generation. A container never starts before its bind is acked (test proves it). Ineligible sandboxes are reported. |
| **3: Enforce** | Exec allow/deny, egress CIDR deny, `failurePolicy`, drift prevention on in-guest overlay rootfs, P3, S1, S2, self-protection (T), load shedding. | The tamper test suite passes (deny or detect). Enforcement survives a guestd kill. Fail-closed and fail-open behavior matches §2.9. The budget is re-checked. |
| **4: Breadth** | Cloud Hypervisor, Dragonball and Firecracker (hybrid vsock). File hooks (F1-F3). DNS audit (N2, N4). Inbound (N3). Deferred detections (reverse shell, LD_PRELOAD, SSH, mount, memfd). Drift fallback for virtio-fs rootfs. Allowlist learning. | e2e passes per hypervisor. Each new hook has a benchmark and a verifier test on all supported kernels. |
| **5: CoCo + rollout** | CoCo mode (§1.4.4): tenant-signed policies, encrypted or redacted events, agent-policy integration. Staged rollout with approval. | A CoCo sandbox runs vesta with attestation covering guestd and the objects. The host cannot alter policy or read event content. |

---

## 9. Open Questions

Items where reviewers disagreed, had low or medium confidence, or could not verify upstream state. Reviewers could not fetch live sources during review, so every [verify] item in this document also belongs here.

1. **Q1 Guest endpoint.** Separate vesta-guestd (baseline), kata-agent RPCs, or both (a thin agent bootstrap RPC plus guestd)? This needs a Kata community discussion. Also confirm that upstream `agent.proto` has no eBPF RPC today.
2. **Q2 Program delivery.** Baked into the guest image only (baseline; one reviewer's recommendation, suits CoCo) versus pushing CO-RE ELFs or light skeletons over the channel (AntCWPP's model; two reviewers described it). If dynamic loading is added, which signing mechanism? Upstream BPF program signing is believed to have landed around v6.18; Hornet is the alternative LSM. Both need verification.
3. ~~**Q3 Guest daemon language.**~~ Resolved: Go host agent, Rust (libbpf-rs) guest daemon, BPF in C (§2.2).
4. ~~**Q4 vsock port allocation.**~~ Resolved: CTRL 22085, EVT 22086. Kata uses 1024-1027 ([compat](compat/kata-4.2.md) §3).
5. **Q5 Wire protocol.** Custom length-prefixed protobuf (baseline) or ttRPC to reuse Kata tooling?
6. ~~**Q6 cgroup v2 in the Kata guest.**~~ Resolved: v2 is the Kata 4.x default (`cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1`), and the agent knob is `systemd.unified_cgroup_hierarchy` ([compat](compat/kata-4.2.md) §4).
7. **Q7 Guest init ordering.** Resolved for the rootfs image (systemd ordering, [compat](compat/kata-4.2.md) §4). Still open for the initrd variant, where the agent is PID 1: does it need a kata-agent hook?
8. **Q8 Drift prevention on virtio-fs.** Is virtio-fs still the default shared rootfs? Are inode numbers stable and unique enough over virtiofs for `(dev, ino)` allowlists, or must vesta use file hashes?
9. ~~**Q9 Kernel feature versions.**~~ Resolved: sleepable BPF LSM is 5.11, and per-hook LSM return-value checks are 6.12 (§3).
10. **Q10 API group and kill-switch form.** API group name (`vesta.dev` is a placeholder). Should the degradation switch be a CR (`VestaConfig`) or a ConfigMap, as in AntCWPP?
11. **Q11 Kernel modules.** Can the vesta guest kernel be built with `CONFIG_MODULES=n` without breaking Kata features some users need (e.g. GPU passthrough drivers)?
12. **Q12 Kata default guest kernel config.** Confirmed: Kata 4.2 enables neither `BPF_LSM` nor (outside debug builds) `DEBUG_INFO_BTF` ([compat](compat/kata-4.2.md) §4). Still open: whether upstream accepts a `vesta` build type.
13. **Q13 NRI gating point.** Confirmed: NRI `RunPodSandbox` fires after the sandbox (VM) has started, and an error from `StartContainer` fails the start before `task.Start` ([compat](compat/kata-4.2.md) §6). Still open: the gate must fit the 2 s plugin timeout and the node-wide NRI lock. Measure bind-ack latency in Phase 1.
14. ~~**Q14 Transport details.**~~ Resolved: vsock is the only agent transport (virtio-serial remains only for the console). Discovery is through the shim-management `/agent-url` for both runtimes ([compat](compat/kata-4.2.md) §2).
15. ~~**Q15 Tetragon as the in-guest engine.**~~ Resolved: not pursued for now; vesta builds its own programs.
16. **Q16 KubeArmor and Kata/CoCo.** Does KubeArmor already support Kata guests? If so, what can vesta reuse?
17. **Q17 Performance targets.** The §5 budget is a reviewer proposal, not a measurement. Confirm or revise it after Phase 0.
18. **Q18 Runtime handler registration.** Mostly resolved ([compat](compat/kata-4.2.md) §1, §5):
    - kata-deploy 4.x has `customRuntimes` (handler, base config, drop-in, RuntimeClass). This is an optional integration mode for vesta, not the default.
    - Drop-in locations: `conf.d` on containerd ≥ 2.2, otherwise `imports`. k3s/RKE2 use `config-v3.toml.d` next to the template, and the template must already import it.
    - vesta supports Kata 4.x and containerd ≥ 2.0.
    - Both runtimes take `ConfigPath`.

    Still open: testing on k3s/RKE2 nodes whose template lacks the import.

---

## 10. References

- AntCWPP whitepaper: https://katacontainers.io/collateral/kata-containers-ant-group-cwpp-ebpf_whitepaper.pdf
- Kernel BPF LSM documentation: https://docs.kernel.org/bpf/prog_lsm.html
- BPF ring buffer: https://nakryiko.com/posts/bpf-ringbuf/
- Kernel sources cited: `include/linux/lsm_hook_defs.h`, `kernel/bpf/bpf_lsm.c`, `kernel/bpf/ringbuf.c`, `kernel/trace/bpf_trace.c`, `security/lockdown/lockdown.c`, `fs/namei.c` (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git)
- Kata Containers: https://github.com/kata-containers/kata-containers (`src/agent`, `src/libs/protocols/protos/agent.proto`, `src/tools/genpolicy`, `src/tools/agent-ctl`, `tools/osbuilder`, `tools/packaging/kernel`, `tools/packaging/kata-deploy`, `docs/how-to/how-to-use-the-kata-agent-policy.md`)
- Confidential Containers: https://confidentialcontainers.org/
- containerd NRI: https://github.com/containerd/nri
- Firecracker vsock: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
- Tetragon: https://github.com/cilium/tetragon
- KubeArmor: https://github.com/kubearmor/KubeArmor
- bpfman: https://bpfman.io/ , https://github.com/bpfman/bpfman
- Inspektor Gadget: https://inspektor-gadget.io/
- Tracee: https://github.com/aquasecurity/tracee
- libbpf-rs: https://github.com/libbpf/libbpf-rs ; aya: https://github.com/aya-rs/aya ; cilium/ebpf: https://github.com/cilium/ebpf
- little-vm-helper: https://github.com/cilium/little-vm-helper
- gVisor: https://gvisor.dev/
- OpenTelemetry semantic conventions: https://opentelemetry.io/docs/specs/semconv/
