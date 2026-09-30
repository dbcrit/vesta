---
title: vesta-guestd
parent: Components
nav_order: 3
---

# vesta-guestd

vesta-guestd is the Rust daemon inside every vesta Kata guest. It loads the [BPF programs](bpf-programs.md), writes their policy maps, reads their ring buffer, and serves vesta-agent on two vsock ports: CTRL (22085) for requests such as `ApplyPolicy` and `BindContainer`, and EVT (22086) for the event stream and heartbeats. It runs as a systemd service that starts before kata-agent, with four capabilities and no `CAP_SYS_ADMIN`. Its links and maps are pinned in bpffs, so enforcement continues if guestd crashes or is stopped, and a restarted guestd adopts what its predecessor left.

> **Status:** unit-tested (`cargo test`) and smoke-tested against the Docker Desktop kernel with only the unit's capabilities. It has **not** run under systemd in the real vesta guest image, and the vsock listeners have never been reached from a real host. There is no arm64 build yet. See [Implementation status](../IMPLEMENTATION_STATUS.md).

Source: [`guest/vesta-guestd`]({{ site.vesta_repo_url }}/blob/main/guest/vesta-guestd/src/main.rs). Crate: Rust 2021, MSRV 1.85, libbpf-rs 0.27.2 (vendored libbpf 1.7.0), prost 0.14, tokio, tokio-vsock 0.7.2. The release binary is fully static (musl, `x86_64-unknown-linux-musl`).

## Command line

```text
vesta-guestd [--config PATH] [--check-config] [--version]
```

| Flag | Effect |
|---|---|
| `--config PATH` | Config file. Default `/etc/vesta/guestd.toml`. A missing file means defaults (with a warning). |
| `--check-config` | Parse and validate the config, print `<path>: OK`, exit. The image build runs this on the rendered config. |
| `--version` | Print `vesta-guestd <version> (abi 1)`. |

Any other argument prints the usage and exits with status 2. Logs go to stderr through `tracing`; the systemd unit sends stdout and stderr to `/dev/console`.

## Configuration

`/etc/vesta/guestd.toml` is baked into the read-only guest image. Unknown keys are rejected and every value is range-checked. The example with defaults is [`guestd.example.toml`]({{ site.vesta_repo_url }}/blob/main/guest/vesta-guestd/guestd.example.toml).

| Key | Default | Valid range / notes |
|---|---|---|
| `guest_image_version` | `0.0.0` | Semver without build metadata, at most 63 bytes. The image build sets the real version. Reported in `HelloReply`. |
| `ctrl_port` | `22085` | 1024 or higher, not a Kata port (1024 to 1027), different from `evt_port` |
| `evt_port` | `22086` | Same rules |
| `allowed_peer_cid` | `2` | Only this vsock CID is served (2 is the host). Must not be `u32::MAX`. |
| `pin_root` | `/sys/fs/bpf/vesta` | Absolute, no `..` or NUL. Its parent must be (or become) a bpffs. |
| `cgroup_root` | `/sys/fs/cgroup` | Absolute. Must be cgroup2. |
| `container_rootfs_base` | `/run/kata-containers` | Container rootfs is `<base>/<container-id>/rootfs` |
| `heartbeat_interval_ms` | `5000` | 100 to 60000 |
| `ringbuf_bytes` | `4194304` (4 MiB) | Power of two, page size to 256 MiB |
| `replay_max_events` | `16384` | 1 to 1000000 |
| `replay_max_bytes` | `8388608` (8 MiB) | 64 KiB to 256 MiB, approximate heap size |
| `bind_timeout_ms` | `10000` | 100 to 120000 |
| `bind_poll_ms` | `20` | 5 to 1000 |
| `frame_timeout_ms` | `10000` | 100 to 120000 |
| `write_timeout_ms` | `10000` | 100 to 120000 |
| `gc_interval_ms` | `30000` | 1000 to 3600000 |
| `capture_argv` | `true` | Sets `VESTA_CFG_EXEC_ARGV` in the `config` map |
| `audit_unbound_exec` | `false` | Sets `.rodata audit_unbound_exec`: P1 also reports execs in unbound cgroups |
| `allow_enforce` | `true` | Accept `MODE_ENFORCE` bundles (also needs the bpf LSM active and P2 attached) |
| `protected_cgroups` | `["system.slice/kata-agent.service"]` | At most 64 paths relative to `cgroup_root`. guestd's own cgroup is always added. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `[baseline] mode` | `audit` | `audit` or `enforce` (`enforce` needs `allow_enforce`). Applies to bindings whose policy generation is not applied yet. |
| `[baseline] failure` | `open` | `open` or `closed` |

## Startup sequence

`main` parses arguments and the config, starts a single-threaded tokio runtime (`current_thread` plus a `LocalSet`), and runs `server::run`:

1. **Environment.** Read the active LSM list from `/sys/kernel/security/lsm` (mounting securityfs first if it is not mounted), the kernel release, and whether `cgroup_root` is cgroup2.
2. **Load** (`load_bpf`), in this order, so that nothing new is attached if an earlier step fails:
   1. Require cgroup v2.
   2. Make sure the parent of `pin_root` is a bpffs, mounting one with `mode=0700` if not. (Under the systemd unit, mount syscalls are not allowed; systemd mounts `/sys/fs/bpf` itself.)
   3. Create `<pin_root>/maps` and `<pin_root>/links`.
   4. Skip P2 if `bpf` is not an active LSM, recording the reason.
   5. Open the embedded skeleton. Refuse it if its `.rodata` ABI version is not 1. Set `audit_unbound_exec` and the ring buffer size.
   6. Decide which pinned maps to reuse (see [Restart and adoption](#restart-and-adoption)) and point every ABI map at its pin path.
   7. Load. If the whole object fails, load each program alone to find the ones that fail, record their error and verifier log (up to 64 KiB), and load the rest together.
   8. Write the `config` map (ABI version, flags, guestd's cgroup id, its executable's inode and `s_dev`, heartbeat interval) and freeze it. If `config` was reused, only check its ABI version.
   9. If maps were reused, read their contents back for adoption.
   10. Open the event seq store at `<pin_root>/state/event_seq`.
   11. Attach every loaded program and pin its link at `<pin_root>/links/<program name>`.
3. **Degraded mode.** If loading fails as a whole, guestd keeps running: `Hello` and `GetStatus` report every program as `FAILED` with the error, and `ApplyPolicy`, `BindContainer` and `SetMode` are refused because every map write fails.
4. **Engine.** Enforcement is supported when `allow_enforce` is true, `bpf` is an active LSM and P2 (`exec_lsm`) is attached. Adopted state and protected cgroups are loaded into the policy engine, and the event hub continues the persisted seq.
5. Start the ring buffer consumer, then send `READY=1` with `STATUS=attached: <features>` to systemd.
6. Start the CTRL and EVT listeners and the cgroup GC loop.
7. On `SIGTERM` or `SIGINT`: send `STOPPING=1`, persist the exact last event seq, and exit. **Pinned links stay attached.**

## Modules

| Module | Role |
|---|---|
| `main` | Argument parsing, config load, logging, single-threaded runtime |
| `config` | `guestd.toml` schema, defaults and validation |
| `server` | Startup sequence, vsock listeners with the peer check, ring buffer consumer, cgroup GC, signals |
| `daemon` | Shared state (`Rc<RefCell<Daemon>>`), the `BpfControl` and `CgroupLookup` traits, and `Unavailable` maps for degraded mode |
| `bpf` | Skeleton load, per-program failure isolation, map pinning and reuse, link attach and pin, detach for the kill switch, drop counters, the pinned event seq map. Contains the only `unsafe` code (the generated skeleton). |
| `abi` | `#[repr(C)]` mirror of `vesta_abi.h` with const size assertions and field-by-field encoding, no transmutes. A test parses the header's `_Static_assert`s and `#define`s and compares them. |
| `codec` | Frame codec: 4-byte big-endian length, 1 byte to 1 MiB, then one protobuf message |
| `proto` | prost types generated from `api/proto` by `build.rs`; protocol version 1.0 |
| `ctrl` | CTRL connection: Hello handshake, then `ApplyPolicy`, `BindContainer`, `Unbind`, `SetMode`, `GetStatus` |
| `evt` | EVT connection: `Subscribe`, event batches, cumulative acks, heartbeats |
| `policy` | Pure validation and compilation of `ApplyPolicy` into map keys; the policy hash |
| `state` | Policy engine: applied policy plus bindings give the desired map state, which is diffed against what is installed |
| `cgroup` | OCI `cgroupsPath` to guest cgroup directory, confined lookup, cgroup ids, the GC walk |
| `resolve` | Exec rule path to `(s_dev, ino)` inside a container's rootfs |
| `events` | Ring buffer record to `vesta.event.v1.Event`, replay buffer, event seq reservation |
| `sysinfo` | LSM list, cgroup2 and bpffs checks, kernel release, RSS and CPU usage, `sd_notify` |

## Channel

### Transport and framing

guestd listens on vsock CID `VMADDR_CID_ANY` on `ctrl_port` and `evt_port`. For every accepted connection:

- **Peer check.** A peer whose CID is not `allowed_peer_cid` (2, the host) is logged and dropped. In-guest processes therefore cannot reach guestd through vsock loopback.
- **One connection per port.** A new connection from the host replaces the previous one on the same port, whose task is aborted.
- **Framing.** Each message is a big-endian `u32` length N (1 to 1 MiB) followed by N bytes of protobuf. The length is checked before allocating. Waiting for the first byte of a frame has no deadline; the rest must arrive within `frame_timeout_ms`. Each write must finish within `write_timeout_ms`.

### CTRL requests

The first request must be `Hello` with protocol major 1; anything else gets an `Error` and the connection is closed. `request_id` must be non-zero. Requests are handled in order, but a `BindContainer` completes in its own task, so responses can arrive out of order. The response queue holds 256 messages.

| Request | Response | Notes |
|---|---|---|
| `Hello` | `HelloReply` | Protocol 1.0, guest image version, kernel release, active LSMs, `cgroup_v2`, features, guestd version, ABI version 1, program status with errors and verifier logs, global mode, applied generation. Features are the attached programs' strings plus `bpf_lsm` and `enforce` when they apply. |
| `ApplyPolicy` | `Ack` or `Error` | See [Policy reconcile](#policy-reconcile). |
| `BindContainer` | `Ack` or `Error` (later) | See [Bind lifecycle](#bind-lifecycle). At most 256 binds may be pending; more get `LIMIT_EXCEEDED`. |
| `Unbind` | `Ack` | Removes the binding and reconciles. Unbinding an unknown container succeeds with a warning. |
| `SetMode` | `Ack` | `DETACHED`: write `global_mode`, then detach every program (unpin and close its link). Other modes: re-attach programs first, then write `global_mode`. |
| `GetStatus` | `Status` | Programs, applied generation, policy hash, drop counters, global mode, up to 1024 bound containers. |

A second `Hello` on the same connection is a `MALFORMED` error.

## Policy reconcile

`ApplyPolicy` is validated completely before any state changes (`policy::compile`):

| Check | Limit |
|---|---|
| `generation` | Greater than 0. Lower than the applied generation is rejected; equal is a no-op `Ack`. |
| Bundles | At most 256, `policy_id` 1 to 1024 and unique, name at most 253 bytes, `schema_version` 1 |
| Mode | `MODE_ENFORCE` is rejected when enforcement is not supported in this guest |
| Exec rules | At most 4096 per bundle and 65536 in total; `rule_id` > 0; absolute path, at most 4096 bytes, no `..` or NUL; verdict must be `ALLOW` or `DENY` |
| Net rules | At most 1024 per bundle; `rule_id` > 0; canonical CIDR (host bits zero); known protocol; at most 64 ports, each 1 to 65535; at most 16384 keys per address family |

Duplicate net keys are resolved deterministically: `DENY` wins, then the lowest `rule_id`, and a warning is returned. Unspecified default verdicts mean allow.

The policy hash reported in `Status` and heartbeats is SHA-256 over the protobuf encoding of `ApplyPolicy{generation: 0, bundles}` with bundles sorted by `policy_id`.

After validation, the engine computes the **desired** map state and diffs it against the **installed** state it tracks:

1. Resolve the exec rules of every bound container against its rootfs (below).
2. Write new or changed `exec_rules`, `net_rules_v4` and `net_rules_v6` entries.
3. Write new or changed `cgroup_policy` entries, then delete stale ones.
4. Delete stale rule entries.
5. Set `policy_ready` to the new generation.

Rules are written before the cgroup entries that reference them, and cgroup entries are removed before their rules. If any write fails, the previous policy is restored and reconciled again, and the `Ack` carries `ok = false` with the applied (old) generation.

**Exec rule resolution.** An exec rule is a path, but the map key is `(policy_id, s_dev, ino)`, because the same path is a different file in every image. For each bound container with a policy, guestd opens `<container_rootfs_base>/<container-id>/rootfs` and resolves the path with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` and `O_PATH`, so symlinks and `..` in the untrusted image stay inside that rootfs and nothing is opened for I/O. The target must be a regular file. A path that does not resolve is not an error: it becomes a warning in the `Ack` (at most 64 warnings of 256 bytes). Rules are resolved when a policy is applied and when a bind completes, not when files change later.

A bound container whose policy ID is no longer in the applied policy becomes monitor-only (a warning says so).

## Bind lifecycle

`BindContainer` carries the CRI container ID, the OCI `linux.cgroupsPath` verbatim, a `policy_id` (0 = monitor only), a rootfs type (always `UNKNOWN` from the current agent) and a policy generation.

1. **Prepare** (`bind_prepare`), synchronously:
   - validate the container ID (`[A-Za-z0-9_.-]`, 1 to 128 bytes, not `.` or `..`);
   - map `cgroupsPath` to a directory under `cgroup_root` with kata-agent 4.2's rules: `slice:prefix:name` becomes `<expanded slice>/<prefix>-<name>.scope` (`::` means `system.slice:kata_agent:<cid>`), anything else has `:` replaced by `/`, and an empty path becomes `/<cid>`. `.` and `..` components are rejected, and at most 32 levels are allowed;
   - refuse the bind if that directory is a protected cgroup or an ancestor of one (guestd's own, `system.slice/kata-agent.service`), because the BPF ancestor lookup would then apply the policy to guestd or kata-agent;
   - refuse a `policy_id` above 1024, and return `NOT_FOUND` for a `policy_id` not in the applied generation when the requested generation is already applied;
   - refuse more than 4096 bindings.
2. **Wait.** A task polls for the cgroup every `bind_poll_ms`. The lookup opens the path with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` and requires a cgroup2 filesystem; the cgroup id is the directory's inode number. If a newer bind for the same container arrives, the older one is acked `ok = false` ("superseded").
3. **Complete** (`bind_complete`) once the cgroup exists: refuse it if that cgroup is already bound to another container, check that the exec rules still fit the map, take over any adopted orphan entry for that cgroup, resolve the container's exec rules, and reconcile. On failure, the previous state is restored.
4. **Ack.** `ok = true` with the binding's generation. If the requested generation is not applied yet, the binding is written with `VESTA_CGF_PENDING` and the `[baseline]` mode and failure, and the ack carries the **applied** generation plus a warning, so the host gate does not treat it as confirmed.
5. **Timeout.** If the cgroup does not appear within `bind_timeout_ms`, the pending bind is dropped and acked `ok = false`, generation 0.

A **re-bind** of a container that is already bound keeps the live binding in force until the new one completes, so a re-bind never opens a gap. The engine is keyed by container ID; the cgroup id to container ID map is refreshed after every change and used to fill `container_id` in events.

**Garbage collection.** Every `gc_interval_ms`, guestd walks the cgroup tree (at most 65536 directories, 32 levels, tolerating cgroups that vanish during the walk) and removes bindings and adopted entries whose cgroup id no longer exists. The walk runs on guestd's single thread.

## Events

### Ring buffer consumption

The consumer waits on the ring buffer's epoll fd through tokio (with a 1 s tick as a safety net) and handles at most 1024 records per turn before yielding. Each record is size-checked and decoded field by field. Malformed records are counted and dropped, and never panic. Each event gets:

- a seq number, assigned in order;
- `guest_wall_unix_ns` = `ktime_boot_ns` plus the current `CLOCK_REALTIME - CLOCK_BOOTTIME` offset (refreshed before each batch);
- `container_id` from the bound cgroup id;
- the exe path (length clamped), argv split on NUL (at most 256 entries), flags, policy reference and connect details.

The process ancestry chain (`Event.chain`) is **not filled** yet.

### Replay buffer and backpressure

Events stay in a bounded replay buffer until the host acks them. The buffer has two queues: `DENIED` events, and everything else. When it exceeds `replay_max_events` or `replay_max_bytes` (an estimate of heap size, not encoded size), the oldest `AUDITED`/`ALLOWED` event is evicted first, and a `DENIED` event only when no other is left. Every eviction is counted and reported as `channel_drops` in heartbeats.

On the EVT connection:

- The host's first message must be `Subscribe` within 10 s, with protocol major 1.
- The stream starts at `from_seq`, or at the oldest buffered event if that is later. A `from_seq` beyond the last assigned seq (the host saw a stream this guestd does not continue) restarts from the oldest buffered event.
- Batches hold at most 512 events and fit in one 1 MiB frame. At most 8 batches are sent before acks and the heartbeat get a turn, so a flood cannot starve them.
- `EventAck` is cumulative and frees everything up to the acked seq.
- Anything else from the host, such as a second `Subscribe`, closes the stream with `MALFORMED`.

If the host reads slowly, writes block (bounded by `write_timeout_ms`), the buffer fills, and eviction starts. The BPF programs are never slowed: a full ring buffer only increments `drop_counters`.

### Event seq persistence

Seqs are monotonic per guest boot. guestd reserves them in blocks of 1024 in the pinned map `<pin_root>/state/event_seq` before using them, and writes the exact last seq on a clean shutdown. After a crash, the restarted guestd continues above the reserved block, so the host sees a gap of up to 1024. That gap is real: the old replay buffer is lost with the process. If the seq map cannot be used, numbering restarts at 1 and the host reports a seq regression.

### Heartbeat

Every `heartbeat_interval_ms` guestd builds a fresh heartbeat (heartbeats are never buffered):

| Field | Content |
|---|---|
| `seq` | Heartbeat counter, starts at 1 per guestd process |
| `last_event_seq` | Highest event seq assigned |
| `applied_generation`, `policy_hash` | What is in force |
| `progs` | Program status without error text or verifier logs |
| `ringbuf_drops` | `drop_counters` summed over CPUs, non-zero types only |
| `channel_drops` | Replay buffer evictions |
| `guestd_rss_bytes`, `guestd_cpu_ns` | From `/proc/self/statm` and `/proc/self/stat` |
| `global_mode`, `interval_ms` | Current kill switch and interval |

## Restart and adoption

guestd is expected to restart (`Restart=always`, no start limit). Within one guest boot:

- **Links.** For each program, the new link is attached first, then the old pin at `<pin_root>/links/<name>` is removed and the new link pinned. There is no enforcement gap.
- **Maps.** A pinned map is compatible if its type, key size, value size, max entries and flags match the new object. The seven policy-state maps (`config`, `global_mode`, `policy_ready`, `cgroup_policy`, `exec_rules`, `net_rules_v4`, `net_rules_v6`) are reused **all together or not at all**; if any is missing or incompatible, all of them are replaced with empty maps and a warning is logged. `events` and `drop_counters` are reused individually when compatible. A reused `config` must carry ABI version 1.
- **Adoption.** Reused `cgroup_policy` entries become orphans that keep enforcing until the host binds that cgroup again or GC removes them. Adopted rules stay installed while an orphan references their `policy_id` (net rules until that policy ID is applied again). The adopted `global_mode` is kept.
- **Open items.** After a restart, `HelloReply` reports `applied_generation = 0` until the host re-applies, `Status` does not list orphans, and `policy_ready` keeps the old generation meanwhile.

## Capabilities and systemd unit

guestd runs as root with this capability bounding set ([`vesta-guestd.service`]({{ site.vesta_repo_url }}/blob/main/images/guest/rootfs/files/usr/lib/systemd/system/vesta-guestd.service)):

| Capability | Needed for |
|---|---|
| `CAP_BPF` | Creating maps and loading programs |
| `CAP_PERFMON` | Tracing and LSM program types, tracepoint attach, `bpf_probe_read_kernel` |
| `CAP_NET_ADMIN` | Attaching `cgroup/connect4` and `connect6` |
| `CAP_DAC_READ_SEARCH` | Resolving exec rule paths in container rootfs trees that root does not own |

There is no `CAP_SYS_ADMIN`: program IDs and tags are read from the fds guestd holds (`BPF_OBJ_GET_INFO_BY_FD`), and pins are reopened with `BPF_OBJ_GET`. The smoke test runs load, attach, pin, detach and restart adoption with only these four capabilities (`VESTA_SMOKE_UNIT_CAPS=1`).

| Setting | Value |
|---|---|
| Type, readiness | `Type=notify`, `NotifyAccess=main`, `TimeoutStartSec=10s` |
| Ordering | `DefaultDependencies=no`, `After=sys-fs-bpf.mount systemd-tmpfiles-setup.service`, `Before=kata-agent.service`, `WantedBy=kata-containers.target` |
| Restart | `Restart=always`, `RestartSec=1s`, `StartLimitIntervalSec=0`, `OOMScoreAdjust=-997` |
| Filesystem | `ProtectSystem=strict`, `ReadWritePaths=-/sys/fs/bpf`, `RuntimeDirectory=vesta` (0700), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `ProtectControlGroups`, `UMask=0077` |
| Process | `NoNewPrivileges`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces` |
| Sockets and syscalls | `RestrictAddressFamilies=AF_VSOCK AF_UNIX`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service bpf perf_event_open`, `SystemCallErrorNumber=EPERM` (no mount syscalls) |
| Resources | `TasksMax=64`, `LimitNOFILE=4096`, `LimitCORE=0` |
| Output | `StandardOutput=tty`, `StandardError=tty`, `TTYPath=/dev/console` |

guestd must not mount bpffs under this unit: a mount made in the unit's private mount namespace would hide its pins. It relies on systemd's `sys-fs-bpf.mount`. The kata-agent drop-in and boot ordering are on the [Guest image](guest-image.md#systemd-units-and-boot-ordering) page.

## Build and test

```sh
docker build -f guest/Dockerfile.build -t vesta-guest-build:local guest
guest/hack/in-builder.sh sh -c 'cd guest && cargo test'
make guestd        # static musl release binary in images/guest/out/guestd/<arch>/
make bpf-smoke     # privileged smoke test on the Docker host kernel, unit capabilities only
```

See [Testing](../testing.md) for the full test layout.
