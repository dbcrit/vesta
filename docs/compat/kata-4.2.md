---
title: Kata 4.2 compatibility
parent: Reference
nav_order: 5
---

# Upstream compatibility: Kata Containers 4.2, containerd 2.4, NRI 0.12

Checked 2026-09-29 against source, not memory. Every claim below links to the file that backs it.

| Project | Version checked | Source |
|---|---|---|
| Kata Containers | `4.2.0` (released 2026-09-15) | https://github.com/kata-containers/kata-containers/tree/4.2.0 |
| containerd | `v2.4.1` | https://github.com/containerd/containerd/tree/v2.4.1 |
| NRI | `v0.12.3` | https://github.com/containerd/nri/tree/v0.12.3 |
| mdlayher/vsock | `v1.3.0` | https://pkg.go.dev/github.com/mdlayher/vsock@v1.3.0 |
| Linux (Kata guest kernel) | `v6.18.35` | Kata `versions.yaml` → `assets.kernel.version` |

Short links below use `K:` for `https://github.com/kata-containers/kata-containers/blob/4.2.0/`, `C:` for `https://github.com/containerd/containerd/blob/v2.4.1/` and `N:` for `https://github.com/containerd/nri/blob/v0.12.3/`.

---

## 1. Runtimes, shims, config paths, handler names

**runtime-rs is the default runtime since Kata 4.0. The Go runtime still ships, but is deprecated.** The 4.0.0 release notes say: "the runtime has been rewritten from Go to Rust, and the new runtime ("runtime-rs") serves as the default runtime moving forward", and "The original Go runtime is now deprecated and will not accept newly proposed features. [...] will still receive critical bug fixes and CVE fixes during the deprecation period" (https://github.com/kata-containers/kata-containers/releases/tag/4.0.0). In 4.2 both trees are present (`K:src/runtime`, `K:src/runtime-rs`).

kata-deploy's default shim is `qemu-runtime-rs` on every arch (`K:tools/packaging/kata-deploy/helm-chart/kata-deploy/values.yaml`, `defaultShim:`).

Shim binaries and config files, as installed by kata-deploy (`K:tools/packaging/kata-deploy/binary/src/utils/system.rs`, `get_kata_containers_runtime_path`, `get_kata_containers_original_config_path`, `get_kata_containers_config_path`; `RUST_SHIMS` lists which shims are runtime-rs):

| | Go runtime (shim `qemu`) | runtime-rs (shim `qemu-runtime-rs`) |
|---|---|---|
| Shim binary | `/opt/kata/bin/containerd-shim-kata-v2` | `/opt/kata/runtime-rs/bin/containerd-shim-kata-v2` |
| Pristine config | `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml` | `/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml` |
| Config containerd points at | `/opt/kata/share/defaults/kata-containers/runtimes/qemu/configuration-qemu.toml` | `/opt/kata/share/defaults/kata-containers/runtime-rs/runtimes/qemu-runtime-rs/configuration-qemu-runtime-rs.toml` |
| Drop-ins | `.../runtimes/qemu/config.d/*.toml` | `.../runtime-rs/runtimes/qemu-runtime-rs/config.d/*.toml` |
| Shim management socket | `/run/vc/sbs/<sandbox-id>/shim-monitor.sock` | `/run/kata/<sandbox-id>/shim-monitor.sock` |

`/opt/kata` is the default `dest_dir` (Helm `env.installationPrefix` changes it).

**Handler / RuntimeClass names** are `kata-<shim>` (`K:tools/packaging/kata-deploy/binary/src/config.rs`, `shim_handler`; `K:tools/packaging/kata-deploy/helm-chart/kata-deploy/templates/runtimeclasses.yaml`). So the default is `kata-qemu-runtime-rs`, and `kata-qemu` is the Go-runtime QEMU class. With `env.multiInstallSuffix` the name becomes `kata-<shim>-<suffix>`. Debug variants are `kata-<shim>-debug` / `kata-<shim>-devkit`.

**How containerd passes the per-handler config.** kata-deploy writes (`K:tools/packaging/kata-deploy/binary/src/runtime/containerd.rs`, `write_containerd_runtime_config`):

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-qemu-runtime-rs]   # config v3; v2 uses "io.containerd.grpc.v1.cri"
  runtime_type = "io.containerd.kata-qemu-runtime-rs.v2"
  runtime_path = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.kubernetes.container.terminationMessage*"]
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-qemu-runtime-rs.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/runtime-rs/runtimes/qemu-runtime-rs/configuration-qemu-runtime-rs.toml"
```

Both shims read `options.ConfigPath` from the CRI runtime options (`runtimeoptions.v1.Options`):

- Go: `K:src/runtime/pkg/containerd-shim-v2/create.go`, `loadRuntimeConfig`. Order: task option `ConfigPath`, then env `KATA_CONF_FILE`.
- runtime-rs: `K:src/runtime-rs/crates/runtimes/src/manager.rs`, `load_config`. Order: env `KATA_CONF_FILE`, then the task option.
- **`KATA_CONF_FILE` is only accepted if it resolves to one of the shipped default config paths** (`isShippedKataConfigPath` / `is_shipped_kata_config_path`). `ConfigPath` has no such restriction. **vesta must use `ConfigPath`, not the env var**, and it works the same for both runtimes.
- Both runtimes merge `config.d/*.toml` next to the config file, in lexical order, later files winning (`K:src/libs/kata-types/src/config/drop_in.rs`; `K:src/runtime/pkg/katautils/config.go`, `dropInDir`).

## 2. Discovering a sandbox's agent endpoint

Each shim serves an HTTP API on a Unix socket, at the paths in the table above (`K:src/libs/shim-interface/src/lib.rs`: `SHIM_MGMT_SOCK_NAME = "shim-monitor.sock"`, `KATA_PATH = "/run/kata"`; `K:src/runtime/pkg/containerd-shim-v2/shim_management.go`: `GetSandboxesStoragePath() = "/run/vc/sbs"`, `GetSandboxesStoragePathRust() = "/run/kata"`). `<sandbox-id>` is the CRI pod sandbox ID, which NRI reports as `PodSandbox.id`.

`GET /agent-url` returns the agent address as a **plain-text body** (no JSON, no trailing newline):

| Hypervisor | Body | Source |
|---|---|---|
| QEMU (both runtimes) | `vsock://<guest-cid>:1024` | `K:src/runtime-rs/crates/hypervisor/src/qemu/inner.rs` `get_agent_socket` + `K:src/runtime-rs/crates/agent/src/kata/mod.rs` `agent_sock`; Go `K:src/runtime/virtcontainers/types/sandbox.go` `VSock.String` |
| Cloud Hypervisor, Dragonball, Firecracker | `hvsock://<abs-uds-path>:1024` | `K:src/runtime-rs/crates/hypervisor/src/ch/inner_hypervisor.rs`, `.../dragonball/inner_hypervisor.rs`; Go `HybridVSock.String` |
| remote (peer pods) | `remote://...` | not supported by vesta |

The Go runtime returns HTTP 500 with the error text on failure. runtime-rs returns 200 with an **empty body** when the agent socket is not initialized (`K:src/runtime-rs/crates/runtimes/src/shim_mgmt/handlers.rs`, `agent_url_handler`), so vesta treats an empty body as "not ready".

vesta-agent parses the scheme plus the CID or UDS path, **ignores the port** (1024 is kata-agent), and dials its own port.

**Hybrid vsock handshake.** Connect to the UDS, write `CONNECT <port>\n`, read one line, and check that it starts with `OK` (the full reply is `OK <host-side-port>\n`). The Go runtime sends `CONNECT %d\n` (`K:src/runtime/virtcontainers/pkg/agent/protocols/client/client.go`). runtime-rs sends lowercase `connect {port}\n` and checks `contains("OK")` (`K:src/runtime-rs/crates/agent/src/sock/hybrid_vsock.rs`). Firecracker documents uppercase `CONNECT` (https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md). vesta sends uppercase, reads at most 32 bytes up to `\n` under a deadline, and requires the prefix `OK `.

## 3. vsock ports used in the guest

From `K:src/libs/kata-types/src/config/default.rs`:

| Port | User |
|---|---|
| 1024 | kata-agent ttRPC (`DEFAULT_AGENT_VSOCK_PORT`) |
| 1025 | agent log forwarding (`DEFAULT_AGENT_LOG_PORT`; `K:src/runtime-rs/crates/hypervisor/src/kernel_param.rs` `VSOCK_LOGS_PORT`) |
| 1026 | debug console (`DEFAULT_AGENT_DBG_CONSOLE_PORT`; Go `kernelParamDebugConsoleVPortValue`) |
| 1027 | passfd listener (`DEFAULT_PASSFD_LISTENER_PORT`, Dragonball) |

All of these can be overridden through `agent.*_vport` / `agent.server_addr` kernel params (`K:src/agent/src/config.rs`). The CoCo guest components (attestation-agent, CDH) talk to kata-agent over guest-local sockets, not vsock.

**Decision: vesta CTRL = 22085, EVT = 22086** (0x5645 is ASCII "VE"). These ports are well away from Kata's contiguous 1024+ block, which grows one port per feature. They are not privileged-range values, and they don't clash with common vsock conventions (e.g. Nitro Enclaves 9000). They are set in the guest image config (`/etc/vesta/guestd.toml`) and in vesta-agent flags. Both sides must agree, and the host learns nothing about the ports from the guest.

## 4. Guest: cgroups, init, kernel

**cgroup v2 is already the default.** Kata 4.2 `KERNELPARAMS` for every arch and both runtimes is `cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1` (`K:src/runtime-rs/arch/x86_64-options.mk`, `K:src/runtime/arch/amd64-options.mk`). kata-agent reads the knob `systemd.unified_cgroup_hierarchy` (there is no `agent.unified_cgroup_hierarchy`; `K:src/agent/src/config.rs`, `UNIFIED_CGROUP_HIERARCHY_OPTION`). vesta keeps these params: the vesta drop-in *appends* to the effective `kernel_params` and never replaces them. guestd still checks `/sys/fs/cgroup/cgroup.controllers` and reports `cgroup_v2`.

**Container cgroup paths in the guest.** The runtimes pass the OCI `linux.cgroupsPath` to the agent **unchanged** (no rewrite in `K:src/runtime/virtcontainers/kata_agent.go` `constrainGRPCSpec` or in runtime-rs). kata-agent (`K:src/agent/src/rpc.rs`, `K:src/agent/rustjail/src/container.rs`) handles it like this:

- If it matches the systemd format `slice:prefix:name` and the agent is not PID 1, the agent uses the **systemd** cgroup manager. For example `kubepods-burstable-pod<uid>.slice:cri-containerd:<cid>` becomes `/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope`.
- Otherwise it uses the cgroupfs manager, with `:` replaced by `/`. An empty path becomes `/<cid>`.

guestd must apply the same rules to the `cgroup_path` in `BindContainer`, and confirm the result with a `cgroup_mkdir` observation (see §2.5 in ARCHITECTURE).

**Guest image init.** The default rootfs **image** (`kata-containers.img`, Ubuntu 26.04 "resolute", `K:versions.yaml`) is built with `AGENT_INIT=no`, so it boots **systemd**. The default **initrd** is built with `AGENT_INIT=yes` on all arches except s390x, so kata-agent is PID 1 there (`K:tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh`; `K:tools/osbuilder/rootfs-builder/rootfs.sh`). The runtime boots with `systemd.unit=kata-containers.target` (`K:src/runtime-rs/crates/hypervisor/src/kernel_param.rs`). `kata-containers.target` has `Requires=kata-agent.service`, and `kata-agent.service` is `Type=simple` with `FailureAction=poweroff` (`K:src/agent/kata-containers.target`, `K:src/agent/kata-agent.service.in`).

To start guestd before kata-agent on the image variant:

```ini
# /usr/lib/systemd/system/vesta-guestd.service
[Unit]
DefaultDependencies=no
After=sys-fs-bpf.mount systemd-tmpfiles-setup.service
Before=kata-agent.service
[Service]
Type=notify            # READY=1 only after programs are attached (or after a failure is recorded)
TimeoutStartSec=10s
[Install]
WantedBy=kata-containers.target

# /etc/systemd/system/kata-agent.service.d/10-vesta.conf
[Unit]
Wants=vesta-guestd.service
After=vesta-guestd.service
```

`Wants=` rather than `Requires=`: if guestd fails, the agent still starts (fail-open at boot), and guestd or the host reports the sandbox as degraded. The initrd (`AGENT_INIT=yes`) variant has no init to order against and is out of scope for the MVP (Q7 stays open for it).

**Kernel.** Kata 4.2 ships **Linux 6.18.35** (`K:versions.yaml` `assets.kernel.version`; `kata_config_version` 202). Config fragments (`K:tools/packaging/kernel/configs/fragments/`):

- `common/cgroup.conf` enables `BPF_SYSCALL` and `CGROUP_BPF`.
- `common/lsm.conf` enables SELinux, `common/landlock.conf` enables Landlock, and `common/network.conf` enables `SECURITY`.
- **`BPF_LSM` is not enabled anywhere.**
- **`DEBUG_INFO_BTF` is enabled only in `debug/ebpf.conf`**, which is merged only for debug kernel builds.
- `CONFIG_MODULES` is off for x86_64 and arm64 (it is set only for s390x, the NVIDIA GPU kernels and module signing).

`CONFIG_LSM` is not set, so the 6.18 Kconfig default applies, which already ends in `...,ipe,bpf` (https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/security/Kconfig?h=v6.18.35). **So with `CONFIG_BPF_LSM=y`, `bpf` is active without any `lsm=` boot param.** vesta therefore sets `CONFIG_LSM` in its fragment and does **not** pass `lsm=` on the command line. That avoids overriding Kata's LSM order from the runtime config.

Fragment mechanism (`K:tools/packaging/kernel/build-kernel.sh`, `get_kernel_frag_path`): every `common/*.conf` (unless tagged `# !<arch>`) plus `<arch>/*.conf` is merged with `scripts/kconfig/merge_config.sh`. The build fails if a requested option is missing from the final `.config` (unless `-s` is passed or it is whitelisted). `-b <type>` adds `build-type/<type>/*.conf`, and `-d`/debug adds `debug/*.conf`. **vesta builds with its fragment as a build type: `build-type/vesta/vesta.conf`, `build-kernel.sh -b vesta ...`.**

## 5. kata-deploy: node label, custom runtimes (Q18), containerd config

- **Node label:** `katacontainers.io/kata-runtime=true`, shared by every kata-deploy instance. Each instance also sets `kata-deploy.katacontainers.io/<suffix|default>` (`K:tools/packaging/kata-deploy/binary/src/main.rs` `KATA_RUNTIME_LABEL`, `INSTANCE_LABEL_PREFIX`). kata-deploy's RuntimeClasses use `scheduling.nodeSelector: katacontainers.io/kata-runtime: "true"`.
- **Custom runtimes exist (answers Q18 in part).** Helm `customRuntimes.enabled` / `customRuntimes.runtimes.<name>: {baseConfig, dropIn, runtimeClass, containerd.snapshotter}` (`K:tools/packaging/kata-deploy/helm-chart/kata-deploy/values.yaml`; `K:tools/packaging/kata-deploy/binary/src/config.rs` `parse_custom_runtimes`). For each one, kata-deploy:
  - copies the base config to `/opt/kata/share/defaults/kata-containers/custom-runtimes/<handler>/configuration-<base>.toml`,
  - writes its common drop-ins plus the user `dropIn` into `.../config.d/`,
  - registers the handler with `ConfigPath` pointing there (`K:tools/packaging/kata-deploy/binary/src/artifacts/install.rs` `install_custom_runtime_configs`; `runtime/containerd.rs` `configure_custom_containerd_runtime`).

  It does **not** copy arbitrary guest assets (kernel/image), and it owns and deletes that directory on uninstall. vesta can use this ("kata-deploy integration mode"): vesta-install places the kernel and image under `/opt/vesta/kata/` and the user adds a `customRuntimes.runtimes.kata-qemu-vesta` entry whose `dropIn` points at them. vesta's default mode stays self-registration, because it doesn't require changing the cluster's kata-deploy values and it keeps vesta's lifecycle independent.
- **How kata-deploy writes containerd config** (`K:tools/packaging/kata-deploy/binary/src/config.rs` `get_containerd_paths`):
  - containerd ≥ 2.2 whose main config imports `/etc/containerd/conf.d` (containerd's built-in default include pattern is `/etc/containerd/conf.d/*.toml`, `C:defaults/defaults_unix.go` `DefaultConfigIncludePattern`): the drop-in goes to `/etc/containerd/conf.d/kata-deploy.toml` and the main config is not touched.
  - Older containerd: the drop-in goes to `/opt/kata/containerd/config.d/kata-deploy.toml` and its path is appended to `imports` in `/etc/containerd/config.toml`.
  - **k3s / RKE2:** the drop-in goes to `config-v3.toml.d/kata-deploy.toml` (containerd config v3) or `config.toml.d/` (v2), next to the template `config-v3.toml.tmpl` in `/var/lib/rancher/{k3s,rke2}/agent/etc/containerd/` (host paths from `K:tools/packaging/kata-deploy/helm-chart/kata-deploy/templates/_helpers.tpl`). kata-deploy **requires the rendered config to already import that directory** and bails otherwise. The plugin id is `io.containerd.cri.v1.runtime` (v3) or `io.containerd.grpc.v1.cri` (v2).
  - k0s: `containerd.d/kata-deploy.toml` next to k0s's `containerd.toml`, auto-loaded. microk8s: the drop-in is imported from `containerd-template.toml`.
- **Runtime entry:** `runtime_type = "io.containerd.<handler>.v2"` plus `runtime_path` set to the shim binary, as shown in §1.

## 6. NRI v0.12.3 plugin API

Stub constructor: `stub.New(plugin any, opts ...stub.Option) (stub.Stub, error)`, then `Run(ctx)` (`N:pkg/stub/stub.go`). Options: `WithPluginName`, `WithPluginIdx` (two digits, sets ordering), `WithSocketPath` (default `/var/run/nri/nri.sock`, `N:pkg/api/plugin.go`), `WithOnClose`, `WithDialer`, `WithLogger`. The plugin implements only the interfaces it needs:

```go
Configure(ctx context.Context, config, runtime, version string) (api.EventMask, error)
Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error)
RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error
StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error
RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error
CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error)
StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error
RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error
Shutdown(ctx context.Context)
```

**Failing or delaying a start.** Returning an error from `RunPodSandbox`, `CreateContainer` or `StartContainer` fails the CRI call:

- `NRI RunPodSandbox failed: ...` (`C:internal/cri/server/sandbox_run.go`)
- `NRI container start failed: ...`, raised *before* `task.Start` (`C:internal/cri/server/container_start.go`)

The runtime aborts on the first plugin error (`N:pkg/adaptation/adaptation.go`). A delay is done by blocking inside the handler. Two constraints apply:

1. **Plugin request timeout:** 2 s by default (`N:pkg/api/timeouts.go` `DefaultPluginRequestTimeout`), configurable in containerd with `[plugins."io.containerd.nri.v1.nri"] plugin_request_timeout` (`C:internal/nri/config.go`).
2. **The adaptation holds one mutex across all plugin calls** (`r.Lock()` in every `Adaptation` method), so a blocked vesta handler stalls NRI processing for *every* pod on the node.

vesta therefore:

- returns immediately for pods whose `runtime_handler` isn't a vesta handler,
- bounds every wait below the request timeout (default budget 1500 ms),
- and does the rest asynchronously.

NRI is enabled by default in containerd 2.x (`C:internal/nri/config.go` `DefaultConfig`: `Disable: false`).

**Timing.** `RunPodSandbox` fires after the sandbox controller has started the sandbox: the VM is up and the shim is serving (`C:internal/cri/server/sandbox_run.go`; the sandbox pid is recorded right before the NRI call). The shim management socket and vsock are therefore reachable at `RunPodSandbox` (answers Q13's timing question).

**Available data** (`N:pkg/api/api.proto`):

- `PodSandbox{id, name, uid, namespace, labels, annotations, runtime_handler, linux{pod_overhead, pod_resources, cgroup_parent, cgroups_path, namespaces, resources}, pid, ips}`.
- `Container{id, pod_sandbox_id, name, state, labels, annotations, args, env, mounts, hooks, linux{namespaces, devices, resources, oom_score_adj, cgroups_path, ...}, pid, rlimits, ..., user, image{name, digest, config_digest}}`.

**`runtime_handler` gives the handler directly**, so vesta doesn't need a RuntimeClass lookup to identify vesta pods. `Container.linux.cgroups_path` is the OCI path that kata-agent receives (§4). `Container.image.digest` feeds `Host.image_digest`.

## 7. Other items checked

- **virtio-serial** is still used for the console (`K:src/runtime-rs/crates/hypervisor/src/qemu/cmdline_generator.rs`), but not as an agent channel. vsock is the only agent transport (Q14).
- **agent.proto has no eBPF RPC** (`K:src/libs/protocols/protos/agent.proto`, no `bpf` match) (Q1).
- **Default shared filesystem:** `shared_fs = virtio-fs` for `qemu-runtime-rs` (`K:src/runtime-rs/Makefile` `DEFSHAREDFS_QEMU_VIRTIOFS := virtio-fs`) (§2.6 / Q8).
- **Agent policy:** `K:src/kata-opa/allow-all-except-exec-process.rego` denies `ExecProcessRequest` and allows `CopyFileRequest` by default. Whether `CopyFile` is denied depends on the genpolicy-generated policy, not the default.
- **Annotations:** kata-deploy handlers allow `pod_annotations = ["io.katacontainers.*"]`. Which hypervisor fields a pod may override is limited by `enable_annotations` in the runtime config. **vesta's drop-in must make sure `enable_annotations` does not include `kernel`, `image`, `initrd`, `kernel_params`, `firmware` or `path`.** Otherwise a pod could boot a non-vesta guest or drop `lockdown=` under the vesta handler.
- **mdlayher/vsock v1.3.0:** `vsock.Dial(contextID, port uint32, cfg *vsock.Config) (*vsock.Conn, error)`. There is no context-aware dial, so vesta sets deadlines on the returned conn and runs the dial in a goroutine bounded by a context.

## 8. Still unverified

- Whether AF_VSOCK on the host is network-namespace-aware on the node's kernel. vesta-agent runs with `hostNetwork: true` to avoid depending on it.
- containerd 1.7: not a target. Kata 4.x kata-deploy still handles config v2, but vesta supports containerd ≥ 2.0 only.
