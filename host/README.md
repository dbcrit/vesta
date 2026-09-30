# host/

Go code for the node side. It uses the single Go module at the repo root, `github.com/dbcrit/vesta` (placeholder path).

**Owner:** the host implementer. Linux builds and tests run in Docker (`hack/go-docker.sh go test ./...`; for `-race`, run the same image with `CGO_ENABLED=1`).

| Path | Contents |
|---|---|
| `cmd/vesta-agent` | DaemonSet binary: NRI plugin, sandbox registry, channel, event export, metrics |
| `cmd/vesta-install` | init container: installs the `kata-qemu-vesta` runtime on the node |
| `internal/wire` | framing: u32 BE length, 1 B to 1 MiB, per-frame deadline |
| `internal/transport` | `/agent-url` discovery on the shim management socket; vhost-vsock and hybrid-vsock dialers |
| `internal/sandbox` | per-sandbox session: Hello, ApplyPolicy, SetMode, BindContainer, EVT stream, heartbeat monitor |
| `internal/nriplugin` | NRI v0.12 plugin and gate logic (§2.9) |
| `internal/policy` | static `VestaPolicy` file: strict parsing, validation, compilation to `PolicyBundle` |
| `internal/events` | event validation, host enrichment, JSON-lines exporter, rate-limited pipeline |
| `internal/metrics` | Prometheus metrics (§2.7) |
| `internal/agentconfig` | agent flags and optional YAML config |
| `internal/hostfs` | no-symlink-following, atomic file operations under a host root |
| `internal/install` | installer: Kata detection, assets, runtime config, containerd drop-in, restart, node label |

Policy API types (`vesta.dev/v1alpha1`) are in `api/v1alpha1`.

## vesta-agent

```
vesta-agent -node-name $NODE_NAME -policy-file /etc/vesta/policy/policy.yaml
```

`vesta-agent -h` lists every flag. `-config` names an optional YAML file with the same fields (`nodeName`, `handlers`, `gateTimeout`, ...); flags override it. Unknown fields are errors.

- Acts only on pods whose NRI `runtime_handler` is in `-handlers` (default `kata-qemu-vesta`). Every other pod returns at once.
- `RunPodSandbox` starts the sandbox session asynchronously. The session discovers the guest endpoint with `GET /agent-url`, dials CTRL (22085) and EVT (22086), sends Hello, ApplyPolicy and (if needed) SetMode, then subscribes to events.
- `CreateContainer` waits (bounded by `-gate-timeout`, default 1500 ms) for the channel to be ready and sends `BindContainer`. It does not wait for the ack, because the guest acks only after kata-agent creates the cgroup, which happens after this hook returns.
- `StartContainer` waits for the bind ack, bounded by `-gate-timeout`. On failure or timeout, `failurePolicy: Closed` fails the start. `Open` lets the container run and counts it as `unmonitored`.
- `Synchronize` (on every NRI (re)connect) rebuilds the registry and rebinds running containers. The plugin re-registers after the NRI connection drops.
- Events go to **stdout** as JSON lines with OpenTelemetry attribute names. Logs go to stderr. Only `k8s.*`, `container.*`, `vesta.sandbox.id`, `vesta.runtime_handler`, `vesta.policy.name` and `vesta.policy.namespace` are host-set. Pod, namespace, container and image come only from NRI, looked up by the guest-reported container ID within the same sandbox. Every other attribute (`process.*`, `network.*`, `vesta.action`, `vesta.hook`, `vesta.flags`, the policy, rule and cgroup ids, and everything under `vesta.guest.*`) is guest-asserted: the host only checks bounds and enum values, so a compromised guest can forge it for its own events.
- `/metrics`, `/healthz` and `/readyz` (ready once the NRI plugin is registered) are served on `-metrics-addr` (default `127.0.0.1:9464`; empty disables). They are unauthenticated and the agent uses the host network, so the chart binds them to the node IP only when the Service or PodMonitor is enabled (`metrics.exposeOnNodeIP`).
- Policy is loaded once at start (Phase 1). Changing it needs an agent restart. Phase 2 adds CRD watches.

### Host access vesta-agent needs

| Access | Why |
|---|---|
| `/var/run/nri/nri.sock` (hostPath) | NRI plugin registration |
| `/run/kata`, `/run/vc/sbs` (hostPath, read-only is enough for socket connect) | shim management sockets (`shim-monitor.sock`), hybrid vsock UDS |
| `/dev/vhost-vsock` is **not** needed | the host side of AF_VSOCK needs only the `vsock` socket family |
| `hostNetwork: true` | AF_VSOCK network-namespace awareness on the host is unverified (compat §8) |
| uid 0 | the NRI socket and Kata sockets are root-owned. No Linux capabilities are needed: drop `ALL`, `allowPrivilegeEscalation: false`, read-only root filesystem |

It needs no `CAP_BPF`, `CAP_SYS_ADMIN` or host PID namespace, and no Kubernetes API access in Phase 1. Sandbox IDs from NRI are validated (`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`) before a socket path is built from them. Hybrid vsock sockets are dialed only below `-kata-run-dirs`.

## vesta-install

```
vesta-install [install|uninstall] -host-root /host -assets-dir /usr/share/vesta/guest
```

The assets directory in the installer image holds `vmlinux-vesta`, `vesta-guest.img`, `SHA256SUMS` (sha256sum format, exactly those two files) and `VERSION` (semver without build metadata).

`install` does the following:

1. Reads the node's `containerRuntimeVersion` (containerd 2.0 or newer required) and picks the drop-in location the way kata-deploy does:
   - `/etc/containerd/conf.d/vesta.toml` on containerd 2.2 or newer when the main config imports `conf.d`;
   - otherwise `/opt/vesta/containerd/config.d/vesta.toml`, plus an `imports` entry in `/etc/containerd/config.toml`. The original config is backed up once to `config.toml.vesta-backup`, and re-encoding drops its comments;
   - on k3s/RKE2, `config-v3.toml.d/vesta.toml` next to the template. The rendered config must already import it; otherwise the installer fails with instructions.
2. Checks Kata: the runtime-rs shim, `/opt/kata/VERSION` 4.x (tested with 4.2.0), and the qemu-runtime-rs config (kata-deploy's per-shim copy first, then the shipped one) with its `config.d`.
3. Copies the kernel and image into `/opt/vesta/kata/<version>/` with SHA-256 verification before the rename. An installed version is immutable: a different digest for the same version is an error.
4. Writes `configuration-qemu-vesta.toml` (the node's base config, verbatim), its `config.d` drop-ins (verbatim) and `config.d/90-vesta.toml`. That drop-in sets `kernel` and `image`, appends `lockdown=integrity` to the effective `kernel_params`, clears `initrd` if set, and strips `kernel`, `image`, `initrd`, `kernel_params`, `kernel_verity_params`, `firmware` and `path` from `enable_annotations`. The merged result is re-checked.
5. Atomically points `/opt/vesta/kata/current` at the version (relative symlink).
6. Writes the containerd handler drop-in (`ConfigPath = /opt/vesta/kata/current/configuration-qemu-vesta.toml`). Only if the content changed does it restart containerd, through systemd's D-Bus private socket (`-restart systemd`, the default). With `-restart none` it fails and asks the operator to restart instead.
7. Labels the node `vesta.dev/guest-ready=<version>`.

On any failure it removes a stale `guest-ready` label and exits non-zero. Old versions are never deleted by `install` (running VMs may use them).

`uninstall` refuses while pods on the node use a RuntimeClass whose handler is `kata-qemu-vesta`. It removes the label, re-checks for pods (and restores the label if one appeared), removes the drop-in and import, restarts containerd if needed, and deletes `/opt/vesta`.

### Host access vesta-install needs

| Access | Why |
|---|---|
| hostPath mounts under `-host-root`: `/opt/kata` (read), `/opt/vesta` (write), `/etc/containerd` (write), `/var/lib/rancher/{k3s,rke2}/agent/etc/containerd` (write, k3s/RKE2 only) | install files |
| `/run/systemd/private` (hostPath, socket) | `RestartUnit` for containerd/k3s/rke2 |
| uid 0, no Linux capabilities (drop `ALL`) | owner write access to root-owned files, and systemd accepts only uid 0 on its private socket. No host PID namespace, no `nsenter`, no privileged mode |
| RBAC: `get`, `patch` on `nodes`; `list` on `pods`; `list` on `runtimeclasses.node.k8s.io` | runtime version, label, uninstall check |

RBAC cannot scope `nodes` to the pod's own node by name. To limit the patch to its own node and to the `vesta.dev/guest-ready` label, add a ValidatingAdmissionPolicy keyed on the service account's `authentication.kubernetes.io/node-name` claim.

Host writes never follow symlinks. Every path component below the host root is opened with `O_NOFOLLOW` relative to its parent. Files are written to a temporary file, fsynced and renamed, and modes are `0644`/`0755`. A consequence: hosts where `/opt` is itself a symlink (e.g. Fedora CoreOS, `/opt -> var/opt`) are refused. Point `-vesta-prefix`/`-kata-prefix` at the real path there.
