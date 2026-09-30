---
title: Getting Started
nav_order: 2
has_children: true
permalink: /getting-started/
---

# Getting Started

This section covers building vesta from source, installing it on Kata nodes with the Helm chart, configuring it, and running it. This page lists what a node must already have and what vesta installs on it. vesta does not publish release images yet, so every deployment starts from a source build.
{: .fs-5 .fw-300 }

{: .warning }
> vesta is pre-release and has not run end to end inside a Kata VM. The installer changes containerd's configuration and restarts containerd on every node it runs on. Use a disposable test cluster. The open items are listed in [Implementation status](../IMPLEMENTATION_STATUS.md).

1. [Building](building.md): make targets, Docker toolchains, pinned versions, outputs.
2. [Deploying](deploying.md): guest image build, `helm install`, running a pod, checking the install, uninstalling.
3. [Configuration](configuration.md): agent flags and config file, the static policy file, `guestd.toml`, Helm values.
4. [Operations](operations.md): event format, metrics, health endpoints, heartbeats and tamper alerts, kill switch, failure policy, troubleshooting.

## Prerequisites

These are the checks the code actually makes, plus the version tested against.

| Requirement | Detail | Enforced by |
|---|---|---|
| Kubernetes ≥ 1.30 | ValidatingAdmissionPolicy v1, and service account tokens that carry the node name | Chart `kubeVersion: ">=1.30.0-0"` |
| Kata Containers 4.x, installed by kata-deploy | Tested with **4.2.0**. The runtime-rs shim must exist at `<prefix>/runtime-rs/bin/containerd-shim-kata-v2`, with `<prefix>/VERSION` readable. Other 4.x versions install with a warning, other majors fail | `vesta-install` |
| Kata QEMU runtime-rs config | `share/defaults/kata-containers/runtime-rs/runtimes/qemu-runtime-rs/configuration-qemu-runtime-rs.toml` (kata-deploy's per-shim copy), or the pristine `.../runtime-rs/configuration-qemu-runtime-rs.toml`. The config must configure exactly one hypervisor, `[hypervisor.qemu]` | `vesta-install` |
| Kata node label | The DaemonSet runs only on nodes labelled `katacontainers.io/kata-runtime=true`, which kata-deploy sets (`kata.nodeSelector`) | Chart |
| containerd ≥ 2.0 with NRI | The node's `containerRuntimeVersion` must be `containerd://2.x` or newer. NRI is on by default in containerd 2.x. Tested with containerd 2.4.1 and NRI v0.12.3 | `vesta-install` (version), agent (NRI socket `/var/run/nri/nri.sock`) |
| containerd managed by systemd | With `installer.restartContainerd: true` (default), the installer restarts the first active unit among `containerd.service`, or `k3s.service`/`k3s-agent.service`, or `rke2-server.service`/`rke2-agent.service`, over `/run/systemd/private` | `vesta-install` |
| k3s / RKE2 only: config v3 and drop-in import | The rendered `/var/lib/rancher/<k3s\|rke2>/agent/etc/containerd/config.toml` must have `version = 3` and already import `config-v3.toml.d/*.toml`. vesta does not edit the k3s/RKE2 template | `vesta-install` |
| Hypervisor | **QEMU only.** The generated runtime config overrides `[hypervisor.qemu]`. The agent can parse `hvsock://` endpoints (Cloud Hypervisor, Dragonball, Firecracker), but the installer only produces a QEMU runtime | `vesta-install` |
| Architecture | **x86_64 (amd64).** The arm64 BPF object and seccomp profile exist, but there is no arm64 `vesta-guestd` build yet (`make guestd` refuses cross builds) | Makefile |
| Host filesystem | `/opt`, `/opt/vesta` and the containerd config directory must not be symlinks: every host write opens each path component with `O_NOFOLLOW` | `vesta-install` (`host/internal/hostfs`) |
| Pod Security | The release namespace must allow the `privileged` level (hostNetwork, hostPath volumes) | Kubernetes admission |
| Build host | Docker and GNU make. Everything Linux-specific runs in containers, so macOS works. The guest rootfs build needs privileged containers (loop device). No KVM needed to build | Makefile |

## What gets installed where

### On each Kata node (by the chart and `vesta-install`)

| Path or object | Written by | Contents |
|---|---|---|
| `/opt/vesta/kata/<version>/vmlinux-vesta` | vesta-install | Guest kernel, SHA-256 checked against `SHA256SUMS`. A version directory is never overwritten with different content |
| `/opt/vesta/kata/<version>/vesta-guest.img` | vesta-install | Guest rootfs image, SHA-256 checked |
| `/opt/vesta/kata/<version>/configuration-qemu-vesta.toml` | vesta-install | Copy of the node's Kata QEMU runtime-rs config |
| `/opt/vesta/kata/<version>/config.d/` | vesta-install | The node's Kata drop-ins, copied verbatim, plus `90-vesta.toml` (below) |
| `/opt/vesta/kata/current` | vesta-install | Symlink to `<version>`, switched atomically |
| `/etc/containerd/conf.d/vesta.toml` | vesta-install | Runtime handler drop-in, on containerd ≥ 2.2 whose `config.toml` imports `/etc/containerd/conf.d` |
| `/opt/vesta/containerd/config.d/vesta.toml` plus an `imports` entry in `/etc/containerd/config.toml` | vesta-install | Same drop-in on containerd 2.0/2.1, or when `conf.d` is not imported. The original `config.toml` is saved once as `config.toml.vesta-backup` |
| `/var/lib/rancher/<k3s\|rke2>/agent/etc/containerd/config-v3.toml.d/vesta.toml` | vesta-install | Same drop-in on k3s / RKE2 |
| Node label `vesta.dev/guest-ready=<version>` | vesta-install | Set after a successful install. Removed when an install fails and on uninstall |
| `<kubelet.rootDir>/seccomp/vesta/vesta-agent.json` | `seccomp-profile` init container | containerd's default seccomp profile plus `socket(AF_VSOCK)` |

`90-vesta.toml` overrides only four things in the node's effective QEMU config:

- `kernel` and `image` point at the files in the version directory, and `initrd` is cleared if the base config set one.
- `kernel_params` keeps the node's parameters, drops any `lockdown=` and appends `lockdown=integrity`. An existing `lsm=` without `bpf` is an error.
- `enable_annotations` loses `kernel`, `image`, `initrd`, `kernel_params`, `kernel_verity_params`, `firmware` and `path`, so a pod cannot boot a different guest through annotations.

The containerd drop-in registers handler `kata-qemu-vesta` with `runtime_type = "io.containerd.kata-qemu-vesta.v2"`, the Kata runtime-rs shim as `runtime_path`, and `options.ConfigPath = /opt/vesta/kata/current/configuration-qemu-vesta.toml`. With `nri.defaultValidator: true` (default) it also enables containerd's NRI default validator. See [Deploying](deploying.md#failurepolicy-closed-and-the-nri-plugin) for why.

### In the cluster (by the chart)

| Object | Name (release `vesta`) | Purpose |
|---|---|---|
| DaemonSet | `vesta-agent` | Init containers `seccomp-profile` and `vesta-install`, then container `vesta-agent` |
| RuntimeClass | `kata-qemu-vesta` | `handler: kata-qemu-vesta`, overhead 352Mi / 250m, `scheduling.nodeSelector: vesta.dev/guest-ready: <guestVersion>` |
| ConfigMaps | `vesta-agent`, `vesta-policies` (only with `staticPolicies`), `vesta-seccomp` | Agent config file, static policies (re-read without a restart), seccomp profiles |
| CRD | `vestapolicies.vesta.dev` | `VestaPolicy` objects, used with `policies.source=kubernetes` |
| ServiceAccount | `vesta` | Used only by the installer (projected, pod-bound token). The agent container gets no token |
| ClusterRole, ClusterRoleBinding | `vesta-installer` | `get`/`patch` on nodes, plus `list` on pods and runtimeclasses in uninstall mode |
| ValidatingAdmissionPolicy + binding | `vesta-node-label` | Limits the service account's node patches to the `vesta.dev/guest-ready` label on its own node |
| ValidatingAdmissionPolicy + binding (optional) | `vesta-nri-required-plugin` | With `nri.requirePluginAnnotation: true`, rejects `kata-qemu-vesta` pods without the NRI required-plugins annotation |
| Service, PodMonitor (optional) | `vesta-metrics`, `vesta` | Metrics scraping |

### Inside the vesta guest image

| Path in the guest | Contents |
|---|---|
| `/usr/bin/vesta-guestd` | Static musl binary |
| `/etc/vesta/guestd.toml` | guestd config. `guest_image_version` is set to the build version |
| `/usr/lib/vesta/bpf/*.bpf.o` | Copies of the BPF objects (omitted with `VESTA_BPF_EMBEDDED=yes`). vesta-guestd loads the object embedded in its own binary |
| `/usr/lib/vesta/image-version` | The guest version |
| `/usr/lib/systemd/system/vesta-guestd.service` | `Type=notify`, `Before=kata-agent.service`, `Restart=always` |
| `/etc/systemd/system/kata-agent.service.d/10-vesta.conf` | `Wants=` and `After=vesta-guestd.service` for kata-agent |
| `/etc/systemd/system/kata-containers.target.wants/vesta-guestd.service` | Symlink that enables the unit |

The rest of the image is Kata's stock Ubuntu 26.04 ("resolute") rootfs, built by Kata's osbuilder with `AGENT_INIT=no`, so it boots systemd. The initrd variant, where kata-agent is PID 1, is not supported.
