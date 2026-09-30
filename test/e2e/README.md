# End-to-end tests: k3s + Cilium + Kata Containers

These scripts stand up a single-node k3s cluster with Cilium as the CNI (replacing flannel and kube-proxy) and Kata Containers 4.2 (kata-deploy, QEMU runtime-rs shim). They build vesta from the working tree, install it, and run the end-to-end tests against real Kata VMs.

## Host requirements

Kata runs every pod in a KVM virtual machine, so the host must expose **`/dev/kvm`**. That rules out:

- **macOS** (Intel or Apple silicon) with Docker Desktop, Lima, or minikube: their Linux VMs have no `/dev/kvm`. Intel Macs have no nested virtualization at all.
- **kind, k3d, or minikube with the docker driver**: the "nodes" are containers without KVM.

Use one of these instead:

| Host | Notes |
|---|---|
| **GitHub Actions** | `.github/workflows/e2e.yml`, run from the Actions tab (`workflow_dispatch`) or nightly. Hosted `ubuntu-24.04` runners expose `/dev/kvm`. Takes about 1 to 2 hours, mostly the guest kernel build. |
| **Cloud VM with nested virtualization** | GCP: `gcloud compute instances create vesta-e2e --machine-type=n2-standard-8 --enable-nested-virtualization --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=100GB`. Azure: Dv5/Ev5 sizes support nested virtualization. AWS: use a `*.metal` instance. |
| **Bare-metal Linux** | Any x86_64 machine with VT-x/AMD-V enabled in firmware. |

The machine also needs: Ubuntu 22.04+ or similar with a 5.10+ kernel (Cilium), at least 4 vCPUs, 16 GB of RAM and 60 GB of free disk (the kernel and rootfs builds), Docker, `helm`, `jq`, `curl`, `make`, and `sudo`. The scripts install k3s system-wide, so use a disposable machine.

k3s is used rather than minikube. minikube runs its node in a VM of its own, so Kata's VMs would need a second level of nested virtualization. k3s runs directly on the host.

## Running

```sh
make e2e-up        # test/e2e/up.sh: k3s, Cilium, kata-deploy, Kata smoke test
make e2e-deploy    # test/e2e/deploy-vesta.sh: build vesta, load images into k3s, helm install
make e2e-test      # test/e2e/test.sh: the tests
make e2e-down      # remove vesta (node cleanup via the chart's uninstall mode)
test/e2e/down.sh --all   # also uninstall k3s, Cilium, Kata
```

`make e2e` runs the first three. Re-running `deploy-vesta.sh` after a code change rebuilds and upgrades vesta in place. `E2E_SKIP_BUILD=1` reuses images already built for `VESTA_VERSION`. `test/e2e/test.sh exec_enforce hot_reload` runs only the named tests (the test workloads are always recreated first).

Versions are pinned in [env.sh](env.sh) (k3s, Cilium, Kata, test images) and can be overridden from the environment.

## What `up.sh` sets up

- **k3s** from the release tag's install script, with `--flannel-backend=none --disable-network-policy --disable-kube-proxy --disable=traefik,servicelb`.
- **Cilium** with `kubeProxyReplacement=true`, and `cni.binPath`/`cni.confPath` read from k3s' containerd config. It also sets **`socketLB.hostNamespaceOnly=true`**, which Kata needs: a Kata pod's sockets live in the guest kernel, where Cilium's socket-level load balancer cannot see them. With this setting, Service translation for pods happens in the tc datapath, which does see the VM's traffic.
- **kata-deploy** (Helm chart `oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy`, version 4.2.0) with `k8sDistribution=k3s` and only the `qemu-runtime-rs` shim. vesta's runtime is derived from that shim's configuration.
- **A Kata smoke test**: a pod with `runtimeClassName: kata-qemu-runtime-rs` must report a kernel release different from the host's.

`deploy-vesta.sh` then runs `make guest-kernel guest-rootfs images`, imports the two images into k3s' containerd (`k3s ctr images import`), and installs the chart with `installer.containerdFlavor=k3s` and `policies.source=kubernetes`. It waits for vesta-install to label the node `vesta.dev/guest-ready=<version>`. vesta-install restarts k3s once to load the `kata-qemu-vesta` handler, as kata-deploy does.

## The tests

| Test | Checks |
|---|---|
| `cilium_kata_networking` | Kata to runc, Kata to Kata and runc to Kata traffic through Cilium Services |
| `vesta_attached` | The agent connected to the pod's guestd; the node carries the guest-ready label |
| `exec_audit` | An audit policy produces an `exec` event for `/usr/bin/id` with pod, container and policy names |
| `audit_would_deny` | An Audit policy with a deny rule lets the exec run and flags the event `would_deny` |
| `exec_enforce` | An Enforce deny rule blocks `/usr/bin/id`, also when started from bash, while other binaries still run; the event is `denied` |
| `plain_kata_unaffected` | A pod with the same labels on the stock `kata-qemu-runtime-rs` handler is not affected |
| `egress_enforce` | An Enforce egress deny rule blocks connects to one pod IP and port, while others still work; a `connect` event is `denied` |
| `hot_reload` | Removing the rules takes effect in the running pod, without a restart |
| `invalid_policy_reported` | An invalid VestaPolicy is reported with `accepted: false` in `status.nodes`, and the valid one stays programmed |
| `closed_pod_starts_with_sandbox_default` | A pod under an Enforce + Closed policy starts, and the agent installs the sandbox default |
| `metrics` | `/metrics` shows monitored sandboxes, denied exec events and loaded policies |

Egress rules match the address the workload dials, which `cgroup/connect4` sees before Cilium translates a Service address. The egress test therefore uses pod IPs. A rule on a Service's ClusterIP would match connects to the ClusterIP.

On failure, `collect-logs.sh` writes the cluster state, agent and installer logs, kata-deploy and Cilium logs, the k3s journal, containerd drop-ins and agent metrics to `$E2E_ARTIFACTS` (default `./e2e-artifacts`). The GitHub workflow uploads them as an artifact.
