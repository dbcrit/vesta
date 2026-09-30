# vesta Helm chart

Installs vesta on Kata nodes:

- **DaemonSet `vesta-agent`:** runs on nodes with `katacontainers.io/kata-runtime=true`. It has two init containers:
  - `seccomp-profile`: installs the agent's seccomp profile on the node.
  - `vesta-install`: installs the guest kernel and image under `/opt/vesta/kata/<version>/`, registers the `kata-qemu-vesta` containerd runtime, and labels the node `vesta.dev/guest-ready=<version>`.
- **RuntimeClass `kata-qemu-vesta`:** schedules only onto nodes with that label. Pods opt in with `runtimeClassName: kata-qemu-vesta`.
- **Access control:** a ServiceAccount, a ClusterRole that allows only `get`/`patch` on nodes, and a ValidatingAdmissionPolicy that narrows that patch to one label on the pod's own node.
- **ConfigMaps:** the agent config (`agent.config`), optional static policies (`staticPolicies`), and the seccomp profiles.
- **CRD:** `vestapolicies.vesta.dev` (from `crds/`, installed on first install). With `policies.source=kubernetes` the agent gets a projected token, `get`/`list`/`watch` on `vestapolicies` and `patch` on `vestapolicies/status`; a ValidatingAdmissionPolicy restricts those status writes to the agent's own node entry (checked against k3s by `make crd-check`).

Requirements:

- Kubernetes ≥ 1.30 (ValidatingAdmissionPolicy v1, and service account tokens that carry the node name).
- Kata Containers 4.x installed by kata-deploy.
- containerd ≥ 2.0 with NRI enabled (the default in 2.x).
- The release namespace must allow the `privileged` Pod Security level, because the pods use hostNetwork and hostPath.

```sh
kubectl create namespace vesta-system
kubectl label namespace vesta-system pod-security.kubernetes.io/enforce=privileged
helm install vesta deploy/helm/vesta -n vesta-system
kubectl get nodes -L vesta.dev/guest-ready
```

## Privileges and why

All three containers run as uid 0 with **every capability dropped**, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and no `privileged`. uid 0 is needed only because the node objects they use are root-owned and root-only: the NRI socket, the shim sockets, `/opt/vesta`, containerd config, systemd's private socket and the kubelet seccomp directory. As owner, uid 0 can use them without `CAP_DAC_OVERRIDE`. Each hostPath volume is mounted only into the container that uses it.

| Container | Host access | Why |
|---|---|---|
| `seccomp-profile` (busybox, pinned digest) | `<kubelet.rootDir>/seccomp/vesta` (rw) | Writes `vesta-agent.json` atomically, before the agent container is created |
| `vesta-install` | `/opt/vesta` (rw), mounted at `/host/opt/vesta` | Guest assets, generated runtime config, `current` symlink |
| | `<kata.installPrefix>` (ro) | Detects Kata and copies its base runtime config and `config.d/` |
| | containerd config dir (rw): `/etc/containerd`, or `/var/lib/rancher/<k3s\|rke2>/agent/etc/containerd` | Runtime handler drop-in, or `imports` entry on containerd < 2.2 |
| | `/run/systemd/private` (socket; only with `installer.restartContainerd`) | Restarts containerd/k3s/rke2 over D-Bus only when the config changed. No hostPID, no nsenter |
| | API token (projected, pod-bound, 1h) | `get`/`patch` its own Node (label). **The agent gets no token.** |
| `vesta-agent` | `hostNetwork: true` | Dials guests over host AF_VSOCK, which is not confirmed to be network-namespace aware |
| | `/var/run/nri` (ro) | NRI plugin socket |
| | `/run/kata`, `/run/vc/sbs` (ro) | Kata shim management sockets (`/agent-url`). Connecting to a socket works through a read-only mount |

### Seccomp

The pod default is `RuntimeDefault`. The agent container instead uses a `Localhost` profile, `vesta/vesta-agent.json`:

- **Why not `RuntimeDefault`:** containerd's default profile denies `socket(AF_VSOCK)` (see `contrib/seccomp/seccomp_default.go` in containerd v2.4.1). The agent cannot reach guests under it.
- **What the profile is:** exactly containerd's default for a container without capabilities, plus one rule allowing `socket(2)` with domain `AF_VSOCK`. `hack/gen-seccomp-profile.sh` generates it from the containerd source, and CI checks it is current.
- **Verified:** on a k3s v1.34 node, the same container got `EPERM` for `AF_VSOCK` under `RuntimeDefault`. Under this profile it succeeded, and `AF_ALG` was still denied.

If the node's kubelet root directory is not `/var/lib/kubelet`, set `kubelet.rootDir`. To manage the profile yourself, set `agent.seccomp.installProfile=false`.

### Node label admission policy

RBAC cannot limit `patch nodes` to one node or one label. The `ValidatingAdmissionPolicy` applies to node `UPDATE`s by this chart's service account and denies anything except:

- adding, changing or removing `vesta.dev/guest-ready`, with a semver value without build metadata;
- on the node named in the token's `authentication.kubernetes.io/node-name` claim.

It also denies any change to other labels, annotations or `spec` (taints included). `nodes/status` is not granted by RBAC.

This was verified against k3s v1.34 with a pod-bound token. Own-node label add/remove was allowed. A bad value, another label, a taint, another node, and a token without a node claim were each denied.

## Values

See [values.yaml](values.yaml); [values.schema.json](values.schema.json) validates them. The main keys:

| Key | Default | |
|---|---|---|
| `guestVersion` | chart `appVersion` | Must match the `VERSION` in the vesta-install image |
| `kata.nodeSelector` | `katacontainers.io/kata-runtime: "true"` | Nodes to run on |
| `installer.containerdFlavor` | `containerd` | `containerd`, `k3s` or `rke2`: which config dir is mounted |
| `installer.restartContainerd` | `true` | `false`: install fails with "restart required" and the node stays unlabelled |
| `agent.config` | see file | Written to the agent's strict config file |
| `agent.seccomp` | Localhost + install | See above |
| `policies.source` | `static` | `static`: `staticPolicies`, re-read every `policies.reloadInterval`. `kubernetes`: `VestaPolicy` objects via the API server |
| `staticPolicies` | `[]` | `vesta.dev/v1alpha1` `VestaPolicy` objects (source `static`) |
| `rbac.policyStatusPolicy.enabled` | `true` | Source `kubernetes`: admission policy keeping each agent to its own `status.nodes` entry |
| `runtimeClass.overhead` | 352Mi / 250m | |
| `priorityClassName` | `""` | `system-node-critical` is recommended where allowed |
| `metrics.exposeOnNodeIP` | `false` | `/metrics`, `/healthz`, `/readyz` listen on `127.0.0.1` unless this, the Service or the PodMonitor is enabled; then on the node IP (`status.hostIP`) only. They are unauthenticated: firewall the port |
| `metrics.service.enabled`, `metrics.podMonitor.enabled` | `false` | `/metrics` on `metrics.port` (host network) |
| `nri.defaultValidator` | `true` | vesta-install enables containerd's NRI default validator (no global required plugins) |
| `nri.requirePluginAnnotation` | `false` | ValidatingAdmissionPolicy requiring the NRI required-plugins annotation on vesta pods (below) |
| `uninstall.enabled` | `false` | Node cleanup mode (below) |

## failurePolicy: Closed and the NRI plugin

NRI only calls plugins that are registered. While vesta-agent is not registered (a DaemonSet rollout, a crash, the containerd restart the installer does, or NRI dropping the plugin after a timeout), containerd creates and starts vesta containers without asking vesta, and a `Closed` policy is not enforced for them.

containerd's NRI default validator closes that gap per pod. vesta-install enables it in its containerd drop-in (`nri.defaultValidator`, no globally required plugins, so no other pod is affected). A pod that carries

```yaml
metadata:
  annotations:
    required-plugins.noderesource.dev/pod: '["vesta"]'
```

then cannot create containers while the `vesta` plugin is not registered; kubelet retries until it is. vesta-agent logs a warning for pods selected by a `Closed` policy that lack the annotation. Set `nri.requirePluginAnnotation=true` to have a ValidatingAdmissionPolicy reject `kata-qemu-vesta` pods without it (checked on k3s v1.34.1). The trade-off: annotated pods, whatever their policy, cannot start while the agent is down.

## Upgrades and uninstall

On upgrade, `vesta-install` adds the new guest version next to the old ones. Running VMs keep the version they booted, and the RuntimeClass moves to the new label value, so nodes that have not been upgraded yet take no new vesta pods.

`helm uninstall` alone removes the Kubernetes objects but leaves the nodes configured. Clean the nodes first:

```sh
helm upgrade vesta deploy/helm/vesta -n vesta-system --reuse-values --set uninstall.enabled=true
kubectl -n vesta-system rollout status ds/vesta-agent   # every node cleaned up
helm uninstall vesta -n vesta-system
```

With `uninstall.enabled` the agent container is replaced by an idle one and the init container runs `vesta-install uninstall`. It removes the node label, the containerd drop-in (or `imports` entry, restoring containerd), and `/opt/vesta`. It refuses while `kata-qemu-vesta` pods run on the node; the init container then fails and kubelet retries it with backoff until they are gone. For this mode only, the service account also gets `list` on pods and runtimeclasses. containerd is restarted on each node that changed, so roll this out when a containerd restart is acceptable (on k3s/RKE2 servers the restarted unit is `k3s`/`rke2-server`, which also restarts the control plane on that node).
