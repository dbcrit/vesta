---
title: Deploying
parent: Getting Started
nav_order: 2
---

# Deploying

This page walks through a deployment: build the guest kernel, rootfs and images, push them, install the Helm chart, run a pod under the `kata-qemu-vesta` RuntimeClass, check that it works, and remove vesta cleanly. The commands use the chart in [`deploy/helm/vesta`]({{ site.vesta_repo_url }}/blob/main/deploy/helm/vesta) and its default values.
{: .fs-5 .fw-300 }

{: .warning }
> This sequence has not been run end to end. No image has been booted in a Kata VM, and the containerd restart and rollback have not run on a real node. The guest kernel, osbuilder image and installer image builds have not been run in this tree either. Expect to debug. See [Implementation status](../IMPLEMENTATION_STATUS.md#not-verified-locally).

Check the [prerequisites](index.md#prerequisites) first: Kata 4.x from kata-deploy with the `qemu-runtime-rs` shim, containerd ≥ 2.0, x86_64 nodes, Kubernetes ≥ 1.30.

## 1. Build the guest runtime and the images

No release images are published. Build on an x86_64 Linux or macOS host with Docker. The guest version is `VERSION`. It must match the chart's `guestVersion`, which defaults to the chart `appVersion` (`0.1.0-dev`).

```sh
export VERSION=0.1.0-dev
export REGISTRY=registry.example.com/vesta    # where your nodes pull from

make guest-kernel          # images/guest/out/kernel/x86_64/vmlinux-vesta (long)
make guest-rootfs          # builds bpf + guestd, then vesta-guest.img with osbuilder (long, privileged Docker)
make images                # guest-stage, then vesta-agent and vesta-install images

docker push "${REGISTRY}/vesta-agent:${VERSION}"
docker push "${REGISTRY}/vesta-install:${VERSION}"
```

The `vesta-install` image carries the kernel, the image, `SHA256SUMS` and `VERSION` in `/usr/share/vesta/guest/`. The installer reads the guest version from that `VERSION` file unless `--guest-version` is passed, which the chart always does. See [Building](building.md) for each target.

## 2. Install the chart

The release namespace must allow the `privileged` Pod Security level: the agent uses `hostNetwork` and hostPath volumes.

```sh
kubectl create namespace vesta-system
kubectl label namespace vesta-system pod-security.kubernetes.io/enforce=privileged

helm install vesta deploy/helm/vesta -n vesta-system \
  --set agent.image.repository="${REGISTRY}/vesta-agent" \
  --set installer.image.repository="${REGISTRY}/vesta-install"
```

Image tags default to the chart `appVersion`. Set `agent.image.digest` and `installer.image.digest` to pin digests; a digest takes precedence over the tag.

Values you are likely to need (all values: [Configuration](configuration.md#helm-values)):

| Situation | Set |
|---|---|
| k3s or RKE2 nodes | `installer.containerdFlavor=k3s` or `rke2` |
| kata-deploy installed with a non-default `env.installationPrefix` | `kata.installPrefix=<prefix>` |
| Kubelet root is not `/var/lib/kubelet` | `kubelet.rootDir=<dir>` |
| Tainted Kata node pool | `tolerations`, and `runtimeClass.tolerations` for workload pods |
| You manage containerd restarts yourself | `installer.restartContainerd=false`. The installer then fails with "containerd config changed and must be restarted by the operator" and leaves the node unlabelled until a later run finds nothing to change |
| Static policies | `staticPolicies` (see [Configuration](configuration.md#static-policy-file)) |
| Prometheus scraping | `metrics.service.enabled=true` or `metrics.podMonitor.enabled=true` (both bind the endpoints to the node IP) |

### What happens on each node

1. The `seccomp-profile` init container copies `vesta-agent-<arch>.json` to `<kubelet.rootDir>/seccomp/vesta/vesta-agent.json`.
2. The `vesta-install` init container runs `vesta-install install --guest-version=<guestVersion> --nri-default-validator=true --host-root=/host --handler=kata-qemu-vesta --kata-prefix=/opt/kata --restart=systemd`. It:
   - reads the node's `containerRuntimeVersion` from the API and picks the containerd drop-in location;
   - checks the Kata install and loads its QEMU runtime-rs config and `config.d/`;
   - copies the kernel and image into `/opt/vesta/kata/<version>/`, verifying SHA-256;
   - writes `configuration-qemu-vesta.toml` and `config.d/` (with `90-vesta.toml`) and switches `/opt/vesta/kata/current`;
   - writes the containerd drop-in and, if the file changed, restarts containerd (or k3s/RKE2) over systemd D-Bus. If the unit does not come back active, it restores the previous files, restarts once more and fails;
   - labels the node `vesta.dev/guest-ready=<version>`.

   On any failure before the label step, it removes a stale `vesta.dev/guest-ready` label so no new vesta pods are scheduled there.
3. The `vesta-agent` container starts with `--config=/etc/vesta/agent.yaml` and registers with NRI as plugin `vesta`, index `90`.

{: .warning }
> The first install restarts containerd on every Kata node the DaemonSet lands on, all at roughly the same time; `vesta-install` does not stagger restarts. On k3s and RKE2 servers the restarted unit is `k3s` or `rke2-server`, which restarts the control plane on that node. A later run restarts containerd only if the drop-in content changed.

### Plain manifests

`deploy/manifests/` holds `helm template` output with default values, plus the namespace. The images point at `ghcr.io/vesta-dev/...:0.1.0-dev`, so edit them (or use a kustomize image override) before applying:

```sh
kubectl apply -k deploy/manifests
```

## 3. Run a pod under vesta

Pods opt in with the RuntimeClass. Its `scheduling.nodeSelector` limits them to nodes labelled with the chart's guest version.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo
  namespace: default
  labels:
    app: demo
  annotations:
    # Optional: refuse to create containers while the vesta NRI plugin is
    # not registered (see "failurePolicy: Closed and the NRI plugin" below).
    required-plugins.noderesource.dev/pod: '["vesta"]'
spec:
  runtimeClassName: kata-qemu-vesta
  containers:
    - name: app
      image: busybox:1.37
      command: ["sh", "-c", "while true; do wget -q -O- http://example.com >/dev/null; sleep 30; done"]
```

With no policy selecting the pod, vesta binds its containers with no policy (monitor only). Every exec is audited (P1), and the container still waits for the guest's bind acknowledgement at `StartContainer`, handled according to `defaultFailurePolicy` (`Open` by default). To add rules, see [Configuration](configuration.md#static-policy-file).

## 4. Verify

**Node label.** Each node where the install succeeded carries the guest version:

```sh
kubectl get nodes -L vesta.dev/guest-ready
```

**Installer log.** The installer logs JSON to stderr. A successful run ends with `"msg":"vesta runtime installed"` followed by `"msg":"done"`, with `guest_version`, `kata`, `flavor`, `assets_changed`, `containerd_changed` and `restarted`:

```sh
kubectl -n vesta-system logs ds/vesta-agent -c vesta-install
```

A Kata version other than 4.2.0 logs `kata version differs from the tested release` and continues.

**Agent log.** The agent logs JSON to stderr and writes events to stdout, so both appear in the container log. Look for these messages, in order:

| `msg` | Meaning |
|---|---|
| `starting vesta-agent` | Config loaded. Shows `handlers`, the number of `policies`, the policy `generation` and `global_mode` |
| `serving metrics and health` | HTTP listener up, with the bound `addr` |
| `NRI plugin configured` | Registered with containerd (readiness turns OK) |
| `synchronized with runtime` | Existing vesta pods and containers picked up (`vesta_pods`, `vesta_containers`) |
| `vesta sandbox started` | A `kata-qemu-vesta` pod sandbox was created |
| `channel ready` | CTRL and EVT connections to vesta-guestd are up. Shows `guest_image`, `kernel`, `proto` and `generation` |

```sh
kubectl -n vesta-system logs ds/vesta-agent -c vesta-agent | grep -v '"event_name"'   # logs only
kubectl -n vesta-system logs ds/vesta-agent -c vesta-agent | grep '"event_name"'      # events only
```

**Events.** Run a command in the demo pod and look for a `vesta.exec` event with `k8s.pod.name` `demo`:

```sh
kubectl exec demo -- ls /
```

The event format is described in [Operations](operations.md#event-output).

**Metrics and health.** By default the endpoints listen on `127.0.0.1:9464` in the host network namespace. The agent image is distroless (no shell or curl), so query from the node itself:

```sh
curl -s http://127.0.0.1:9464/readyz          # "ok" once registered with NRI
curl -s http://127.0.0.1:9464/metrics | grep '^vesta_sandboxes'
```

`vesta_sandboxes{state="monitored"}` counts sandboxes whose channel is up and whose heartbeat is current. See [Operations](operations.md#metrics).

## failurePolicy: Closed and the NRI plugin

NRI only calls plugins that are registered. While vesta-agent is not registered (a rollout, a crash, the installer's containerd restart), containerd creates and starts vesta containers without asking vesta, so a `Closed` policy is not enforced for them.

vesta-install enables containerd's NRI default validator in its drop-in (`nri.defaultValidator: true`). It sets no globally required plugins, so it changes nothing for other pods. A pod annotated `required-plugins.noderesource.dev/pod: '["vesta"]'` cannot create containers while the `vesta` plugin is not registered; kubelet retries until it is.

- vesta-agent logs `failurePolicy Closed is not guaranteed while vesta-agent is down: the pod lacks the NRI required-plugins annotation` once per pod for containers selected by a `Closed` policy that lack the annotation.
- `nri.requirePluginAnnotation: true` installs a ValidatingAdmissionPolicy that rejects `kata-qemu-vesta` pods without the annotation. The cost: no such pod can start while the agent is down, whatever its policy.

## Upgrades

On upgrade, vesta-install adds the new guest version next to the old ones under `/opt/vesta/kata/` and moves `current`. Running VMs keep the kernel and image they booted from. The RuntimeClass selects on the new label value, so nodes that have not been upgraded yet take no new vesta pods.

A version directory is immutable: if `/opt/vesta/kata/<version>/` already holds a kernel or image with a different SHA-256, the install fails with `refusing to replace an installed version (bump the guest version)`. Rebuild with a new `VERSION` instead of reusing one.

The DaemonSet has a `checksum/config` annotation over the ConfigMaps, so changing `agent.config` or `staticPolicies` with `helm upgrade` restarts the agents. That restart is how a policy or kill-switch change takes effect: there is no hot reload.

## Uninstall

`helm uninstall` alone removes the Kubernetes objects but leaves the nodes configured. Clean the nodes first:

```sh
helm upgrade vesta deploy/helm/vesta -n vesta-system --reuse-values --set uninstall.enabled=true
kubectl -n vesta-system rollout status ds/vesta-agent   # every node cleaned up
helm uninstall vesta -n vesta-system
```

With `uninstall.enabled: true`:

- The agent container is replaced by an idle `uninstalled` container, so `rollout status` shows when every node is done.
- The init container runs `vesta-install uninstall`. It refuses while pods using `kata-qemu-vesta` run on the node (`vesta runtime is in use by N pod(s) on <node>: ...`); the init container then fails and kubelet retries it with backoff until those pods are gone.
- It removes the node label first, checks again for pods that arrived meanwhile (and restores the label if it finds any), then removes every vesta containerd drop-in location and the `imports` entry, restarts containerd if anything changed, and deletes `/opt/vesta/kata` and `/opt/vesta/containerd`.
- The installer's service account also gets `list` on pods and runtimeclasses, in this mode only.

{: .note }
> There is no `preStop` hook and no pre-delete Job: uninstall is this chart mode. The seccomp profile in `<kubelet.rootDir>/seccomp/vesta/` and a `config.toml.vesta-backup` file are left on the node.
