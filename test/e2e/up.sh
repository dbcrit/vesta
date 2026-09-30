#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Brings up a single-node k3s cluster with Cilium (replacing flannel and
# kube-proxy) and Kata Containers (kata-deploy, QEMU runtime-rs shim), then
# checks that a Kata pod really runs in a VM. Needs a Linux host with
# /dev/kvm and root (sudo). Meant for a disposable machine or CI runner.
#
#   test/e2e/up.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

preflight() {
	[[ "$(uname -s)" == Linux ]] || die "Linux host required (Kata needs KVM)"
	as_root test -c /dev/kvm || die "/dev/kvm missing: enable virtualization (nested virtualization on a VM)"
	need curl helm jq
	# QEMU uses vhost-vsock for the agent (and vesta) channel.
	as_root modprobe vhost_vsock || die "cannot load vhost_vsock"
	as_root modprobe vhost_net || warn "vhost_net not available"
	local kmaj kmin
	IFS=. read -r kmaj kmin _ <<<"$(uname -r)"
	((kmaj > 5 || (kmaj == 5 && kmin >= 10))) || die "Cilium ${CILIUM_VERSION} needs a 5.10+ host kernel"
}

install_k3s() {
	if command -v k3s >/dev/null 2>&1 && as_root k3s kubectl get --raw /readyz >/dev/null 2>&1; then
		log "k3s already running: $(k3s --version | head -1)"
		return
	fi
	log "installing k3s ${K3S_VERSION} (no flannel, no kube-proxy, no network policy controller)"
	local script
	script="$(mktemp)"
	# The install script from the release tag, not the moving get.k3s.io.
	curl -sfL "https://raw.githubusercontent.com/k3s-io/k3s/${K3S_VERSION//+/%2B}/install.sh" -o "${script}"
	as_root env INSTALL_K3S_VERSION="${K3S_VERSION}" \
		INSTALL_K3S_EXEC="server --flannel-backend=none --disable-network-policy --disable-kube-proxy --disable=traefik,servicelb --write-kubeconfig-mode=0644" \
		sh "${script}"
	rm -f "${script}"
	retry 180 "the k3s API server" kc get --raw /readyz
	retry 120 "the node to register" sh -c 'kubectl get nodes -o name | grep -q node/'
}

# CNI directories k3s' containerd uses; Cilium must install its plugin there.
k3s_cni_dirs() {
	local cfg=/var/lib/rancher/k3s/agent/etc/containerd/config.toml bin conf
	bin="$(as_root sed -nE 's/^[[:space:]]*bin_dirs?[[:space:]]*=[[:space:]]*\[?[[:space:]]*"([^"]+)".*/\1/p' "${cfg}" | head -1)"
	conf="$(as_root sed -nE 's/^[[:space:]]*conf_dir[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${cfg}" | head -1)"
	[[ -n "${bin}" && -n "${conf}" ]] || die "could not read the CNI dirs from ${cfg}"
	echo "${bin} ${conf}"
}

install_cilium() {
	local bin conf ip
	read -r bin conf <<<"$(k3s_cni_dirs)"
	ip="$(node_ip)"
	log "installing Cilium ${CILIUM_VERSION} (kube-proxy replacement, API ${ip}:6443, CNI ${bin} ${conf})"
	# socketLB.hostNamespaceOnly: a Kata pod's sockets live in the guest
	# kernel, where Cilium's socket-level load balancer cannot see them, so
	# service translation for pods must happen in the datapath instead.
	helm upgrade --install cilium cilium --repo https://helm.cilium.io --version "${CILIUM_VERSION}" \
		--namespace kube-system \
		--set kubeProxyReplacement=true \
		--set k8sServiceHost="${ip}" --set k8sServicePort=6443 \
		--set ipam.mode=kubernetes \
		--set operator.replicas=1 \
		--set socketLB.hostNamespaceOnly=true \
		--set cni.binPath="${bin}" --set cni.confPath="${conf}" \
		--wait --timeout 10m
	kc -n kube-system rollout status ds/cilium --timeout=5m
	retry 180 "the node to become Ready" kc wait --for=condition=Ready "node/$(node_name)" --timeout=5s
	kc -n kube-system rollout status deploy/coredns --timeout=5m
}

install_kata() {
	log "installing Kata Containers ${KATA_VERSION} with kata-deploy (shim qemu-runtime-rs)"
	helm upgrade --install kata-deploy "${KATA_DEPLOY_CHART}" --version "${KATA_VERSION}" \
		--namespace kube-system \
		--set k8sDistribution=k3s \
		--set shims.disableAll=true \
		--set shims.qemu-runtime-rs.enabled=true
	# No helm --wait: kata-deploy restarts k3s (and with it the API server) to
	# load the new containerd config; its node label marks completion.
	retry 180 "the k3s API server after the restart" kc get --raw /readyz
	retry 900 "kata-deploy to label the node" node_has_label katacontainers.io/kata-runtime=true
	retry 60 "the kata-qemu-runtime-rs RuntimeClass" kc get runtimeclass kata-qemu-runtime-rs
}

smoke_kata() {
	log "checking that a Kata pod runs in its own guest kernel"
	kc delete pod kata-smoke --ignore-not-found --wait >/dev/null
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: kata-smoke, namespace: default}
spec:
  runtimeClassName: kata-qemu-runtime-rs
  restartPolicy: Never
  containers:
    - name: uname
      image: ${E2E_SERVER_IMAGE}
      command: ["uname", "-r"]
EOF
	# shellcheck disable=SC2016 # expanded by the inner sh
	retry 300 "the kata-smoke pod to finish" \
		sh -c '[ "$(kubectl get pod kata-smoke -o jsonpath="{.status.phase}")" = Succeeded ]'
	local guest host
	guest="$(kc logs kata-smoke)"
	host="$(uname -r)"
	kc delete pod kata-smoke --wait=false >/dev/null
	[[ -n "${guest}" && "${guest}" != "${host}" ]] || die "kata-smoke ran on the host kernel (${host})"
	log "Kata works: guest kernel ${guest}, host kernel ${host}"
}

preflight
install_k3s
install_cilium
install_kata
smoke_kata
log "cluster ready. Next: test/e2e/deploy-vesta.sh"
