#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Collects cluster, vesta, Kata and Cilium state into $E2E_ARTIFACTS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e

out="${E2E_ARTIFACTS}"
mkdir -p "${out}"
log "collecting logs into ${out}"

kc get nodes -o wide --show-labels >"${out}/nodes.txt" 2>&1
kc get pods -A -o wide >"${out}/pods.txt" 2>&1
kc get events -A --sort-by=.lastTimestamp >"${out}/events.txt" 2>&1
kc get runtimeclass -o yaml >"${out}/runtimeclasses.yaml" 2>&1
kc get vestapolicies -A -o yaml >"${out}/vestapolicies.yaml" 2>&1
kc describe pods -n "${E2E_NAMESPACE}" >"${out}/e2e-pods.txt" 2>&1
kc describe pods -n "${VESTA_NAMESPACE}" >"${out}/vesta-pods.txt" 2>&1
for pod in $(kc -n "${VESTA_NAMESPACE}" get pods -o name 2>/dev/null); do
	name="${pod#pod/}"
	for c in $(kc -n "${VESTA_NAMESPACE}" get "${pod}" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}'); do
		kc -n "${VESTA_NAMESPACE}" logs "${pod}" -c "${c}" >"${out}/${name}-${c}.log" 2>&1
		kc -n "${VESTA_NAMESPACE}" logs "${pod}" -c "${c}" --previous >"${out}/${name}-${c}.previous.log" 2>/dev/null
	done
done
kc -n kube-system logs -l name=kata-deploy --tail=-1 >"${out}/kata-deploy.log" 2>&1
kc -n kube-system logs ds/cilium --tail=2000 >"${out}/cilium.log" 2>&1
curl -sf http://127.0.0.1:9464/metrics >"${out}/vesta-metrics.txt" 2>&1
as_root journalctl -u k3s --no-pager --since "-2h" >"${out}/k3s.journal" 2>&1
# k3s' containerd (and the Kata shims' "vm console" lines) log to a file.
as_root cat /var/lib/rancher/k3s/agent/containerd/containerd.log >"${out}/containerd.log" 2>&1
# Kata shim and hypervisor messages go to the journal via containerd.
as_root journalctl --no-pager --since "-2h" -t kata -t containerd-shim-kata-v2 >"${out}/kata.journal" 2>&1
as_root find /opt/vesta/kata -maxdepth 3 -ls >"${out}/opt-vesta.txt" 2>&1
as_root sh -c 'cat /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/*.toml' >"${out}/containerd-dropins.toml" 2>&1
as_root cat /var/lib/rancher/k3s/agent/etc/containerd/config.toml >"${out}/containerd-config.toml" 2>&1
log "done"
