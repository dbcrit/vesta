#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks the VestaPolicy CRD and vesta-agent's status permissions against a
# real API server, in a throwaway k3s container:
#   - the CRD is accepted, defaults apply and the schema rejects bad values;
#   - status.nodes entries written with server-side apply by different field
#     managers merge per node;
#   - the policy-status ValidatingAdmissionPolicy lets the agent's
#     node-bound token change only its own node's entry.
# Needs Docker with privileged containers.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
k3s_image="rancher/k3s:v1.34.1-k3s1@sha256:5e0707cfd1239b358ef73f3254bc3eadc027dd30cd5ec6ca41e29e47652a1b8c"
helm_image="alpine/helm:3.19.0@sha256:aef9b56f64e866207d9591d0abd8f6d767b36aadd12edf68f8a719716d9d29c9"
name="vesta-crd-check-$$"
ns="vesta-system"

cleanup() { docker rm -f "${name}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "ok: $*"; }

docker run -d --name "${name}" --privileged "${k3s_image}" server \
	--disable=traefik,servicelb,metrics-server,local-storage,coredns >/dev/null

kc() { docker exec -i "${name}" kubectl "$@"; }
# kubectl as a bearer token only (no admin kubeconfig).
kc_token() {
	local token="$1"
	shift
	docker exec -i "${name}" sh -c 'touch /tmp/empty && exec kubectl --kubeconfig=/tmp/empty \
		--server=https://127.0.0.1:6443 --insecure-skip-tls-verify=true --token="$0" "$@"' "${token}" "$@"
}

for _ in $(seq 1 90); do
	if kc get --raw /readyz >/dev/null 2>&1 && kc get nodes -o name 2>/dev/null | grep -q node/; then
		break
	fi
	sleep 1
done
kc get --raw /readyz >/dev/null || fail "k3s did not become ready"
node="$(kc get nodes -o jsonpath='{.items[0].metadata.name}')"

kc create namespace "${ns}" >/dev/null
docker run --rm -v "${repo_root}:/src:ro" -w /src -e HELM_CACHE_HOME=/tmp -e HELM_CONFIG_HOME=/tmp "${helm_image}" \
	template vesta deploy/helm/vesta --namespace "${ns}" --kube-version 1.34.1 --include-crds \
	--set policies.source=kubernetes |
	kc apply -f - >/dev/null
kc wait --for=condition=Established crd/vestapolicies.vesta.dev --timeout=60s >/dev/null
pass "chart with policies.source=kubernetes applies; CRD established"

kc apply -f - >/dev/null <<'EOF'
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: web, namespace: default}
spec:
  selector: {matchLabels: {app: web}}
  process:
    allow: [{path: /usr/bin/app}]
  network:
    egress: [{cidr: 10.0.0.0/8, ports: [443], protocol: TCP}]
EOF
[[ "$(kc get vpol web -o jsonpath='{.spec.mode}/{.spec.failurePolicy}')" == "Audit/Open" ]] ||
	fail "defaults not applied"
pass "valid VestaPolicy accepted, mode/failurePolicy defaulted"

for bad in 'mode: Sometimes' 'process: {allow: [{path: relative}]}' 'network: {egress: [{cidr: 10.0.0.0/8, ports: [0]}]}' 'containerSelector: {names: []}'; do
	if kc apply -f - >/dev/null 2>&1 <<EOF; then
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: bad, namespace: default}
spec:
  selector: {}
  ${bad}
EOF
		fail "schema accepted: ${bad}"
	fi
done
pass "schema rejects bad mode, relative path, port 0, empty containerSelector"

status_apply() { # $1 node, $2 accepted -> manifest
	cat <<EOF
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: web, namespace: default}
status:
  nodes:
    - {node: $1, observedGeneration: 1, accepted: $2, sandboxes: 1, programmed: 1, containers: 2}
EOF
}

# Another node's agent (as admin, so the admission policy does not apply).
status_apply other true | kc apply --server-side --subresource=status --field-manager=vesta-agent-other -f - >/dev/null

token="$(kc create token vesta -n "${ns}" --bound-object-kind=Node --bound-object-name="${node}" --duration=10m)"
status_apply "${node}" true |
	kc_token "${token}" apply --server-side --force-conflicts --subresource=status --field-manager="vesta-agent-${node}" -f - >/dev/null ||
	fail "agent could not write its own node's status entry"
nodes="$(kc get vpol web -o jsonpath='{range .status.nodes[*]}{.node}{" "}{end}')"
[[ "${nodes}" == *"other"* && "${nodes}" == *"${node}"* ]] || fail "entries did not merge: ${nodes}"
pass "server-side apply by two field managers keeps one entry per node (${nodes% })"

if out="$(status_apply other false |
	kc_token "${token}" apply --server-side --force-conflicts --subresource=status --field-manager="vesta-agent-${node}" -f - 2>&1)"; then
	fail "agent changed another node's status entry"
fi
[[ "${out}" == *"only change the status entry of its own node"* ]] || fail "denied for another reason: ${out}"
[[ "$(kc get vpol web -o jsonpath='{.status.nodes[?(@.node=="other")].accepted}')" == "true" ]] ||
	fail "other node's entry changed"
pass "admission policy denies changing another node's entry"

unbound="$(kc create token vesta -n "${ns}" --duration=10m)"
if out="$(status_apply "${node}" false |
	kc_token "${unbound}" apply --server-side --force-conflicts --subresource=status --field-manager="vesta-agent-${node}" -f - 2>&1)"; then
	fail "status write without a node-bound token was allowed"
fi
[[ "${out}" == *"node-bound service account token"* ]] || fail "denied for another reason: ${out}"
pass "admission policy denies tokens without a node binding"

if kc_token "${token}" patch vpol web --type=merge -p '{"spec":{"mode":"Enforce"}}' >/dev/null 2>&1; then
	fail "agent could change a policy spec"
fi
pass "agent cannot change policy specs (RBAC)"
echo "crd-check: all checks passed"
