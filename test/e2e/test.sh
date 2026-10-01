#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end tests for vesta on the cluster from up.sh + deploy-vesta.sh.
# Runs on the node itself (it reads the agent's loopback metrics).
#
#   test/e2e/test.sh              run every test
#   test/e2e/test.sh exec_enforce run the named tests (after the workloads)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need jq curl

ns="${E2E_NAMESPACE}"
passed=()
failed=()

agent_pod() { kc -n "${VESTA_NAMESPACE}" get pod -l app.kubernetes.io/component=agent -o name | head -1; }
# Event lines (JSON with "attributes") the agent exported since the test started.
events() {
	kc -n "${VESTA_NAMESPACE}" logs "$(agent_pod)" -c vesta-agent --since-time="${started}" 2>/dev/null |
		grep '^{' | jq -c 'select(.attributes != null)' 2>/dev/null || true
}
# wait_event <description> <jq boolean filter over .attributes>
wait_event() {
	local what="$1" filter="$2" deadline=$((SECONDS + 60))
	while [[ -z "$(events | jq -c "select(.attributes | ${filter})" 2>/dev/null | head -1)" ]]; do
		((SECONDS < deadline)) || {
			echo "no event: ${what}" >&2
			return 1
		}
		sleep 2
	done
}
agent_log_has() { kc -n "${VESTA_NAMESPACE}" logs "$(agent_pod)" -c vesta-agent 2>/dev/null | grep -q "$1"; }

kx() { kc -n "${ns}" exec "$1" -c app -- "${@:2}"; }
# tcp_get <pod> <host> <port>: one HTTP request over bash's /dev/tcp.
tcp_get() {
	# shellcheck disable=SC2016 # expanded by the inner bash
	kx "$1" timeout 10 bash -c 'exec 3<>/dev/tcp/$0/$1 && printf "GET / HTTP/1.0\r\n\r\n" >&3 && cat <&3' "$2" "$3"
}
pod_ip() { kc -n "${ns}" get pod "$1" -o jsonpath='{.status.podIP}'; }

apply_policy() { # <name> <spec yaml, indented by 2>
	kc apply -f - >/dev/null <<EOF
apiVersion: vesta.dev/v1alpha1
kind: VestaPolicy
metadata: {name: $1, namespace: ${ns}}
spec:
$2
EOF
}
# The policy's current generation is accepted and programmed on this node.
programmed() {
	local o
	o="$(kc -n "${ns}" get vpol "$1" -o json)"
	jq -e '.metadata.generation as $g | .status.nodes // [] | any(.observedGeneration == $g and .accepted and .programmed >= 1)' <<<"${o}" >/dev/null
}
wait_programmed() { retry 90 "policy $1 to be programmed" programmed "$1"; }

run() {
	local name="$1"
	if [[ ${#only[@]} -gt 0 ]] && [[ ! " ${only[*]} " == *" ${name} "* ]]; then
		return
	fi
	log "test: ${name}"
	if ("test_${name}"); then
		passed+=("${name}")
		printf '  \033[1;32mPASS\033[0m %s\n' "${name}"
	else
		failed+=("${name}")
		printf '  \033[1;31mFAIL\033[0m %s\n' "${name}"
	fi
}

setup_workloads() {
	log "deploying test workloads in ${ns}"
	kc delete namespace "${ns}" --ignore-not-found --wait >/dev/null
	kc create namespace "${ns}" >/dev/null
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: server-runc, namespace: ${ns}, labels: {app: server-runc}}
spec:
  containers:
    - name: app
      image: ${E2E_SERVER_IMAGE}
      command: ["sh", "-c", "mkdir -p /www && echo ok > /www/index.html && exec httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Pod
metadata: {name: server-kata, namespace: ${ns}, labels: {app: server-kata}}
spec:
  runtimeClassName: kata-qemu-vesta
  containers:
    - name: app
      image: ${E2E_SERVER_IMAGE}
      command: ["sh", "-c", "mkdir -p /www && echo ok > /www/index.html && exec httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Service
metadata: {name: server-runc, namespace: ${ns}}
spec: {selector: {app: server-runc}, ports: [{port: 8080}]}
---
apiVersion: v1
kind: Service
metadata: {name: server-kata, namespace: ${ns}}
spec: {selector: {app: server-kata}, ports: [{port: 8080}]}
---
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: ${ns}, labels: {app: vesta-e2e}}
spec:
  runtimeClassName: kata-qemu-vesta
  containers:
    - {name: app, image: "${E2E_IMAGE}", command: ["sleep", "infinity"]}
---
apiVersion: v1
kind: Pod
metadata: {name: plain-kata, namespace: ${ns}, labels: {app: vesta-e2e}}
spec:
  runtimeClassName: kata-qemu-runtime-rs
  containers:
    - {name: app, image: "${E2E_IMAGE}", command: ["sleep", "infinity"]}
EOF
	kc -n "${ns}" wait --for=condition=Ready pod --all --timeout=10m >/dev/null
}

# ---- tests ------------------------------------------------------------------

test_cilium_kata_networking() {
	tcp_get client "server-runc.${ns}.svc.cluster.local" 8080 | grep -q ok || {
		echo "kata -> runc service failed" >&2
		return 1
	}
	tcp_get client "server-kata.${ns}.svc.cluster.local" 8080 | grep -q ok || {
		echo "kata -> kata service failed" >&2
		return 1
	}
	kc -n "${ns}" exec server-runc -c app -- wget -qO- -T 10 "http://server-kata.${ns}.svc.cluster.local:8080" | grep -q ok || {
		echo "runc -> kata service failed" >&2
		return 1
	}
}

test_vesta_attached() {
	local sb
	sb="$(kc -n "${ns}" get pod client -o jsonpath='{.metadata.uid}')"
	[[ -n "${sb}" ]] || return 1
	retry 60 "the agent to report channel ready" agent_log_has '"channel ready"'
	node_has_label "vesta.dev/guest-ready=${VESTA_VERSION}"
}

test_exec_audit() {
	apply_policy e2e "  selector: {matchLabels: {app: vesta-e2e}}
  mode: Audit"
	wait_programmed e2e
	kx client /usr/bin/id >/dev/null
	wait_event "exec of /usr/bin/id audited" \
		'.["vesta.event.type"] == "exec" and .["process.executable.path"] == "/usr/bin/id" and .["k8s.pod.name"] == "client" and .["k8s.container.name"] == "app" and .["vesta.policy.name"] == "e2e"'
}

test_audit_would_deny() {
	apply_policy e2e "  selector: {matchLabels: {app: vesta-e2e}}
  mode: Audit
  process:
    deny: [{path: /usr/bin/id}]"
	wait_programmed e2e
	kx client /usr/bin/id >/dev/null || {
		echo "audit mode denied the exec" >&2
		return 1
	}
	wait_event "would-deny audit of /usr/bin/id" \
		'.["process.executable.path"] == "/usr/bin/id" and .["vesta.action"] == "audited" and ((.["vesta.flags"] // []) | any(.[]; . == "would_deny"))'
}

test_exec_enforce() {
	apply_policy e2e "  selector: {matchLabels: {app: vesta-e2e}}
  mode: Enforce
  process:
    deny: [{path: /usr/bin/id}]"
	wait_programmed e2e
	if kx client /usr/bin/id >/dev/null 2>&1; then
		echo "/usr/bin/id ran under an Enforce deny rule" >&2
		return 1
	fi
	if kx client bash -c /usr/bin/id >/dev/null 2>&1; then
		echo "/usr/bin/id ran when exec'd from bash" >&2
		return 1
	fi
	kx client /bin/ls / >/dev/null || {
		echo "an unrelated binary was denied" >&2
		return 1
	}
	wait_event "denied exec of /usr/bin/id" \
		'.["process.executable.path"] == "/usr/bin/id" and .["vesta.action"] == "denied"'
}

test_plain_kata_unaffected() {
	# Same labels, but the stock Kata handler: vesta does not act on it.
	kx plain-kata /usr/bin/id >/dev/null
}

test_egress_enforce() {
	local runc_ip kata_ip
	runc_ip="$(pod_ip server-runc)"
	kata_ip="$(pod_ip server-kata)"
	# cgroup/connect4 sees the address the workload dials. Pod IPs are used
	# because Service translation happens after it, in Cilium's datapath.
	apply_policy e2e "  selector: {matchLabels: {app: vesta-e2e}}
  mode: Enforce
  network:
    egress:
      - {cidr: ${runc_ip}/32, ports: [8080], protocol: TCP, action: Deny}"
	wait_programmed e2e
	if tcp_get client "${runc_ip}" 8080 2>/dev/null | grep -q ok; then
		echo "connect to ${runc_ip}:8080 was allowed" >&2
		return 1
	fi
	tcp_get client "${kata_ip}" 8080 | grep -q ok || {
		echo "connect to ${kata_ip}:8080 was denied" >&2
		return 1
	}
	wait_event "denied connect to ${runc_ip}" \
		'.["vesta.event.type"] == "connect" and .["vesta.action"] == "denied"'
}

test_hot_reload() {
	local uid restarts
	uid="$(kc -n "${ns}" get pod client -o jsonpath='{.metadata.uid}')"
	apply_policy e2e "  selector: {matchLabels: {app: vesta-e2e}}
  mode: Enforce"
	wait_programmed e2e
	kx client /usr/bin/id >/dev/null || {
		echo "exec still denied after the rule was removed" >&2
		return 1
	}
	tcp_get client "$(pod_ip server-runc)" 8080 | grep -q ok || {
		echo "connect still denied after the rule was removed" >&2
		return 1
	}
	restarts="$(kc -n "${ns}" get pod client -o jsonpath='{.status.containerStatuses[0].restartCount}')"
	[[ "$(kc -n "${ns}" get pod client -o jsonpath='{.metadata.uid}')" == "${uid}" && "${restarts}" == 0 ]] || {
		echo "the pod was recreated or restarted" >&2
		return 1
	}
}

test_invalid_policy_reported() {
	apply_policy broken "  selector: {matchLabels: {app: nothing}}
  process: {denyNonImageExec: true}"
	retry 60 "broken to be reported as not accepted" sh -c \
		"kubectl -n ${ns} get vpol broken -o json | jq -e '.status.nodes // [] | any(.accepted == false and (.message | contains(\"denyNonImageExec\")))'"
	# The valid policy is still in force.
	wait_programmed e2e
	kc -n "${ns}" delete vpol broken >/dev/null
}

test_closed_pod_starts_with_sandbox_default() {
	apply_policy closed "  selector: {matchLabels: {app: vesta-closed}}
  mode: Enforce
  failurePolicy: Closed"
	retry 60 "policy closed to be accepted" sh -c \
		"kubectl -n ${ns} get vpol closed -o json | jq -e '.status.nodes // [] | any(.accepted)'"
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: closed, namespace: ${ns}, labels: {app: vesta-closed}}
spec:
  runtimeClassName: kata-qemu-vesta
  containers:
    - {name: app, image: "${E2E_IMAGE}", command: ["sleep", "infinity"]}
EOF
	kc -n "${ns}" wait --for=condition=Ready pod/closed --timeout=5m >/dev/null
	kx closed /usr/bin/id >/dev/null
	retry 60 "the sandbox default log line" agent_log_has 'sandbox default installed'
	kc -n "${ns}" delete pod closed --wait=false >/dev/null
	kc -n "${ns}" delete vpol closed >/dev/null
}

test_metrics() {
	local m
	m="$(curl -sf http://127.0.0.1:9464/metrics)"
	awk '/^vesta_sandboxes\{state="monitored"\}/ { exit !($2 >= 2) }' <<<"${m}" || {
		grep '^vesta_sandboxes' <<<"${m}" >&2
		return 1
	}
	grep -qE '^vesta_events_total\{action="denied",type="exec"\} [1-9]' <<<"${m}" || {
		grep '^vesta_events_total' <<<"${m}" >&2
		return 1
	}
	grep -qE '^vesta_policies [1-9]' <<<"${m}"
}

only=("$@")
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
setup_workloads
for t in cilium_kata_networking vesta_attached exec_audit audit_would_deny exec_enforce plain_kata_unaffected \
	egress_enforce hot_reload invalid_policy_reported closed_pod_starts_with_sandbox_default metrics; do
	run "${t}"
done

echo
log "${#passed[@]} passed, ${#failed[@]} failed"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	{
		echo "### vesta e2e: ${#passed[@]} passed, ${#failed[@]} failed"
		echo
		echo "| Test | Result |"
		echo "|---|---|"
		for t in "${passed[@]}"; do echo "| \`${t}\` | :white_check_mark: pass |"; done
		for t in "${failed[@]}"; do echo "| \`${t}\` | :x: fail |"; done
		echo
		echo "k3s ${K3S_VERSION}, Cilium ${CILIUM_VERSION}, Kata ${KATA_VERSION}, vesta ${VESTA_VERSION}"
	} >>"${GITHUB_STEP_SUMMARY}"
fi
if ((${#failed[@]} > 0)); then
	printf '  failed: %s\n' "${failed[@]}"
	"${E2E_DIR}/collect-logs.sh" || true
	exit 1
fi
