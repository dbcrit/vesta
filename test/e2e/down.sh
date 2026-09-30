#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tears the e2e environment down. By default only vesta and the test
# namespace are removed (node cleaned up through the chart's uninstall mode);
# --all also uninstalls k3s, which removes Cilium and Kata with it.
#
#   test/e2e/down.sh [--all]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

all=0
[[ "${1:-}" == --all ]] && all=1

if kc get --raw /readyz >/dev/null 2>&1; then
	kc delete namespace "${E2E_NAMESPACE}" --ignore-not-found --wait=true --timeout=5m >/dev/null || true
	kc delete vestapolicies -A --all >/dev/null 2>&1 || true
	if helm status vesta -n "${VESTA_NAMESPACE}" >/dev/null 2>&1; then
		log "cleaning the node (vesta uninstall mode), then removing the release"
		helm upgrade vesta "${REPO_ROOT}/deploy/helm/vesta" -n "${VESTA_NAMESPACE}" --reuse-values \
			--set uninstall.enabled=true >/dev/null
		kc -n "${VESTA_NAMESPACE}" rollout status ds/vesta-agent --timeout=10m || warn "node cleanup did not finish"
		helm uninstall vesta -n "${VESTA_NAMESPACE}" >/dev/null
	fi
fi

if ((all)); then
	if [[ -x /usr/local/bin/k3s-uninstall.sh ]]; then
		log "uninstalling k3s"
		as_root /usr/local/bin/k3s-uninstall.sh
	fi
	as_root rm -rf /opt/vesta /opt/kata
fi
log "done"
