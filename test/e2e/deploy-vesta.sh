#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds vesta (BPF objects, guestd, guest kernel and rootfs, host images),
# loads the images into k3s' containerd and installs the chart with the
# k3s containerd flavor and VestaPolicy objects as the policy source.
#
#   test/e2e/deploy-vesta.sh            build everything, then install
#   E2E_SKIP_BUILD=1 test/e2e/deploy-vesta.sh
#                                       reuse images already built for VESTA_VERSION
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need docker helm make
agent_image="${VESTA_REGISTRY}/vesta-agent:${VESTA_VERSION}"
install_image="${VESTA_REGISTRY}/vesta-install:${VESTA_VERSION}"

if [[ "${E2E_SKIP_BUILD:-}" != 1 ]]; then
	log "building vesta ${VESTA_VERSION}: guest kernel, guest rootfs, host images (the kernel takes a while)"
	make -C "${REPO_ROOT}" VERSION="${VESTA_VERSION}" REGISTRY="${VESTA_REGISTRY}" \
		guest-kernel guest-rootfs images
fi

for img in "${agent_image}" "${install_image}"; do
	docker image inspect "${img}" >/dev/null 2>&1 || die "image ${img} not built"
	log "loading ${img} into k3s containerd"
	docker save "${img}" | as_root k3s ctr -n k8s.io images import - >/dev/null
done

log "installing the vesta chart"
helm upgrade --install vesta "${REPO_ROOT}/deploy/helm/vesta" \
	--namespace "${VESTA_NAMESPACE}" --create-namespace \
	--set guestVersion="${VESTA_VERSION}" \
	--set agent.image.repository="${VESTA_REGISTRY}/vesta-agent" \
	--set agent.image.tag="${VESTA_VERSION}" --set agent.image.pullPolicy=Never \
	--set installer.image.repository="${VESTA_REGISTRY}/vesta-install" \
	--set installer.image.tag="${VESTA_VERSION}" --set installer.image.pullPolicy=Never \
	--set installer.containerdFlavor=k3s \
	--set policies.source=kubernetes \
	--set agent.config.logLevel=debug

# vesta-install restarts k3s (containerd) once to load its runtime handler.
retry 900 "vesta-install to label the node" node_has_label "vesta.dev/guest-ready=${VESTA_VERSION}"
retry 180 "the k3s API server" kc get --raw /readyz
kc -n "${VESTA_NAMESPACE}" rollout status ds/vesta-agent --timeout=10m
retry 60 "the kata-qemu-vesta RuntimeClass" kc get runtimeclass kata-qemu-vesta
log "vesta is running. Next: test/e2e/test.sh"
