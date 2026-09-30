# SPDX-License-Identifier: Apache-2.0
# Pinned versions and settings for the k3s + Cilium + Kata end-to-end
# environment. Every value can be overridden from the environment.
# shellcheck shell=bash disable=SC2034

K3S_VERSION="${K3S_VERSION:-v1.37.0+k3s1}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.2}"
KATA_VERSION="${KATA_VERSION:-4.2.0}"
# kata-deploy's chart version equals the Kata release.
KATA_DEPLOY_CHART="${KATA_DEPLOY_CHART:-oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy}"

# vesta images and guest runtime version. The guest version must be semver
# without build metadata (it becomes a node label value).
VESTA_VERSION="${VESTA_VERSION:-0.1.0-e2e}"
VESTA_REGISTRY="${VESTA_REGISTRY:-ghcr.io/dbcrit}"
VESTA_NAMESPACE="${VESTA_NAMESPACE:-vesta-system}"
# Where test workloads run.
E2E_NAMESPACE="${E2E_NAMESPACE:-vesta-e2e}"

# Images used by the test workloads. debian-slim has separate binaries for
# /usr/bin/id and /bin/ls (busybox resolves every applet to one inode, which
# would make exec rules match all of them) and bash for /dev/tcp connects.
E2E_IMAGE="${E2E_IMAGE:-docker.io/library/debian:trixie-slim}"
E2E_SERVER_IMAGE="${E2E_SERVER_IMAGE:-docker.io/library/busybox:1.37}"

KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG

# Output for logs collected on failure.
E2E_ARTIFACTS="${E2E_ARTIFACTS:-${PWD}/e2e-artifacts}"
