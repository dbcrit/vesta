#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Stages the built guest kernel and rootfs image for the vesta-install image:
# images/guest/out/dist/<amd64|arm64>/{vmlinux-vesta,vesta-guest.img,SHA256SUMS,VERSION},
# the layout vesta-install reads from its -assets-dir. vesta-install verifies
# SHA256SUMS before installing to /opt/vesta/kata/<VERSION>/ and appends
# lockdown=integrity to the runtime's kernel_params (ARCHITECTURE §3).
#
# Environment: VESTA_GUEST_VERSION (required), ARCH (x86_64|aarch64).
set -euo pipefail

# shellcheck source=images/guest/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

version="${VESTA_GUEST_VERSION:-}"
[[ -n "${version}" ]] || die "VESTA_GUEST_VERSION is not set"
validate_version "${version}"

arch="${ARCH:-$(uname -m)}"
case "${arch}" in
x86_64 | amd64) arch=x86_64 oci_arch=amd64 ;;
aarch64 | arm64) arch=aarch64 oci_arch=arm64 ;;
*) die "unsupported ARCH ${arch}" ;;
esac

kernel="${out_dir}/kernel/${arch}/vmlinux-vesta"
image="${out_dir}/rootfs/${arch}/vesta-guest.img"
[[ -f "${kernel}" ]] || die "missing ${kernel}; run 'make guest-kernel'"
[[ -f "${image}" ]] || die "missing ${image}; run 'make guest-rootfs'"

dist="${out_dir}/dist/${oci_arch}"
if [[ -d "${dist}" ]]; then
	chmod -R u+w "${dist}"
	rm -rf "${dist}"
fi
mkdir -p "${dist}"
cp "${kernel}" "${dist}/vmlinux-vesta"
cp "${image}" "${dist}/vesta-guest.img"
printf '%s\n' "${version}" >"${dist}/VERSION"
{
	printf '%s  vmlinux-vesta\n' "$(sha256_of "${dist}/vmlinux-vesta")"
	printf '%s  vesta-guest.img\n' "$(sha256_of "${dist}/vesta-guest.img")"
} >"${dist}/SHA256SUMS"
chmod 0444 "${dist}"/*
log "staged ${dist}"
