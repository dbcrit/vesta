#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the vesta guest kernel with Kata's own kernel tooling
# (tools/packaging/kernel/build-kernel.sh at the pinned Kata tag), adding
# vesta.conf as build type "vesta". Everything runs in Kata's kernel builder
# container (tools/packaging/static-build/kernel/Dockerfile).
#
#   images/guest/kernel/build.sh config   merge fragments + olddefconfig only (fast check)
#   images/guest/kernel/build.sh build    full build; writes out/kernel/vmlinux-vesta
#
# Environment:
#   ARCH                     x86_64 (default: host) or aarch64
#   VESTA_KERNEL_CONFIDENTIAL yes (default) builds with -x -m like Kata's stock
#                            x86_64/aarch64 kernel asset, so the vesta kernel is a
#                            superset of the kernel stock kata-qemu pods boot.
#   VESTA_GUEST_OUT          output root (default images/guest/out); the kernel
#                            tree itself is kept in Docker volume vesta-kernel-build-<arch>
set -euo pipefail

# shellcheck source=images/guest/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

cmd="${1:-build}"
case "${cmd}" in config | build) ;; *) die "usage: $0 config|build" ;; esac

arch="${ARCH:-$(uname -m)}"
case "${arch}" in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) die "unsupported ARCH ${arch}" ;;
esac

kernel_out="${out_dir}/kernel/${arch}"
builder_image="vesta-kata-kernel-builder:${KATA_VERSION}"
fragment="${guest_dir}/kernel/vesta.conf"

require docker
fetch_kata

pinned="$(awk '/^  kernel:/{k=1} k && /version:/{gsub(/[" v]/,"",$2); print $2; exit}' "${kata_src}/versions.yaml")"
[[ "${pinned}" == "${KERNEL_VERSION}" ]] ||
	die "Kata ${KATA_VERSION} pins kernel ${pinned}, versions.env says ${KERNEL_VERSION}"

# Install the fragment as build type "vesta". build-kernel.sh also applies
# patches/<major>.x/<build-type>/ and fails if that directory is missing.
kernel_pkg="${kata_src}/tools/packaging/kernel"
major_minor="${KERNEL_VERSION%.*}"
# Host tools may be BSD (macOS), so avoid GNU-only flags such as install -D.
mkdir -p "${kernel_pkg}/configs/fragments/build-type/vesta" "${kernel_pkg}/patches/${major_minor}.x/vesta"
cp "${fragment}" "${kernel_pkg}/configs/fragments/build-type/vesta/vesta.conf"
: >"${kernel_pkg}/patches/${major_minor}.x/vesta/no_patches.txt"

log "building ${builder_image}"
docker build -q -t "${builder_image}" "${kata_src}/tools/packaging/static-build/kernel" >/dev/null

extra_flags=()
if [[ "${VESTA_KERNEL_CONFIDENTIAL:-yes}" == "yes" ]]; then
	extra_flags=(-x -m)
fi

# The kernel tree lives in a Docker volume, not under out/: kernel sources
# contain paths that differ only in case (ipt_ECN.h / ipt_ecn.h), which break
# on case-insensitive host filesystems such as macOS APFS.
work=/work
volume="vesta-kernel-build-${arch}"
docker volume create "${volume}" >/dev/null
docker run --rm --mount "type=volume,src=${volume},dst=${work},volume-nocopy" "${builder_image}" chown "$(id -u):$(id -g)" "${work}"
mkdir -p "${kernel_out}"
run_builder() {
	docker run --rm -i \
		-v "${out_dir}:${out_dir}" --mount "type=volume,src=${volume},dst=${work},volume-nocopy" -w "${work}" \
		-u "$(id -u):$(id -g)" -e HOME=/tmp \
		"${builder_image}" "$@"
}

bk=("${kernel_pkg}/build-kernel.sh" -a "${arch}" -v "${KERNEL_VERSION}" -b vesta ${extra_flags[@]+"${extra_flags[@]}"})

log "setup (download ${KERNEL_VERSION}, apply Kata patches, merge fragments) flags: ${extra_flags[*]+${extra_flags[*]}}"
run_builder "${bk[@]}" -f setup

src_dir="${work}/kata-linux-vesta-${KERNEL_VERSION}-$(cat "${kernel_pkg}/kata_config_version")"
config="${kernel_out}/config-vesta"
run_builder cp "${src_dir}/.config" "${config}" || die "setup did not produce ${src_dir}/.config"

# merge_config.sh only reports options whose final value differs; also check
# the literal lines so a silently dropped string option (CONFIG_LSM) fails.
missing=0
while IFS= read -r line; do
	[[ "${line}" =~ ^CONFIG_ ]] || continue
	if ! grep -qxF -- "${line}" "${config}"; then
		log "not in final .config: ${line} (have: $(grep -E "^(# )?${line%%=*}[= ]" "${config}" || echo unset))"
		missing=1
	fi
done <"${fragment}"
((missing == 0)) || die "vesta.conf did not apply cleanly"
log "fragment applied; merged config at ${config}"

[[ "${cmd}" == "config" ]] && exit 0

log "building kernel (this takes a while)"
run_builder "${bk[@]}" build

# .BTF is an allocated section, so --strip-debug removes DWARF and keeps BTF.
case "${arch}" in
x86_64)
	run_builder bash -ec "
		objcopy --strip-debug '${src_dir}/vmlinux' '${kernel_out}/vmlinux-vesta'
		readelf -S '${kernel_out}/vmlinux-vesta' | grep -q '[.]BTF ' || { echo 'no .BTF in vmlinux-vesta' >&2; exit 1; }
	"
	;;
aarch64)
	run_builder bash -ec "
		readelf -S '${src_dir}/vmlinux' | grep -q '[.]BTF ' || { echo 'no .BTF in vmlinux' >&2; exit 1; }
		install -m 0644 '${src_dir}/arch/arm64/boot/Image' '${kernel_out}/vmlinux-vesta'
	"
	;;
esac

printf '%s  vmlinux-vesta\n' "$(sha256_of "${kernel_out}/vmlinux-vesta")" >"${kernel_out}/vmlinux-vesta.sha256"
log "wrote ${kernel_out}/vmlinux-vesta ($(du -h "${kernel_out}/vmlinux-vesta" | cut -f1))"
