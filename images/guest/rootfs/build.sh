#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the vesta guest rootfs image with Kata's osbuilder at the pinned tag:
# the stock Kata Ubuntu rootfs (systemd init, AGENT_INIT=no) plus a vesta
# overlay passed through osbuilder's GUEST_HOOKS_TARBALL, which rootfs.sh
# unpacks into the rootfs after kata-agent is installed.
#
#   images/guest/rootfs/build.sh overlay   only build out/rootfs/<arch>/vesta-overlay.tar.zst
#   images/guest/rootfs/build.sh image     overlay + osbuilder; writes vesta-guest.img
#
# Environment:
#   VESTA_GUEST_VERSION  required; semver without build metadata
#   ARCH                 x86_64 (default: host) or aarch64
#   GUESTD_BIN           static vesta-guestd (default: out/guestd/<arch>/vesta-guestd, from `make guestd`)
#   GUESTD_CONFIG        guestd config template baked as /etc/vesta/guestd.toml
#                        (default: guest/vesta-guestd/guestd.example.toml). Its
#                        guest_image_version line is rewritten to VESTA_GUEST_VERSION.
#   BPF_OBJ_DIR          directory with *.bpf.o (default: bpf/.output/<x86_64|arm64>, from `make bpf`)
#   VESTA_BPF_EMBEDDED   yes = guestd embeds its objects; ship none in /usr/lib/vesta/bpf
#   SOURCE_DATE_EPOCH    timestamp for overlay entries (default: last commit time)
#
# The initrd variant (kata-agent as PID 1, AGENT_INIT=yes) has no init to order
# guestd against and is not supported (ARCHITECTURE Q7).
set -euo pipefail

# shellcheck source=images/guest/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

cmd="${1:-image}"
case "${cmd}" in overlay | image) ;; *) die "usage: $0 overlay|image" ;; esac

version="${VESTA_GUEST_VERSION:-}"
[[ -n "${version}" ]] || die "VESTA_GUEST_VERSION is not set"
validate_version "${version}"

arch="${ARCH:-$(uname -m)}"
case "${arch}" in
x86_64 | amd64) arch=x86_64 bpf_arch=x86_64 elf_machine=62 ;;
aarch64 | arm64) arch=aarch64 bpf_arch=arm64 elf_machine=183 ;;
*) die "unsupported ARCH ${arch}" ;;
esac

rootfs_out="${out_dir}/rootfs/${arch}"
files_dir="${guest_dir}/rootfs/files"
guestd_bin="${GUESTD_BIN:-${out_dir}/guestd/${arch}/vesta-guestd}"
guestd_config="${GUESTD_CONFIG:-${repo_root}/guest/vesta-guestd/guestd.example.toml}"
bpf_dir="${BPF_OBJ_DIR:-${repo_root}/bpf/.output/${bpf_arch}}"

require docker od

# Reads the ELF e_machine field (bytes 18-19, little endian on both targets).
check_elf() {
	local f="$1" magic machine
	magic="$(od -An -tx1 -N4 "${f}" | tr -d ' \n')"
	[[ "${magic}" == "7f454c46" ]] || die "${f} is not an ELF file"
	machine="$(od -An -tu2 -j18 -N2 "${f}" | tr -d ' \n')"
	[[ "${machine}" == "${elf_machine}" ]] || die "${f} is ELF machine ${machine}, want ${elf_machine} (${arch})"
}

[[ -f "${guestd_bin}" ]] || die "guestd binary not found: ${guestd_bin} (build it with 'make guestd' or set GUESTD_BIN)"
check_elf "${guestd_bin}"
[[ -f "${guestd_config}" ]] || die "guestd config not found: ${guestd_config} (set GUESTD_CONFIG)"
# guestd reports guest_image_version in HelloReply and the host matches it
# against the node label, so it must be the build version, not the template's.
n="$(grep -cE '^guest_image_version[[:space:]]*=' "${guestd_config}" || true)"
[[ "${n}" == "1" ]] || die "${guestd_config}: want exactly one top-level guest_image_version line, found ${n}"

bpf_objs=()
if [[ "${VESTA_BPF_EMBEDDED:-no}" != "yes" ]]; then
	[[ -d "${bpf_dir}" ]] || die "BPF object dir not found: ${bpf_dir} (run 'make bpf', or set VESTA_BPF_EMBEDDED=yes)"
	while IFS= read -r -d '' f; do bpf_objs+=("${f}"); done < <(find "${bpf_dir}" -maxdepth 1 -type f -name '*.bpf.o' -print0 | sort -z)
	((${#bpf_objs[@]} > 0)) || die "no *.bpf.o in ${bpf_dir}"
	for f in "${bpf_objs[@]}"; do
		# BPF objects are ELF with e_machine EM_BPF (247) regardless of target arch.
		[[ "$(od -An -tu2 -j18 -N2 "${f}" | tr -d ' \n')" == "247" ]] || die "${f} is not a BPF ELF object"
	done
fi

epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo_root}" log -1 --format=%ct 2>/dev/null || echo 0)}"
[[ "${epoch}" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"

# Stage with explicit modes. Only files and symlinks go into the tarball: a
# directory entry would reset the mode/owner of existing rootfs directories.
mkdir -p "${rootfs_out}"
stage="$(mktemp -d "${rootfs_out}/stage.XXXXXX")"
trap 'rm -rf "${stage}"' EXIT
put() { # put <mode> <src> <dest-relative-to-/>
	mkdir -p "${stage}/$(dirname "$3")"
	cp "$2" "${stage}/$3"
	chmod "$1" "${stage}/$3"
}
put 0755 "${guestd_bin}" usr/bin/vesta-guestd
mkdir -p "${stage}/etc/vesta"
sed -E "s/^guest_image_version[[:space:]]*=.*/guest_image_version = \"${version}\"/" "${guestd_config}" >"${stage}/etc/vesta/guestd.toml"
chmod 0644 "${stage}/etc/vesta/guestd.toml"
put 0644 "${files_dir}/usr/lib/systemd/system/vesta-guestd.service" usr/lib/systemd/system/vesta-guestd.service
put 0644 "${files_dir}/etc/systemd/system/kata-agent.service.d/10-vesta.conf" etc/systemd/system/kata-agent.service.d/10-vesta.conf
for f in ${bpf_objs[@]+"${bpf_objs[@]}"}; do
	put 0644 "${f}" "usr/lib/vesta/bpf/$(basename "${f}")"
done
mkdir -p "${stage}/usr/lib/vesta"
printf '%s\n' "${version}" >"${stage}/usr/lib/vesta/image-version"
chmod 0644 "${stage}/usr/lib/vesta/image-version"
# Equivalent of `systemctl enable` (WantedBy=kata-containers.target). rootfs.sh
# creates kata-containers.target.wants before it unpacks the hooks tarball.
mkdir -p "${stage}/etc/systemd/system/kata-containers.target.wants"
ln -s /usr/lib/systemd/system/vesta-guestd.service \
	"${stage}/etc/systemd/system/kata-containers.target.wants/vesta-guestd.service"

builder_image="vesta-osbuilder:${KATA_VERSION}"
log "building ${builder_image}"
docker build -q -t "${builder_image}" -f "${guest_dir}/rootfs/builder.Dockerfile" "${guest_dir}/rootfs" >/dev/null

# guestd is static, so it runs in the builder container when the arch matches.
if [[ "$(docker info --format '{{.Architecture}}')" == "${arch}" ]]; then
	docker run --rm -v "${stage}:/stage:ro" "${builder_image}" \
		/stage/usr/bin/vesta-guestd --check-config --config /stage/etc/vesta/guestd.toml ||
		die "vesta-guestd rejected the rendered /etc/vesta/guestd.toml"
else
	log "skipping --check-config: ${arch} binary on a $(docker info --format '{{.Architecture}}') Docker host"
fi

overlay="${rootfs_out}/vesta-overlay.tar.zst"
log "writing ${overlay}"
docker run --rm -v "${rootfs_out}:${rootfs_out}" -w "${stage}" -u "$(id -u):$(id -g)" \
	-e epoch="${epoch}" -e out="${overlay}" "${builder_image}" bash -euo pipefail -c '
		find . \( -type f -o -type l \) -print0 | LC_ALL=C sort -z |
			tar --no-recursion --null --format=posix \
				--owner=0 --group=0 --numeric-owner --mtime="@${epoch}" \
				--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
				--files-from=- -cf - | zstd -q -19 -f -o "${out}"
		tar --zstd -tvf "${out}"
	'

[[ "${cmd}" == "overlay" ]] && exit 0

require git
fetch_kata

build_dir="${rootfs_out}/build"
rm -rf "${build_dir}"
mkdir -p "${build_dir}"

# The rootfs is unpacked into build_dir through a bind mount. On a
# case-insensitive filesystem (macOS APFS by default) packages that ship
# names differing only in case break: libpam-runtime's PAM.7.gz -> pam.7.gz
# symlink points to itself and dpkg fails deep inside mmdebstrap.
touch "${build_dir}/.case-probe"
if [[ -e "${build_dir}/.CASE-PROBE" ]]; then
	rm -f "${build_dir}/.case-probe"
	die "${build_dir} is on a case-insensitive filesystem; build the guest rootfs on Linux (CI, the e2e host) or from a case-sensitive volume"
fi
rm -f "${build_dir}/.case-probe"

# osbuilder runs nested containers (rootfs builder, privileged image builder
# for loop devices) through the Docker socket; paths must match on both sides.
log "running osbuilder (${ROOTFS_DISTRO} ${ROOTFS_OS_VERSION}, AGENT_INIT=no); this builds kata-agent and takes a while"
docker run --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v "${out_dir}:${out_dir}" \
	-w "${kata_src}/tools/osbuilder" \
	-e HOME=/tmp -e GOPATH=/tmp/go \
	"${builder_image}" \
	make image \
	DISTRO="${ROOTFS_DISTRO}" \
	OS_VERSION="${ROOTFS_OS_VERSION}" \
	ARCH="${arch}" \
	USE_DOCKER=1 \
	AGENT_INIT=no \
	AGENT_POLICY=yes \
	MEASURED_ROOTFS=no \
	ROOTFS_BUILD_DEST="${build_dir}" \
	IMAGES_BUILD_DEST="${build_dir}" \
	GUEST_HOOKS_TARBALL="${overlay}"

img="${build_dir}/kata-containers.img"
[[ -f "${img}" ]] || die "osbuilder did not produce ${img}"
mv -f "${img}" "${rootfs_out}/vesta-guest.img"
printf '%s  vesta-guest.img\n' "$(sha256_of "${rootfs_out}/vesta-guest.img")" >"${rootfs_out}/vesta-guest.img.sha256"
log "wrote ${rootfs_out}/vesta-guest.img"
