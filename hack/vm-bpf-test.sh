#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boots a kernel in QEMU and runs vesta-guestd's BPF smoke test inside it as
# PID 1's child: CO-RE relocation, verifier, attach, pinning, exec audit and
# deny (BPF LSM), egress deny, kill switch, with the guestd unit's capability
# set. This is the verifier check on the real guest kernels (ARCHITECTURE §5),
# without Kata or a cluster. Uses KVM when /dev/kvm is usable, otherwise TCG
# (software emulation, slower but works on any Docker host).
#
#   hack/vm-bpf-test.sh vesta             the vesta guest kernel (make guest-kernel)
#   hack/vm-bpf-test.sh debian-6.1        Debian bookworm 6.1 LTS (the documented minimum)
#   hack/vm-bpf-test.sh kernel <path>     any x86_64 bzImage or PVH vmlinux with BTF
# shellcheck disable=SC2016 # the single-quoted scripts run in containers and expand there
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${repo_root}/images/guest/out/vm-test"
tools_image="docker.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

# Debian bookworm linux-image-6.1.0-50-cloud-amd64-unsigned 6.1.176-1, from
# snapshot.debian.org (permanent URL), verified by SHA-256.
debian_url="https://snapshot.debian.org/file/2dabfc54d90165cf737fea4282fd2e06b73c6322"
debian_sha256="4f217f710203cdfedde21f836bc66a0a4d773752d7fe8e5e13f701f891788945"

log() { printf '[vm-bpf-test] %s\n' "$*" >&2; }
die() {
	log "error: $*"
	exit 1
}

[[ "$(uname -m)" == x86_64 || "${VM_ALLOW_TCG_ANY_ARCH:-}" == 1 ]] || log "note: the VM is x86_64 and runs under TCG on this host"
mkdir -p "${out}"

case "${1:-}" in
vesta)
	kernel="${repo_root}/images/guest/out/kernel/x86_64/vmlinux-vesta"
	[[ -s "${kernel}" ]] || die "${kernel} missing: run make guest-kernel"
	label="vesta guest kernel"
	;;
debian-6.1)
	kernel="${out}/vmlinuz-debian-6.1"
	if [[ ! -s "${kernel}" ]]; then
		log "fetching the Debian 6.1 kernel"
		docker run --rm -v "${out}:/out" "${tools_image}" sh -euc '
			apk add -q curl binutils xz >/dev/null
			cd /tmp && curl -fsSL -o k.deb "$1"
			echo "$2  k.deb" | sha256sum -c -
			ar x k.deb && tar -xf data.tar.xz ./boot
			cp boot/vmlinuz-* /out/vmlinuz-debian-6.1
		' sh "${debian_url}" "${debian_sha256}"
	fi
	label="Debian 6.1 LTS kernel"
	;;
kernel)
	kernel="$(cd "$(dirname "${2:?kernel path}")" && pwd)/$(basename "$2")"
	[[ -s "${kernel}" ]] || die "${kernel} missing"
	label="${kernel}"
	;;
*)
	die "usage: $0 vesta|debian-6.1|kernel <path>"
	;;
esac

# The smoke test binary (static musl), built in the guest builder.
log "building the smoke test binary"
"${repo_root}/guest/hack/in-builder.sh" sh -euc '
	cd guest
	exe="$(cargo test --locked --no-run 2>&1 | sed -n "s/.*Executable unittests src\/main.rs (\(.*\))/\1/p" | head -1)"
	[ -n "${exe}" ] || { echo "no test executable" >&2; exit 1; }
	install -D -m 0755 "${exe}" /src/images/guest/out/vm-test/vesta-guestd-tests
'

# A busybox initramfs whose init mounts what guestd expects in a Kata guest
# and runs the test in strict mode (a skip is a failure).
cat >"${out}/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mkdir -p /proc /sys /dev /tmp /run
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t securityfs securityfs /sys/kernel/security
ip link set lo up
echo "VESTA-VM kernel $(uname -r), LSMs: $(cat /sys/kernel/security/lsm)"
VESTA_SMOKE_STRICT=1 VESTA_SMOKE_UNIT_CAPS=1 /vesta-guestd-tests --ignored --test-threads=1 --nocapture smoke
echo "VESTA-VM-RESULT rc=$?"
poweroff -f
EOF
chmod 0755 "${out}/init"

kvm=()
accel=tcg
if [[ -w /dev/kvm ]] && [[ "$(uname -m)" == x86_64 ]]; then
	kvm=(--device /dev/kvm)
	accel=kvm
fi
log "booting the ${label} in QEMU (${accel})"
log_file="${out}/console-$(basename "${kernel}").log"
docker run --rm ${kvm[@]+"${kvm[@]}"} -v "${out}:/vm" -v "${kernel}:/kernel:ro" "${tools_image}" sh -euc '
	apk add -q qemu-system-x86_64 busybox-static cpio >/dev/null
	root=/tmp/initramfs
	mkdir -p "${root}/bin"
	cp /bin/busybox.static "${root}/bin/busybox"
	cp /vm/init "${root}/init"
	cp /vm/vesta-guestd-tests "${root}/vesta-guestd-tests"
	(cd "${root}" && find . | cpio -o -H newc --quiet) >/tmp/initramfs.cpio
	cpu=max
	[ "$1" = kvm ] && cpu=host
	timeout 900 qemu-system-x86_64 -accel "$1" -cpu "${cpu}" -m 1024 -smp 2 -nographic -no-reboot \
		-kernel /kernel -initrd /tmp/initramfs.cpio \
		-append "console=ttyS0 panic=-1 rdinit=/init lsm=lockdown,capability,yama,bpf cgroup_no_v1=all"
' sh "${accel}" 2>&1 | tee "${log_file}"

result="$(sed -n 's/.*VESTA-VM-RESULT rc=\([0-9]*\).*/\1/p' "${log_file}" | tail -1)"
[[ -n "${result}" ]] || die "the VM did not report a result (see ${log_file})"
[[ "${result}" == 0 ]] || die "smoke test failed in the ${label} (rc=${result}, see ${log_file})"
log "PASS: vesta BPF smoke test on the ${label}"
