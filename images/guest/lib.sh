# SPDX-License-Identifier: Apache-2.0
# Shared helpers for images/guest build scripts. Source, do not execute.
# shellcheck shell=bash

guest_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # used by the scripts that source this file
repo_root="$(cd "${guest_dir}/../.." && pwd)"
# shellcheck source=images/guest/versions.env
source "${guest_dir}/versions.env"

out_dir="${VESTA_GUEST_OUT:-${guest_dir}/out}"
kata_src="${out_dir}/src/kata-containers-${KATA_VERSION}"

# The Kata checkout contains Go packages outside any module. A go.mod here
# keeps them out of the repo module's ./... (go vet, go test).
mkdir -p "${out_dir}"
[[ -f "${out_dir}/go.mod" ]] || printf 'module vesta.local/guest-build-output\n\ngo 1.25.0\n' >"${out_dir}/go.mod"

log() { printf '[%s] %s\n' "$(basename "$0")" "$*" >&2; }
die() { log "error: $*"; exit 1; }

require() {
	local c
	for c in "$@"; do
		command -v "${c}" >/dev/null 2>&1 || die "required command not found: ${c}"
	done
}

# Semver without build metadata, so it is usable as a Kubernetes label value
# (vesta.dev/guest-ready) and as a directory name under /opt/vesta/kata/.
validate_version() {
	local v="$1"
	[[ "${v}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
		die "invalid guest version '${v}': want MAJOR.MINOR.PATCH[-PRERELEASE]"
	((${#v} <= 63)) || die "guest version '${v}' exceeds the 63-character label limit"
}

# Checks out Kata Containers at KATA_VERSION into ${kata_src} and verifies the
# tag resolves to KATA_COMMIT. Re-uses an existing checkout if it matches.
fetch_kata() {
	require git
	if [[ -d "${kata_src}/.git" ]]; then
		local have
		have="$(git -C "${kata_src}" rev-parse HEAD)"
		[[ "${have}" == "${KATA_COMMIT}" ]] ||
			die "${kata_src} is at ${have}, want ${KATA_COMMIT}; remove it and retry"
		return 0
	fi
	log "fetching kata-containers ${KATA_VERSION}"
	mkdir -p "$(dirname "${kata_src}")"
	local tmp="${kata_src}.tmp"
	rm -rf "${tmp}"
	git -c advice.detachedHead=false clone --quiet --depth 1 --branch "${KATA_VERSION}" "${KATA_REPO}" "${tmp}"
	local got
	got="$(git -C "${tmp}" rev-parse HEAD)"
	if [[ "${got}" != "${KATA_COMMIT}" ]]; then
		rm -rf "${tmp}"
		die "tag ${KATA_VERSION} resolves to ${got}, pinned ${KATA_COMMIT}"
	fi
	mv "${tmp}" "${kata_src}"
}

# Prints the hex sha256 of a file (GNU coreutils or macOS shasum).
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}
