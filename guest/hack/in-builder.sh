#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs a command in the vesta guest builder image with the repo at /src.
#   guest/hack/in-builder.sh make -C bpf
#   guest/hack/in-builder.sh cargo test --manifest-path guest/Cargo.toml
# VESTA_PRIVILEGED=1 adds --privileged (BPF smoke tests only). The host's bpffs
# is not shared: tests mount a private bpffs, so nothing stays attached to the
# Docker VM kernel once the container exits.
# VESTA_PLATFORM=linux/arm64 (or linux/amd64) runs the builder for that
# platform, under QEMU emulation when it is not the Docker host's. Each
# platform gets its own image tag and cargo target volume.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

platform=()
suffix=""
case "${VESTA_PLATFORM:-}" in
"") ;;
linux/amd64 | linux/arm64)
	platform=(--platform "${VESTA_PLATFORM}")
	suffix="-${VESTA_PLATFORM#linux/}"
	;;
*)
	echo "in-builder.sh: unsupported VESTA_PLATFORM '${VESTA_PLATFORM}' (linux/amd64 or linux/arm64)" >&2
	exit 2
	;;
esac
image="${VESTA_BUILDER_IMAGE:-vesta-guest-build:local${suffix}}"

if ! docker image inspect "${image}" >/dev/null 2>&1; then
	docker build -q ${platform[@]+"${platform[@]}"} -f "${repo_root}/guest/Dockerfile.build" -t "${image}" "${repo_root}/guest" >/dev/null
fi

extra=()
if [[ "${VESTA_PRIVILEGED:-}" == "1" ]]; then
	extra+=(--privileged)
fi

tty=()
[[ -t 0 ]] && tty=(-t)

exec docker run --rm ${tty[@]+"${tty[@]}"} ${extra[@]+"${extra[@]}"} ${platform[@]+"${platform[@]}"} \
	-v "${repo_root}:/src" -w /src \
	-v vesta-cargo-registry:/usr/local/cargo/registry \
	-v "vesta-guest-target${suffix}:/src/guest/target" \
	-e CARGO_TERM_COLOR=never \
	"${image}" "$@"
