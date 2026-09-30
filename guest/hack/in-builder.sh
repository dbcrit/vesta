#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs a command in the vesta guest builder image with the repo at /src.
#   guest/hack/in-builder.sh make -C bpf
#   guest/hack/in-builder.sh cargo test --manifest-path guest/Cargo.toml
# VESTA_PRIVILEGED=1 adds --privileged (BPF smoke tests only). The host's bpffs
# is not shared: tests mount a private bpffs, so nothing stays attached to the
# Docker VM kernel once the container exits.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${VESTA_BUILDER_IMAGE:-vesta-guest-build:local}"

if ! docker image inspect "${image}" >/dev/null 2>&1; then
	docker build -q -f "${repo_root}/guest/Dockerfile.build" -t "${image}" "${repo_root}/guest" >/dev/null
fi

extra=()
if [[ "${VESTA_PRIVILEGED:-}" == "1" ]]; then
	extra+=(--privileged)
fi

tty=()
[[ -t 0 ]] && tty=(-t)

exec docker run --rm ${tty[@]+"${tty[@]}"} ${extra[@]+"${extra[@]}"} \
	-v "${repo_root}:/src" -w /src \
	-v vesta-cargo-registry:/usr/local/cargo/registry \
	-v vesta-guest-target:/src/guest/target \
	-e CARGO_TERM_COLOR=never \
	"${image}" "$@"
