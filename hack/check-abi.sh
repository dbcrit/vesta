#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compile-checks bpf/include/vesta_abi.h for x86_64/arm64 userspace and the BPF target.
# Runs inside a Debian container so it works on non-Linux hosts.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${VESTA_ABI_CHECK_IMAGE:-debian:trixie-slim}"

if [[ "${VESTA_IN_CONTAINER:-}" != "1" ]]; then
	exec docker run --rm -e VESTA_IN_CONTAINER=1 -e DEBIAN_FRONTEND=noninteractive -v "${repo_root}:/src:ro" -w /src "${image}" \
		bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends clang gcc libc6-dev linux-libc-dev >/dev/null && hack/check-abi.sh'
fi

flags=(-std=c11 -Wall -Wextra -Wpadded -Werror -I bpf/include -c -o /dev/null)
gcc "${flags[@]}" test/abi/abi_check.c
clang "${flags[@]}" --target=aarch64-linux-gnu -isystem /usr/include -isystem "/usr/include/$(gcc -dumpmachine)" test/abi/abi_check.c
clang "${flags[@]}" --target=bpf -isystem /usr/include -isystem "/usr/include/$(gcc -dumpmachine)" test/abi/abi_check.c
echo "vesta_abi.h: OK (gcc host, clang aarch64, clang bpf)"
