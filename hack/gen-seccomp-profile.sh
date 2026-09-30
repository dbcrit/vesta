#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generates the vesta-agent Localhost seccomp profiles shipped in the Helm chart
# (deploy/helm/vesta/files/seccomp/).
#
# containerd's RuntimeDefault profile denies socket(AF_VSOCK), which vesta-agent
# needs to dial guests. The profile here is exactly containerd's default for a
# container with no capabilities (contrib/seccomp.DefaultProfile at the pinned
# containerd version), plus one rule allowing socket(2) with domain AF_VSOCK.
# The chart's seccomp-profile init container copies the profile for the
# node's arch into <kubelet root>/seccomp/vesta/ before the agent starts.
#
#   hack/gen-seccomp-profile.sh          regenerate
#   hack/gen-seccomp-profile.sh --check  fail if the committed profiles are stale
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${repo_root}/deploy/helm/vesta/files/seccomp"
containerd_version="v2.4.1"
# containerd v2.4.1 requires go >= 1.26.6; this throwaway module is separate
# from the repo module (go 1.25).
go_image="golang:1.26-trixie@sha256:bdca99a00bc16590cb1a0bb4e698f5fc5d6a64e4d5eef13d9f18a0ee08e5fa65"
run_image="debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"
check=0
[[ "${1:-}" == "--check" ]] && check=1

work="$(mktemp -d "${TMPDIR:-/tmp}/vesta-seccomp.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/gen" "${work}/out"

cat >"${work}/gen/main.go" <<'EOF'
// Command gen prints containerd's default seccomp profile for a container
// without capabilities, extended to allow socket(AF_VSOCK, ...).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func main() {
	p := seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}})
	p.Syscalls = append(p.Syscalls, specs.LinuxSyscall{
		Names:  []string{"socket"},
		Action: specs.ActAllow,
		Args:   []specs.LinuxSeccompArg{{Index: 0, Value: unix.AF_VSOCK, Op: specs.OpEqualTo}},
	})
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal profile:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
EOF

cat >"${work}/gen/go.mod" <<EOF
module vesta.local/seccompgen

go 1.25.0

require github.com/containerd/containerd/v2 ${containerd_version}
EOF

# Build natively for each arch (the profile depends on runtime.GOARCH), then
# run the arm64 binary under emulation.
docker run --rm -v "${work}:/work" -w /work/gen -e CGO_ENABLED=0 -e GOFLAGS=-mod=mod \
	-v vesta-gomod:/go/pkg/mod "${go_image}" bash -euo pipefail -c '
		go mod tidy 2>&1 | grep -v "^go: downloading" >&2 || true
		test -f go.sum
		for a in amd64 arm64; do GOARCH=$a go build -trimpath -o /work/gen-$a .; done'
for a in amd64 arm64; do
	docker run --rm --platform "linux/${a}" -v "${work}:/work" "${run_image}" "/work/gen-${a}" >"${work}/out/vesta-agent-${a}.json"
done

if ((check)); then
	if ! diff -ru "${work}/out" "${out_dir}"; then
		echo "deploy/helm/vesta/files/seccomp is stale; run hack/gen-seccomp-profile.sh" >&2
		exit 1
	fi
	echo "deploy/helm/vesta/files/seccomp is up to date"
	exit 0
fi

mkdir -p "${out_dir}"
cp "${work}"/out/*.json "${out_dir}/"
echo "wrote $(find "${out_dir}" -name '*.json' | wc -l | tr -d ' ') profiles into deploy/helm/vesta/files/seccomp"
