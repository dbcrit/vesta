#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regenerates Go code for api/proto into api/gen/go using the pinned toolchain
# in hack/proto.Dockerfile. The generated code is committed.
#   hack/gen-proto.sh           regenerate
#   hack/gen-proto.sh --check   fail if the committed code is stale
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="vesta-proto-gen:local"
check=0
[[ "${1:-}" == "--check" ]] && check=1

if [[ "${VESTA_IN_CONTAINER:-}" != "1" ]]; then
	docker build -q -t "${image}" -f "${repo_root}/hack/proto.Dockerfile" "${repo_root}/hack" >/dev/null
	exec docker run --rm -e VESTA_IN_CONTAINER=1 -u "$(id -u):$(id -g)" -e HOME=/tmp \
		-v "${repo_root}:/src" -w /src "${image}" hack/gen-proto.sh "$@"
fi

out_dir="api/gen/go"
module_prefix="github.com/dbcrit/vesta/${out_dir}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mapfile -t protos < <(cd api/proto && find vesta -name '*.proto' | LC_ALL=C sort)
protoc -I api/proto \
	--go_out="${work}" --go_opt=module="${module_prefix}" --go_opt=paths=import \
	"${protos[@]}"

if [[ "${check}" == "1" ]]; then
	if ! diff -r "${work}" "${out_dir}" >/dev/null; then
		diff -r "${work}" "${out_dir}" || true
		echo "api/gen/go is stale; run hack/gen-proto.sh" >&2
		exit 1
	fi
	echo "api/gen/go is up to date"
	exit 0
fi

rm -rf "${out_dir}"
mkdir -p "${out_dir}"
cp -R "${work}/." "${out_dir}/"
echo "generated $(find "${out_dir}" -name '*.pb.go' | wc -l | tr -d ' ') files into ${out_dir}"
