#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# gofmt, go vet and golangci-lint for the Go module, in Docker.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
golangci_image="${VESTA_GOLANGCI_IMAGE:-golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f}"

# shellcheck disable=SC2016 # evaluated by the container shell
"${repo_root}/hack/go-docker.sh" bash -euo pipefail -c '
	mapfile -t files < <(find . -name "*.go" -not -path "./images/guest/out/*" -not -path "./guest/*" -not -path "./.git/*")
	unformatted="$(gofmt -l "${files[@]}")"
	if [[ -n "${unformatted}" ]]; then printf "gofmt needed:\n%s\n" "${unformatted}"; exit 1; fi
	go vet ./...
'

docker run --rm -v "${repo_root}:/src" -w /src \
	-v vesta-gomod:/go/pkg/mod -v vesta-golangci-cache:/root/.cache \
	"${golangci_image}" golangci-lint run --config hack/golangci.yml ./...
