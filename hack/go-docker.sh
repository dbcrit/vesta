#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs a command in a Linux Go container with the repo mounted, e.g.
#   hack/go-docker.sh go test ./...
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec docker run --rm -v "${repo_root}:/src" -w /src \
	-v vesta-gomod:/go/pkg/mod -v vesta-gocache:/root/.cache/go-build \
	-e CGO_ENABLED=0 "${VESTA_GO_IMAGE:-golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c}" "$@"
