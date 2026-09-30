#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs a command in a Linux Go container with the repo mounted, e.g.
#   hack/go-docker.sh go test ./...
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec docker run --rm -v "${repo_root}:/src" -w /src \
	-v vesta-gomod:/go/pkg/mod -v vesta-gocache:/root/.cache/go-build \
	-e CGO_ENABLED=0 "${VESTA_GO_IMAGE:-golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437}" "$@"
