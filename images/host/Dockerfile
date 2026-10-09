# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0
# Host images, built from the repo root:
#   docker buildx build -f images/host/Dockerfile --target vesta-agent   .
#   docker buildx build -f images/host/Dockerfile --target vesta-install .
# vesta-install also needs the staged guest artifacts in
# images/guest/out/dist/<TARGETARCH>/ (make guest-stage).

ARG GO_IMAGE=golang:1.26-trixie@sha256:74b756a8621f299bc587991ac19d1f26aa415006eb23c50132c467c29f8f5a25
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download -x
COPY api/ api/
COPY host/ host/
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN --mount=type=cache,target=/go/pkg/mod \
      --mount=type=cache,target=/root/.cache/go-build \
      set -eu; \
      for cmd in vesta-agent vesta-install; do \
      GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o /out/${cmd} ./host/cmd/${cmd}; \
      done

FROM ${RUNTIME_IMAGE} AS runtime-base
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/dbcrit/vesta" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="vesta"

FROM runtime-base AS vesta-agent
LABEL org.opencontainers.image.title="vesta-agent" \
      org.opencontainers.image.description="vesta host agent: NRI plugin and guest channel for Kata sandboxes"
COPY --from=build /out/vesta-agent /usr/bin/vesta-agent
USER 65532:65532
ENTRYPOINT ["/usr/bin/vesta-agent"]

FROM runtime-base AS vesta-install
ARG TARGETARCH
LABEL org.opencontainers.image.title="vesta-install" \
      org.opencontainers.image.description="vesta node installer: guest kernel/image, kata-qemu-vesta runtime handler, node label"
COPY --from=build /out/vesta-install /usr/bin/vesta-install
# Guest artifacts: vmlinux-vesta, vesta-guest.img, SHA256SUMS and VERSION
# (vesta-install -assets-dir default). The installer verifies the sums.
# stage.sh makes the files 0444; COPY keeps those modes (a --chmod would also
# strip the x bit from the directory).
COPY images/guest/out/dist/${TARGETARCH}/ /usr/share/vesta/guest/
USER 65532:65532
ENTRYPOINT ["/usr/bin/vesta-install"]
