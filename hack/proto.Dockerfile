# SPDX-License-Identifier: Apache-2.0
# Pinned protobuf toolchain for hack/gen-proto.sh.
FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG PROTOC_VERSION=36.2
ARG PROTOC_SHA256_AMD64=121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278
ARG PROTOC_SHA256_ARM64=8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a
ARG PROTOC_GEN_GO_VERSION=v1.36.12

RUN set -eux; \
    apt-get update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends unzip; \
    rm -rf /var/lib/apt/lists/*; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=x86_64;  sum="${PROTOC_SHA256_AMD64}" ;; \
      arm64) arch=aarch_64; sum="${PROTOC_SHA256_ARM64}" ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${arch}.zip"; \
    echo "${sum}  /tmp/protoc.zip" | sha256sum -c -; \
    unzip -q /tmp/protoc.zip -d /usr/local bin/protoc 'include/*'; \
    rm /tmp/protoc.zip; \
    GOBIN=/usr/local/bin go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"; \
    protoc --version; protoc-gen-go --version
