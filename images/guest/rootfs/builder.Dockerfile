# SPDX-License-Identifier: Apache-2.0
# Host-side environment for Kata's osbuilder (tools/osbuilder, USE_DOCKER=1).
# osbuilder starts its own rootfs/image containers through the Docker socket,
# so images/guest/rootfs/build.sh mounts the socket and the work tree at the
# same absolute path it has on the host.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Same yq release Kata's ci/install_yq.sh pins, preinstalled so osbuilder does
# not try to fetch it (it wants sudo for that).
ARG YQ_VERSION=v4.44.5
ARG YQ_SHA256_AMD64=638c4b251c49201fc94b598834b715f8f1c6e9b1854d2820772d2c79f0289002
ARG YQ_SHA256_ARM64=8205dd975725cd13bf8ecb03a9ef48ef64fdffdbf2e23cbdd7a4462c5e386211

RUN set -eux; \
    apt-get update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        bash ca-certificates coreutils curl docker-cli findutils git make tar zstd; \
    rm -rf /var/lib/apt/lists/*; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=amd64; sum="${YQ_SHA256_AMD64}" ;; \
      arm64) arch=arm64; sum="${YQ_SHA256_ARM64}" ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${arch}"; \
    echo "${sum}  /usr/local/bin/yq" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/yq; \
    yq --version; docker --version
