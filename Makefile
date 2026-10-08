# SPDX-License-Identifier: Apache-2.0
# Top-level build entry point. Linux-only steps run in Docker so the tree
# builds on macOS too. Component builds are delegated:
#   bpf/     -> bpf/Makefile, run in the guest builder (guest/hack/in-builder.sh)
#   guest/   -> cargo in the guest builder (guest/Dockerfile.build)
#   host/    -> go build via hack/go-docker.sh
#   images/  -> images/guest/{kernel,rootfs}/build.sh, images/host/Dockerfile
# Run `make help` for the target list.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-builtin-rules

VERSION ?= 0.1.0-dev
REVISION ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
REGISTRY ?= ghcr.io/dbcrit
# Guest/kernel arch naming (x86_64|aarch64). OCI_ARCH is the image platform
# arch; BPF_ARCH is bpf/Makefile's output directory name.
HOST_ARCH := $(shell uname -m | sed -e 's/^arm64$$/aarch64/' -e 's/^amd64$$/x86_64/')
ARCH ?= $(HOST_ARCH)
OCI_ARCH := $(if $(filter aarch64,$(ARCH)),arm64,amd64)
BPF_ARCH := $(if $(filter aarch64,$(ARCH)),arm64,x86_64)

GO_DOCKER := hack/go-docker.sh
IN_BUILDER := guest/hack/in-builder.sh
BIN_DIR := bin/linux_$(OCI_ARCH)
GO_LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

# Guest build outputs, copied out of the builder's cargo target volume.
GUESTD_BIN ?= images/guest/out/guestd/$(ARCH)/vesta-guestd
BPF_OBJ_DIR ?= bpf/.output/$(BPF_ARCH)

export VESTA_GUEST_VERSION := $(VERSION)
export ARCH

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: proto-check seccomp-check lint test bpf guestd agent ## Everything CI runs except the guest image build

##@ Code generation

.PHONY: proto
proto: ## Regenerate Go protobuf code (api/gen/go)
	hack/gen-proto.sh

.PHONY: proto-check
proto-check: ## Fail if generated protobuf code is stale
	hack/gen-proto.sh --check

.PHONY: seccomp
seccomp: ## Regenerate the vesta-agent seccomp profiles (chart files/seccomp)
	hack/gen-seccomp-profile.sh

.PHONY: seccomp-check
seccomp-check: ## Fail if the chart seccomp profiles are stale
	hack/gen-seccomp-profile.sh --check

##@ Components

.PHONY: bpf
bpf: ## Build and sanity-check the BPF objects (bpf/Makefile)
	$(IN_BUILDER) make -C bpf all check

# A foreign ARCH builds natively in the builder image for that platform, under
# Docker's QEMU emulation (slow, but the same static musl toolchain).
GUESTD_PLATFORM := $(if $(filter $(ARCH),$(HOST_ARCH)),,VESTA_PLATFORM=linux/$(OCI_ARCH))

.PHONY: guestd
guestd: ## Build vesta-guestd (static musl, release) into images/guest/out/guestd/<arch>/ (ARCH=aarch64 on x86_64 uses emulation)
	$(GUESTD_PLATFORM) $(IN_BUILDER) sh -euc 'cargo build --locked --release --manifest-path guest/Cargo.toml && \
		install -D -m 0755 guest/target/release/vesta-guestd $(GUESTD_BIN)'

.PHONY: agent
agent: ## Build vesta-agent and vesta-install into bin/linux_<arch>/
	$(GO_DOCKER) env GOOS=linux GOARCH=$(OCI_ARCH) CGO_ENABLED=0 \
		go build -trimpath -buildvcs=false -ldflags '$(GO_LDFLAGS)' -o $(BIN_DIR)/ ./host/cmd/vesta-agent ./host/cmd/vesta-install

##@ Guest runtime (kernel + rootfs image)

.PHONY: guest-kernel-config
guest-kernel-config: ## Check that images/guest/kernel/vesta.conf merges into Kata's kernel config
	images/guest/kernel/build.sh config

.PHONY: guest-kernel
guest-kernel: ## Build the vesta guest kernel (vmlinux-vesta) with Kata's build-kernel.sh
	images/guest/kernel/build.sh build

.PHONY: guest-overlay
guest-overlay: bpf guestd ## Build the vesta rootfs overlay tarball only
	GUESTD_BIN=$(GUESTD_BIN) BPF_OBJ_DIR=$(BPF_OBJ_DIR) images/guest/rootfs/build.sh overlay

.PHONY: guest-rootfs
guest-rootfs: bpf guestd ## Build the vesta guest rootfs image with Kata's osbuilder
	GUESTD_BIN=$(GUESTD_BIN) BPF_OBJ_DIR=$(BPF_OBJ_DIR) images/guest/rootfs/build.sh image

.PHONY: guest-stage
guest-stage: ## Stage kernel, image, SHA256SUMS and VERSION for the vesta-install image
	images/guest/stage.sh

##@ Container images

HOST_IMAGE_ARGS = --platform linux/$(OCI_ARCH) --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) \
	-f images/host/Dockerfile

.PHONY: images
images: image-agent image-install ## Build both host images

.PHONY: image-agent
image-agent: ## Build the vesta-agent image
	docker buildx build $(HOST_IMAGE_ARGS) --target vesta-agent -t $(REGISTRY)/vesta-agent:$(VERSION) --load .

# The installer image carries the guest artifacts, so it depends on them
# explicitly: guest-kernel and guest-rootfs produce them, guest-stage copies
# them into images/guest/out/dist/<oci arch>/ with SHA256SUMS and VERSION.
.PHONY: image-install
image-install: guest-stage ## Build the vesta-install image (needs guest-kernel and guest-rootfs outputs)
	docker buildx build $(HOST_IMAGE_ARGS) --target vesta-install -t $(REGISTRY)/vesta-install:$(VERSION) --load .

##@ Deploy

.PHONY: helm
helm: ## Lint the chart and regenerate deploy/manifests
	hack/helm.sh lint
	hack/helm.sh render

.PHONY: helm-check
helm-check: ## Lint the chart, fail if deploy/manifests is stale, validate with kubeconform
	hack/helm.sh lint
	hack/helm.sh check
	hack/helm.sh kubeconform

.PHONY: crd-check
crd-check: ## Check the VestaPolicy CRD, status server-side apply and admission policy on a throwaway k3s (privileged Docker)
	hack/crd-check.sh

##@ End-to-end (Linux host with /dev/kvm; see test/e2e/README.md)

.PHONY: e2e-up
e2e-up: ## Single-node k3s + Cilium + Kata (kata-deploy) on this host
	test/e2e/up.sh

.PHONY: e2e-deploy
e2e-deploy: ## Build vesta (guest kernel, rootfs, images) and install it on the e2e cluster
	test/e2e/deploy-vesta.sh

.PHONY: e2e-test
e2e-test: ## Run the e2e tests against the e2e cluster
	test/e2e/test.sh

.PHONY: e2e
e2e: e2e-up e2e-deploy e2e-test ## All of the above

.PHONY: e2e-down
e2e-down: ## Remove vesta and the test namespace (test/e2e/down.sh --all also removes k3s)
	test/e2e/down.sh

##@ Quality

.PHONY: lint
lint: go-lint go-vulncheck rust-lint script-lint helm-check ## All linters

.PHONY: go-lint
go-lint: ## gofmt, go vet, golangci-lint
	hack/go-lint.sh

# govulncheck v1.1.4 is the newest release that runs on go 1.25.
GOVULNCHECK_VERSION ?= v1.1.4

.PHONY: go-vulncheck
go-vulncheck: ## govulncheck on the Go module (fails on reachable vulnerabilities)
	$(GO_DOCKER) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: rust-lint
rust-lint: ## cargo fmt --check and clippy -D warnings (guest workspace)
	$(IN_BUILDER) sh -euc 'cargo fmt --manifest-path guest/Cargo.toml --all --check && \
		cargo clippy --locked --manifest-path guest/Cargo.toml --all-targets -- -D warnings'

.PHONY: script-lint
script-lint: ## shellcheck, hadolint, actionlint (in Docker)
	hack/lint.sh

.PHONY: test
test: go-test rust-test abi-check ## Unit tests

.PHONY: go-test
go-test: ## go test -race ./...
	$(GO_DOCKER) env CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: rust-test
rust-test: ## cargo test (guest workspace)
	$(IN_BUILDER) cargo test --locked --manifest-path guest/Cargo.toml

.PHONY: bpf-smoke
bpf-smoke: ## Load/attach/enforce smoke test on the Docker host kernel (privileged container, guestd unit capabilities)
	VESTA_PRIVILEGED=1 $(IN_BUILDER) sh -euc 'cd guest && VESTA_SMOKE_UNIT_CAPS=1 \
		cargo test --locked -- --ignored --test-threads=1 smoke'

.PHONY: bpf-vm
bpf-vm: ## BPF smoke test inside QEMU on the vesta guest kernel (needs make guest-kernel; KVM if available)
	hack/vm-bpf-test.sh vesta

.PHONY: bpf-vm-6.1
bpf-vm-6.1: ## BPF smoke test inside QEMU on Debian's 6.1 LTS kernel (the minimum guest kernel)
	hack/vm-bpf-test.sh debian-6.1

.PHONY: abi-check
abi-check: ## Compile-check bpf/include/vesta_abi.h
	hack/check-abi.sh

.PHONY: clean
clean: ## Remove local build outputs (keeps the Kata source cache)
	rm -rf bin images/guest/out/kernel images/guest/out/rootfs images/guest/out/dist images/guest/out/guestd
