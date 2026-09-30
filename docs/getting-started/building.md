---
title: Building
parent: Getting Started
nav_order: 1
---

# Building

All builds go through the top-level [`Makefile`]({{ site.vesta_repo_url }}/blob/main/Makefile). Every Linux-specific step runs in a container whose base image is pinned by digest, so a host with only Docker and GNU make can build the whole tree, macOS included. This page lists every target, the toolchain containers, the pinned upstream versions, and where the outputs go.
{: .fs-5 .fw-300 }

## Quick start

```sh
make help                 # list targets
make test                 # Go tests (-race), Rust tests, ABI header check
make bpf guestd agent     # BPF objects, vesta-guestd, vesta-agent + vesta-install
make image-agent          # vesta-agent container image
# Slow: guest kernel, guest rootfs image, installer image
make guest-kernel guest-rootfs image-install
```

`make` with no target prints the help. `make all` runs `proto-check seccomp-check lint test bpf guestd agent`, which is everything CI runs except the guest image build.

## Make variables

| Variable | Default | Used for |
|---|---|---|
| `VERSION` | `0.1.0-dev` | `-X main.version` in the Go binaries, image tags, and the guest version (exported as `VESTA_GUEST_VERSION`). Must be semver without build metadata, at most 63 characters, because it becomes the `vesta.dev/guest-ready` label value and a directory name under `/opt/vesta/kata/` |
| `REVISION` | `git rev-parse --short=12 HEAD` | `org.opencontainers.image.revision` label |
| `REGISTRY` | `ghcr.io/dbcrit` | Image names: `$(REGISTRY)/vesta-agent:$(VERSION)`, `$(REGISTRY)/vesta-install:$(VERSION)` |
| `ARCH` | host `uname -m`, normalized to `x86_64` or `aarch64` | Guest kernel/rootfs arch. Derived: `OCI_ARCH` (`amd64`/`arm64`) and `BPF_ARCH` (`x86_64`/`arm64`) |
| `GUESTD_BIN` | `images/guest/out/guestd/$(ARCH)/vesta-guestd` | guestd binary baked into the rootfs |
| `BPF_OBJ_DIR` | `bpf/.output/$(BPF_ARCH)` | BPF objects baked into the rootfs |
| `GOVULNCHECK_VERSION` | `v1.1.4` | govulncheck version (the newest that runs on Go 1.25) |

## Targets

### Code generation

| Target | What it does |
|---|---|
| `proto` | Regenerates Go protobuf code from `api/proto` into `api/gen/go` (`hack/gen-proto.sh`). The generated code is committed |
| `proto-check` | Fails if `api/gen/go` is stale |
| `seccomp` | Regenerates the vesta-agent seccomp profiles in `deploy/helm/vesta/files/seccomp/` (`hack/gen-seccomp-profile.sh`) |
| `seccomp-check` | Fails if those profiles are stale |

### Components

| Target | What it does | Output |
|---|---|---|
| `bpf` | Builds `bpf/vesta.bpf.c` for x86_64 and arm64 in the guest builder, then checks each object: BTF parses, and the sections `tp_btf/sched_process_exec`, `lsm/bprm_check_security`, `cgroup/connect4`, `cgroup/connect6` exist | `bpf/.output/x86_64/vesta.bpf.o`, `bpf/.output/arm64/vesta.bpf.o` |
| `guestd` | `cargo build --locked --release` of `vesta-guestd` (static musl). Fails if `ARCH` differs from the host: cross builds are not wired up | `images/guest/out/guestd/<arch>/vesta-guestd` |
| `agent` | `go build -trimpath` of `vesta-agent` and `vesta-install`, `CGO_ENABLED=0`, `GOOS=linux`, ldflags `-s -w -buildid= -X main.version=$(VERSION)` | `bin/linux_<oci-arch>/vesta-agent`, `bin/linux_<oci-arch>/vesta-install` |

vesta-guestd's `build.rs` compiles the same BPF source with the same flags for its libbpf-rs skeleton, so `make guestd` does not depend on `make bpf`.

### Guest runtime (kernel and rootfs image)

| Target | What it does | Output |
|---|---|---|
| `guest-kernel-config` | Fetches Kata at the pinned commit, installs `images/guest/kernel/vesta.conf` as Kata build type `vesta`, runs Kata's `build-kernel.sh ... -f setup`, and fails if any line of the fragment is missing from the final `.config`. Takes minutes | `images/guest/out/kernel/<arch>/config-vesta` |
| `guest-kernel` | The same setup, then a full build with Kata's `build-kernel.sh -a <arch> -v 6.18.35 -b vesta -x -m`. On x86_64 the `vmlinux` is stripped of DWARF with `objcopy --strip-debug`, which keeps `.BTF`; the build fails if `.BTF` is missing. On aarch64 it copies `arch/arm64/boot/Image` | `images/guest/out/kernel/<arch>/vmlinux-vesta`, `vmlinux-vesta.sha256` |
| `guest-overlay` | Depends on `bpf guestd`. Builds only the reproducible vesta overlay tarball | `images/guest/out/rootfs/<arch>/vesta-overlay.tar.zst` |
| `guest-rootfs` | Depends on `bpf guestd`. Builds the overlay, checks the rendered `guestd.toml` with `vesta-guestd --check-config` (when the Docker host arch matches), then runs Kata's osbuilder `make image` with `DISTRO=ubuntu OS_VERSION=resolute AGENT_INIT=no AGENT_POLICY=yes MEASURED_ROOTFS=no GUEST_HOOKS_TARBALL=<overlay>` | `images/guest/out/rootfs/<arch>/vesta-guest.img`, `vesta-guest.img.sha256` |
| `guest-stage` | Copies the kernel and image into the layout the installer image expects, with `SHA256SUMS` and `VERSION`, all mode 0444. Needs the outputs of `guest-kernel` and `guest-rootfs` | `images/guest/out/dist/<oci-arch>/{vmlinux-vesta,vesta-guest.img,SHA256SUMS,VERSION}` |

`guest-rootfs` runs osbuilder with the Docker socket mounted, because osbuilder starts its own containers and needs a privileged one for the loop device. The work tree is mounted at the same absolute path on both sides.

The kernel source tree lives in the Docker volume `vesta-kernel-build-<arch>`, not under `out/`, because kernel sources contain paths that differ only in case and break on case-insensitive filesystems such as macOS APFS.

### Container images

| Target | What it does |
|---|---|
| `images` | `image-agent` and `image-install` |
| `image-agent` | `docker buildx build --target vesta-agent -t $(REGISTRY)/vesta-agent:$(VERSION) --load .` |
| `image-install` | Depends on `guest-stage`. `docker buildx build --target vesta-install -t $(REGISTRY)/vesta-install:$(VERSION) --load .` The image carries the staged guest artifacts in `/usr/share/vesta/guest/` |

Both images are built from [`images/host/Dockerfile`]({{ site.vesta_repo_url }}/blob/main/images/host/Dockerfile) for `linux/$(OCI_ARCH)`. The Go build stage uses `golang:1.25-trixie`, the runtime stage is `gcr.io/distroless/static-debian13:nonroot` (both pinned by digest), and the binaries run as `65532:65532` by default. The images are loaded into the local Docker daemon (`--load`). Pushing them to a registry is up to you.

### Deploy

| Target | What it does |
|---|---|
| `helm` | `helm lint --strict` with the default and two alternate value sets, then regenerates `deploy/manifests/vesta.yaml` (`helm template` with default values, namespace `vesta-system`) |
| `helm-check` | Lints, fails if `deploy/manifests/vesta.yaml` is stale, and validates rendered manifests with kubeconform against Kubernetes 1.34.1 (PodMonitor skipped) |

### Quality

| Target | What it does |
|---|---|
| `lint` | `go-lint go-vulncheck rust-lint script-lint helm-check` |
| `go-lint` | `gofmt -l`, `go vet ./...`, `golangci-lint run --config hack/golangci.yml` |
| `go-vulncheck` | `govulncheck ./...`, fails on reachable vulnerabilities |
| `rust-lint` | `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` on the guest workspace |
| `script-lint` | shellcheck on every `*.sh`, hadolint on every Dockerfile, actionlint on `.github/workflows` |
| `test` | `go-test rust-test abi-check` |
| `go-test` | `go test -race -count=1 ./...` (with `CGO_ENABLED=1` for the race detector) |
| `rust-test` | `cargo test --locked` on the guest workspace |
| `bpf-smoke` | Privileged: loads, attaches and exercises the BPF programs on the Docker host kernel, holding only the guestd unit's four capabilities (`VESTA_SMOKE_UNIT_CAPS=1`). See [Testing](../testing.md) |
| `abi-check` | Compiles `test/abi/abi_check.c` against `bpf/include/vesta_abi.h` with gcc (host), clang for aarch64, and clang for BPF, with `-Wpadded -Werror` |
| `clean` | Removes `bin/` and `images/guest/out/{kernel,rootfs,dist,guestd}`. The Kata source checkout in `images/guest/out/src/` is kept |

## Toolchain containers

| Script | Image | Used by |
|---|---|---|
| [`hack/go-docker.sh`]({{ site.vesta_repo_url }}/blob/main/hack/go-docker.sh) | `golang:1.25-bookworm` (digest-pinned; override with `VESTA_GO_IMAGE`) | `agent`, `go-test`, `go-vulncheck`, `go-lint` (gofmt, vet) |
| [`hack/go-lint.sh`]({{ site.vesta_repo_url }}/blob/main/hack/go-lint.sh) | `golangci/golangci-lint:v2.14.0` (`VESTA_GOLANGCI_IMAGE`) | `go-lint` |
| [`guest/hack/in-builder.sh`]({{ site.vesta_repo_url }}/blob/main/guest/hack/in-builder.sh) | `vesta-guest-build:local`, built from [`guest/Dockerfile.build`]({{ site.vesta_repo_url }}/blob/main/guest/Dockerfile.build) on first use (`VESTA_BUILDER_IMAGE`). Base `rust:1.98.1-alpine3.24` with clang 21, LLVM 21, bpftool, libbpf-dev, protoc. `VESTA_PRIVILEGED=1` adds `--privileged` | `bpf`, `guestd`, `rust-lint`, `rust-test`, `bpf-smoke` |
| [`hack/gen-proto.sh`]({{ site.vesta_repo_url }}/blob/main/hack/gen-proto.sh) | `vesta-proto-gen:local` from `hack/proto.Dockerfile`: `golang:1.25-bookworm`, protoc 36.2 (SHA-256 checked), protoc-gen-go v1.36.12 | `proto`, `proto-check` |
| [`hack/gen-seccomp-profile.sh`]({{ site.vesta_repo_url }}/blob/main/hack/gen-seccomp-profile.sh) | `golang:1.26-trixie` (containerd v2.4.1 needs Go ≥ 1.26), `debian:trixie-slim` to run the arm64 generator under emulation | `seccomp`, `seccomp-check` |
| [`hack/check-abi.sh`]({{ site.vesta_repo_url }}/blob/main/hack/check-abi.sh) | `debian:trixie-slim` (`VESTA_ABI_CHECK_IMAGE`) with gcc and clang | `abi-check` |
| [`hack/helm.sh`]({{ site.vesta_repo_url }}/blob/main/hack/helm.sh) | `alpine/helm:3.19.0`, `ghcr.io/yannh/kubeconform:v0.7.0` | `helm`, `helm-check` |
| [`hack/lint.sh`]({{ site.vesta_repo_url }}/blob/main/hack/lint.sh) | `koalaman/shellcheck:v0.11.0`, `hadolint/hadolint:v2.14.0`, `rhysd/actionlint:1.7.8` | `script-lint` |
| `images/guest/kernel/build.sh` | `vesta-kata-kernel-builder:4.2.0`, built from Kata's `tools/packaging/static-build/kernel/Dockerfile` | `guest-kernel-config`, `guest-kernel` |
| `images/guest/rootfs/build.sh` | `vesta-osbuilder:4.2.0` from [`images/guest/rootfs/builder.Dockerfile`]({{ site.vesta_repo_url }}/blob/main/images/guest/rootfs/builder.Dockerfile) | `guest-overlay`, `guest-rootfs` |

Caches live in named Docker volumes: `vesta-gomod`, `vesta-gocache`, `vesta-golangci-cache`, `vesta-cargo-registry`, `vesta-guest-target` (the guest `cargo` target directory) and `vesta-kernel-build-<arch>`.

## Pinned upstream versions

The guest build inputs are in [`images/guest/versions.env`]({{ site.vesta_repo_url }}/blob/main/images/guest/versions.env):

| Key | Value | Notes |
|---|---|---|
| `KATA_VERSION` | `4.2.0` | Kata tag to check out |
| `KATA_COMMIT` | `c7351e797efff8bfc6bd73da0eb1909be12e2cfe` | The build refuses a tag that resolves to a different commit, or an existing checkout at another commit |
| `KATA_REPO` | `https://github.com/kata-containers/kata-containers.git` | |
| `KERNEL_VERSION` | `6.18.35` | Cross-checked against Kata's `versions.yaml` (`assets.kernel.version`) |
| `ROOTFS_DISTRO` / `ROOTFS_OS_VERSION` | `ubuntu` / `resolute` | Kata's stock image distro (Ubuntu 26.04) |

Other pinned versions: libbpf 1.7.0 (vendored by libbpf-sys; libbpf-rs 0.27.2), NRI v0.12.3, mdlayher/vsock v1.3.0, containerd v2.4.1 (seccomp profile source), Go 1.25 for the module. See [`go.mod`]({{ site.vesta_repo_url }}/blob/main/go.mod) and [`guest/Cargo.lock`]({{ site.vesta_repo_url }}/blob/main/guest/Cargo.lock) for the full dependency set.

## Guest build environment variables

The guest scripts read these. The Makefile sets `VESTA_GUEST_VERSION` from `VERSION` and passes `ARCH`, `GUESTD_BIN` and `BPF_OBJ_DIR`.

| Variable | Default | Script | Effect |
|---|---|---|---|
| `VESTA_GUEST_VERSION` | required | `rootfs/build.sh`, `stage.sh` | Guest version. Written to `/usr/lib/vesta/image-version`, to `guest_image_version` in `/etc/vesta/guestd.toml`, and to `VERSION` in the staged assets |
| `VESTA_KERNEL_CONFIDENTIAL` | `yes` | `kernel/build.sh` | `yes` passes `-x -m` to `build-kernel.sh`, like Kata's stock x86_64/aarch64 kernel, so the vesta kernel is a superset of it. `no` drops them |
| `VESTA_GUEST_OUT` | `images/guest/out` | all | Output root |
| `GUESTD_CONFIG` | `guest/vesta-guestd/guestd.example.toml` | `rootfs/build.sh` | Template for `/etc/vesta/guestd.toml`. It must contain exactly one top-level `guest_image_version` line |
| `VESTA_BPF_EMBEDDED` | `no` | `rootfs/build.sh` | `yes`: ship no objects in `/usr/lib/vesta/bpf`. vesta-guestd loads the object embedded in its binary (libbpf-rs skeleton) and does not read that directory |
| `SOURCE_DATE_EPOCH` | last commit time | `rootfs/build.sh` | Fixed mtime for overlay entries |

## Outputs

| Path | Produced by |
|---|---|
| `bin/linux_<oci-arch>/vesta-agent`, `vesta-install` | `make agent` |
| `bpf/.output/<x86_64\|arm64>/vesta.bpf.o` | `make bpf` |
| `images/guest/out/guestd/<arch>/vesta-guestd` | `make guestd` |
| `images/guest/out/kernel/<arch>/` | `make guest-kernel-config`, `make guest-kernel` |
| `images/guest/out/rootfs/<arch>/` | `make guest-overlay`, `make guest-rootfs` |
| `images/guest/out/dist/<oci-arch>/` | `make guest-stage` |
| `images/guest/out/src/kata-containers-4.2.0/` | Kata checkout, reused across builds |
| `$(REGISTRY)/vesta-agent:$(VERSION)`, `$(REGISTRY)/vesta-install:$(VERSION)` | `make image-agent`, `make image-install` (local Docker) |

`images/guest/out/` is git-ignored.

## Known build limitations

- There is no arm64 `vesta-guestd`: the builder has no musl cross toolchain, and `make guestd` refuses a non-native `ARCH`. The arm64 BPF object builds.
- The full guest kernel build, the osbuilder rootfs image and the `vesta-install` image have not been built in this tree yet. `guest-kernel-config` has been run (it is also a CI job).
- Image digests pinned inside shell scripts are not tracked by Dependabot.

See [Implementation status](../IMPLEMENTATION_STATUS.md) for the full list.
