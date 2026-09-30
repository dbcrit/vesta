# Contributing to vesta

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Upstream facts vesta relies on are in [docs/compat/kata-4.2.md](docs/compat/kata-4.2.md), and the kernel/userspace ABI is in [docs/abi.md](docs/abi.md).

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. It certifies that you wrote the change, or have the right to submit it under the project's licenses. Pull requests with unsigned commits cannot be merged.

## Licenses

- Userspace, API, deploy and build files: Apache-2.0. Put `SPDX-License-Identifier: Apache-2.0` at the top of each new file.
- BPF C in `bpf/`: `GPL-2.0-only OR BSD-2-Clause`, declared in the program as `char LICENSE[] SEC("license") = "Dual BSD/GPL";`.

## Building

Only Docker and GNU make are needed. Everything Linux-specific runs in containers whose base images are pinned by digest, so the tree builds on macOS too. There is no KVM requirement for anything below.

| Command | What it does |
|---|---|
| `make help` | List all targets |
| `make proto` / `make proto-check` | Regenerate / check the generated Go protobuf code |
| `make bpf` | Build the BPF objects (`bpf/Makefile`) |
| `make guestd` | Build `vesta-guestd` for `ARCH` (musl) |
| `make agent` | Build `vesta-agent` and `vesta-install` into `bin/linux_<arch>/` |
| `make test` | Go tests with `-race`, Rust tests, ABI header check |
| `make lint` | gofmt, go vet, golangci-lint, rustfmt, clippy, shellcheck, hadolint, actionlint, helm lint, kubeconform |
| `make helm` | Lint the chart and regenerate `deploy/manifests/vesta.yaml` |
| `make seccomp` | Regenerate the vesta-agent seccomp profiles in `deploy/helm/vesta/files/seccomp/` |

The guest runtime is built with Kata's own tooling at the version pinned in `images/guest/versions.env` (Kata 4.2.0):

| Command | What it does | Time |
|---|---|---|
| `make guest-kernel-config` | Merges `images/guest/kernel/vesta.conf` into Kata's kernel config and fails if any option is dropped | minutes |
| `make guest-kernel` | Builds `vmlinux-vesta` (Linux 6.18.35 with BTF) | long |
| `make guest-rootfs` | Builds `vesta-guest.img` with Kata's osbuilder. Needs the Docker socket and privileged containers for the loop device | long |
| `make guest-stage images` | Stages the guest artifacts and builds both host images | |

Outputs go to `images/guest/out/`, which is git-ignored. `VERSION=x.y.z` sets the image tags and the guest version. The guest version is also the value of the `vesta.dev/guest-ready` node label, so it must be semver without build metadata.

## Pull requests

- Keep changes focused and explain the reason in the description.
- Before pushing, run `make lint test` and, where relevant, `make proto-check helm-check`. CI runs the same targets.
- Changes to `api/proto` or `bpf/include/vesta_abi.h` change the shared contract. Update `docs/abi.md` and both the Go and Rust sides in the same PR.
- Treat all guest→host data as untrusted: bound every size, never derive host paths or commands from guest input, and do not panic on malformed input.
- New GitHub Actions must be pinned by full commit SHA, and container images by digest.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not use public issues for vulnerabilities.
