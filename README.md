# vesta

eBPF security monitoring and enforcement for Kata Containers guest kernels.

vesta runs BPF LSM, cgroup and tracepoint programs inside each Kata pod's guest kernel. It audits and optionally blocks process execution, network connections, file access and sensitive syscalls there, with the kind of OS-level context that host-side eBPF tools cannot see through the VM boundary. A host DaemonSet (`vesta-agent`) manages policies defined as Kubernetes CRDs. It reaches a guest-side daemon (`vesta-guestd`) over vsock and exports the enriched events.

The design follows Ant Group's AntCWPP whitepaper, with vesta's own choices for transport, program lifecycle and threat model.

The name: vesta is short for **V**irtual-machine **e**BPF **S**ecurity and **T**elemetry **A**gent. It is also a nod to Vesta, the Roman goddess of the hearth and home, who guarded what happens inside the house. vesta guards what happens inside each pod's VM.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architecture, threat model, roadmap and open questions.

## Status

Pre-release (0.1.0-dev). The Phase 0/1 components are implemented, build, and pass their unit tests. The BPF programs also pass a privileged load-and-enforce smoke test on a Docker host kernel. Nothing has run end to end in a Kata VM yet: no KVM was available during development.

| Component | State |
|---|---|
| BPF programs (`bpf/`): P1 exec audit, P2 exec LSM, N1 egress connect4/6 | Implemented. Builds for x86_64 and arm64; smoke-tested on a 7.0 kernel with the bpf LSM |
| `vesta-guestd` (`guest/`) | Implemented: load/attach/pin, policy maps, container binding, CTRL/EVT channel, heartbeats, replay buffer |
| `vesta-agent` (`host/cmd/vesta-agent`) | Implemented: NRI plugin with start gate, sandbox sessions over vsock, event export (JSON lines), metrics. Policies from a static file or from `VestaPolicy` objects (CRD, dynamic informer), hot-reloaded into running guests; per-node status |
| `vesta-install` (`host/cmd/vesta-install`) | Implemented: guest assets, runtime config, containerd drop-in with rollback, node label, uninstall |
| Guest kernel fragment and rootfs recipe (`images/guest/`) | Fragment merge checked with Kata's `build-kernel.sh`; the full kernel and osbuilder image builds have not been run here |
| Helm chart (`deploy/`) | Lints and validates against the Kubernetes 1.34 schemas |

What is implemented, what deviates from the architecture, and what is still open: [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Building

Everything Linux-specific runs in Docker, so the tree builds on macOS or Linux with only Docker and `make` installed. `make help` lists all targets.

```sh
make proto-check        # generated protobuf Go code is current
make bpf abi-check      # BPF objects (x86_64, arm64) and the ABI header check
make rust-lint rust-test
make go-lint go-test go-vulncheck
make helm-check script-lint seccomp-check
make bpf-smoke          # privileged: loads and exercises the BPF programs on the Docker host kernel
make agent guestd       # binaries into bin/ and images/guest/out/
make image-agent        # vesta-agent container image
make guest-kernel guest-rootfs guest-stage image-install   # guest kernel/image and installer image (slow)
```

## Repository layout

| Path | Contents | License |
|---|---|---|
| `bpf/` | BPF programs (C, CO-RE). `bpf/include/vesta_abi.h` is the kernel/userspace ABI ([docs/abi.md](docs/abi.md)) | GPL-2.0-only OR BSD-2-Clause |
| `guest/` | Cargo workspace for `vesta-guestd` (Rust, libbpf-rs) | Apache-2.0 |
| `host/` | Go: `cmd/vesta-agent` (DaemonSet, NRI plugin), `cmd/vesta-install` (node installer), `internal/` | Apache-2.0 |
| `api/proto/` | Channel and event protobuf (`vesta/channel/v1`, `vesta/event/v1`) | Apache-2.0 |
| `api/gen/go/` | Generated Go code, committed. Regenerate with `hack/gen-proto.sh` | Apache-2.0 |
| `api/channel/` | Wire constants: ports, frame size, protocol and ABI versions | Apache-2.0 |
| `images/guest/` | Guest kernel fragment and guest image recipe | Apache-2.0 |
| `deploy/` | Helm chart, RuntimeClass `kata-qemu-vesta` | Apache-2.0 |
| `hack/` | Docker-based dev scripts (`gen-proto.sh`, `check-abi.sh`, `go-docker.sh`) | Apache-2.0 |
| `test/` | ABI check, BPF and e2e suites | Apache-2.0 |
| `docs/` | Architecture, ABI, upstream compatibility notes ([docs/compat/kata-4.2.md](docs/compat/kata-4.2.md)) | Apache-2.0 |

The repo has one Go module at the root, `github.com/dbcrit/vesta`. Linux-specific builds and tests run in Docker, e.g. `hack/go-docker.sh go test ./...`.

License texts are in `LICENSE` (Apache-2.0) and `LICENSES/`.
