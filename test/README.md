# test/

- `abi/`: compile check for `bpf/include/vesta_abi.h`, run by `hack/check-abi.sh`.
- `bpf/` (BPF implementer): verifier load tests against the vesta guest kernel.
- `e2e/`: single-node k3s + Cilium + Kata (kata-deploy) with vesta built from the tree, and the end-to-end tests ([e2e/README.md](e2e/README.md)). Needs a Linux host with `/dev/kvm` (CI: `.github/workflows/e2e.yml`); not runnable on macOS.
