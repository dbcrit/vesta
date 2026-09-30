# test/

- `abi/`: compile check for `bpf/include/vesta_abi.h`, run by `hack/check-abi.sh`.
- `bpf/` (BPF implementer): verifier load tests against the vesta guest kernel.
- `e2e/`: k3s + kata-deploy on a KVM runner (ARCHITECTURE §5). Not runnable locally.
