# bpf/include and vmlinux.h

- `vesta_abi.h`: the kernel/userspace ABI (owned by the contract, see [docs/abi.md](../../docs/abi.md)). Do not edit it without bumping `VESTA_ABI_VERSION`.
- `../vmlinux/<arch>/vmlinux.h`: CO-RE type definitions, one per guest architecture (`x86_64`, `arm64`).

## vmlinux.h provenance

The headers are generated from the BTF of a signed distribution kernel on the same LTS line as the Kata 4.2 guest kernel (6.18.35). The stock Kata kernel is not used because it has no `CONFIG_DEBUG_INFO_BTF` outside debug builds (docs/compat/kata-4.2.md §4). CO-RE relocates every field access against the running guest kernel's own `/sys/kernel/btf/vmlinux`, so the header only has to contain the types and fields the programs use. They are stable from 6.1, the minimum guest kernel, to 7.0.

| Arch | Source package (Debian trixie-backports) | Version | .deb SHA-256 |
|---|---|---|---|
| x86_64 | `linux-image-6.18.9+deb13-cloud-amd64-unsigned` | `6.18.9-1~bpo13+1` | `b8d9ce5053476b8aa833b5b59e411aaa9b8be0b30e05a2833013e20a8c71e064` |
| arm64 | `linux-image-6.18.9+deb13-cloud-arm64-unsigned` | `6.18.9-1~bpo13+1` | `19e0ce6b80120ffefccf3db5d0339b8c21a6af8565e59dba49ebe2efb123a98d` |

The headers were generated on 2026-09-29 with bpftool v7.5.0 (Debian `bpftool 7.5.0+6.12.111-1`). apt verifies each package against the signed Debian Release file.

Regenerate both headers with:

```sh
bpf/scripts/gen-vmlinux.sh
# or pin another kernel:
KERNEL_ABI=6.18.9+deb13 KERNEL_PKG_VERSION=6.18.9-1~bpo13+1 bpf/scripts/gen-vmlinux.sh
```

The script runs in `debian:trixie-slim`. For each arch it does the following:

1. Downloads the kernel package.
2. Decompresses `vmlinuz` with the kernel's `scripts/extract-vmlinux` (v6.18, SHA-256 pinned).
3. Carves the `.BTF` blob out of the image with `bpf/scripts/btf-carve.py`. The arm64 `Image` is a raw binary with no ELF sections, so the blob is found by its BTF header.
4. Dumps the blob with `bpftool btf dump file <blob> format c`.

When the vesta guest kernel (built from `images/guest/kernel/vesta.conf`, which enables BTF) is available, the headers can instead come straight from it (`bpftool btf dump file vmlinux format c`). Record the change in this file when that happens.

6.18's BTF contains `typedef struct config_s config`, which clashes with the ABI map name `config`. `vesta.bpf.c` renames that typedef while including `vmlinux.h`.
