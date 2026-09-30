# Kata 4.2.0 reference configuration

`configuration-qemu-runtime-rs.toml` is the unmodified file shipped in the Kata Containers 4.2.0 release tarball for amd64:

- Source: https://github.com/kata-containers/kata-containers/releases/download/4.2.0/kata-static-4.2.0-amd64.tar.zst
- Path in the tarball: `opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml`
- `opt/kata/VERSION` in the same tarball: `4.2.0`
- sha256: `915b45824b6e13c28944b7a0ee9f923398debbd136507303ec09c3d3af0eed3c`
- Fetched 2026-09-29.

It is Apache-2.0 licensed, like the rest of Kata Containers. The golden files next to it (`*.golden`) are what `vesta-install` generates from it; regenerate them with `go test ./host/internal/install -run Golden -update`.
