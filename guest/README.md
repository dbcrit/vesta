# guest/

Cargo workspace for the in-guest daemon. The crate is `guest/vesta-guestd` (Rust 2021, MSRV 1.85). It uses libbpf-rs 0.27.2 with a libbpf-cargo skeleton, prost 0.14, tokio and tokio-vsock 0.7.2. The workspace is Apache-2.0.

**Owner:** the guest implementer. All building and testing happens in Docker, using `guest/Dockerfile.build`.

## Build and test

```sh
docker build -f guest/Dockerfile.build -t vesta-guest-build:local guest
guest/hack/in-builder.sh sh -c 'cd guest && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'
guest/hack/in-builder.sh sh -c 'cd guest && cargo build --release'   # target/release/vesta-guestd (static musl)
# BPF smoke test on the Docker VM kernel (private bpffs, scratch cgroup):
VESTA_PRIVILEGED=1 guest/hack/in-builder.sh sh -c 'cd guest && cargo test -- --ignored --test-threads=1 smoke'
# Same, with the test thread reduced to the vesta-guestd.service capabilities:
VESTA_PRIVILEGED=1 guest/hack/in-builder.sh sh -c 'cd guest && VESTA_SMOKE_UNIT_CAPS=1 cargo test -- --ignored --test-threads=1 smoke'
```

The binary is fully static (musl, `x86_64-unknown-linux-musl`) and has no dependency on the guest rootfs libc. This matches how Kata builds kata-agent for x86_64. libbpf v1.7.0 is vendored by libbpf-sys, and libelf/zlib/zstd are linked statically from Alpine. An arm64 guestd needs a musl cross toolchain, which is not in the builder yet; the arm64 BPF object is already built by `make -C bpf`.

## Runtime contract

- **vsock.** guestd listens on CID any, CTRL port 22085 and EVT port 22086. It refuses peers whose CID is not `allowed_peer_cid` (2, the host), so guest processes cannot use vsock loopback. A new connection replaces the previous one on the same port.
- **BPF object.** The BPF object is embedded through the skeleton, built from `bpf/vesta.bpf.c` at the same commit. Maps are pinned under `/sys/fs/bpf/vesta/maps/` and links under `/sys/fs/bpf/vesta/links/`. After a guestd restart, compatible pinned maps are reused, and the new links are attached before the old pins are replaced. On SIGTERM guestd exits and leaves the links attached.
- **Config.** `/etc/vesta/guestd.toml` (see `vesta-guestd/guestd.example.toml`). Unknown keys are rejected and every value is range-checked.
- **systemd.** guestd sends `READY=1` after load and attach, or after a load failure has been recorded. In that case it keeps serving Hello and GetStatus with FAILED program states, and nacks policy writes.
- **ABI mirror.** `src/abi.rs` mirrors `bpf/include/vesta_abi.h` with `#[repr(C)]` and const asserts. A unit test also parses the header's `_Static_assert`s and `#define`s and compares them.

## Module map

| Module | Role |
|---|---|
| `abi` | ABI mirror; safe (no transmute) encoding and decoding of map entries and ring buffer records |
| `codec` | u32 BE length framing, 1..=1 MiB, deadline once a frame has started |
| `policy` | ApplyPolicy validation (proto limits) and net key compilation; policy hash |
| `resolve` | Exec rule path → (s_dev, ino) inside `/run/kata-containers/<cid>/rootfs` via `openat2(RESOLVE_IN_ROOT)` |
| `cgroup` | OCI cgroupsPath → guest cgroup dir (kata-agent rules), `openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_XDEV)`, cgroup id = inode |
| `state` | Engine: applied policy and bindings → desired map state, diffed against installed state |
| `bpf` | Skeleton load, attach, pin, restart adoption, kill-switch detach, drop counters, privileged smoke test |
| `events` | Record → `vesta.event.v1.Event`; bounded replay buffer that evicts AUDITED/ALLOWED before DENIED |
| `ctrl`, `evt` | CTRL and EVT sessions |
| `server` | Startup sequence, listeners, ring buffer consumer (epoll through tokio `AsyncFd`), cgroup GC, signals |

guestd is single-threaded: tokio `current_thread` plus a `LocalSet`. The skeleton is not `Send`, the guest is memory-constrained, and nothing in guestd needs parallelism. tokio-vsock is the crate kata-agent itself uses.
