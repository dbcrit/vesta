# images/guest/

Build recipe for the vesta guest kernel and guest rootfs image. It uses Kata's own tooling at the pinned tag in [`versions.env`](versions.env) (Kata 4.2.0, commit-verified), and everything runs in Docker.

| Path | What |
|---|---|
| `versions.env` | Pinned Kata tag and commit, kernel version (6.18.35, cross-checked against Kata's `versions.yaml`), rootfs distro (Ubuntu 26.04 "resolute") |
| `lib.sh` | Shared helpers: fetches Kata at the pinned commit and validates the guest version |
| `kernel/vesta.conf` | Kernel config fragment. It is installed as Kata build type `vesta` (`configs/fragments/build-type/vesta/`) |
| `kernel/build.sh` | `config`: merge only, fails if any option is dropped. `build`: builds `vmlinux-vesta` |
| `rootfs/files/` | systemd units baked into the image |
| `rootfs/build.sh` | `overlay`: builds the vesta overlay tarball. `image`: builds `vesta-guest.img` with osbuilder |
| `rootfs/builder.Dockerfile` | Host side for osbuilder (make, git, yq, docker CLI) |
| `stage.sh` | Copies kernel and image, plus `SHA256SUMS` and `VERSION`, to `out/dist/<oci-arch>/` for the vesta-install image |

Outputs go to `out/` (git-ignored). Use the top-level make targets: `guest-kernel-config`, `guest-kernel`, `guest-rootfs`, `guest-stage`, `image-install`.

## Kernel

`build.sh` runs Kata's `tools/packaging/kernel/build-kernel.sh -a <arch> -v 6.18.35 -b vesta -x -m`. It runs inside Kata's kernel builder container (`tools/packaging/static-build/kernel/Dockerfile`, which includes pahole).

- **Why `-x -m`:** Kata 4.2 builds its stock x86_64/aarch64 kernel asset with `-x` (confidential fragments) and `-m` (measured rootfs) (`kata-deploy-binaries.sh`, `install_kernel`). Using the same flags makes the vesta kernel a superset of the kernel that stock `kata-qemu` pods boot. `VESTA_KERNEL_CONFIDENTIAL=no` drops them.
- **Patches directory:** `-b vesta` also makes `build-kernel.sh` apply `patches/6.18.x/vesta/`. That directory must exist, so the script creates it with `no_patches.txt`.
- **Fragment checks:** Kata's check only catches options whose final value differs. The script also checks every line of `vesta.conf` literally against the final `.config`, which catches a dropped `CONFIG_LSM` string.
- **Fragment contents:** `vesta.conf` does not repeat options that Kata's common fragments already set (`BPF_SYSCALL`, `CGROUP_BPF`, `SECURITY`, `SECURITY_NETWORK`, SELinux, Landlock). It adds:
  - `BPF_LSM`, JIT always-on, unprivileged BPF off;
  - BTF (`DEBUG_INFO_BTF`);
  - lockdown and Yama;
  - `CONFIG_LSM="landlock,lockdown,yama,selinux,bpf"`, so no `lsm=` boot parameter is needed;
  - tracing (`FUNCTION_TRACER`, which `DYNAMIC_FTRACE` depends on).
- **Output:** `vmlinux-vesta` is the uncompressed `vmlinux`, which is what `qemu-runtime-rs` boots (`KERNELTYPE_QEMU = uncompressed`). It goes through `objcopy --strip-debug`, which removes DWARF and keeps the allocated `.BTF` section. The script fails if `.BTF` is missing.

## Rootfs image

`rootfs/build.sh image` runs osbuilder's `make image` with these settings:

- `DISTRO=ubuntu`, `OS_VERSION=resolute`;
- `AGENT_INIT=no`, so the image boots systemd;
- `AGENT_POLICY=yes`, like the stock image;
- `MEASURED_ROOTFS=no`. vesta's runtime is not confidential; CoCo is Phase 5.

The vesta files are passed through osbuilder's own `GUEST_HOOKS_TARBALL` hook, which `rootfs.sh` unpacks after kata-agent is installed. No osbuilder fork is needed.

The overlay tarball is reproducible: sorted entries, fixed owner, and a fixed mtime from `SOURCE_DATE_EPOCH` or the last commit. It contains only files and symlinks, so it never resets the modes of existing rootfs directories. It contains:

| Path in guest | Mode | Source |
|---|---|---|
| `/usr/bin/vesta-guestd` | 0755 | `make guestd` (static musl). ELF machine checked against `ARCH` |
| `/etc/vesta/guestd.toml` | 0644 | `guest/vesta-guestd/guestd.example.toml` (`GUESTD_CONFIG`) with `guest_image_version` set to the build version, then checked with `vesta-guestd --check-config` |
| `/usr/lib/vesta/bpf/*.bpf.o` | 0644 | `make bpf` (`bpf/.output/<arch>/`). EM_BPF checked. Skipped with `VESTA_BPF_EMBEDDED=yes` |
| `/usr/lib/vesta/image-version` | 0644 | the guest version |
| `/usr/lib/systemd/system/vesta-guestd.service` | 0644 | `rootfs/files/` |
| `/etc/systemd/system/kata-agent.service.d/10-vesta.conf` | 0644 | `rootfs/files/` |
| `/etc/systemd/system/kata-containers.target.wants/vesta-guestd.service` | symlink | enables the unit |

osbuilder's `rootfs.sh` and `image_builder.sh` start their own containers, and the image builder needs a privileged container for the loop device. `build.sh` therefore runs osbuilder in `builder.Dockerfile` with the Docker socket mounted, and mounts the work tree at the same absolute path on both sides. This is a build-time requirement only.

### Boot ordering and fail-open

`vesta-guestd.service` is `Type=notify` with `Before=kata-agent.service` and `WantedBy=kata-containers.target`. The `10-vesta.conf` drop-in gives kata-agent `Wants=` and `After=vesta-guestd.service`.

- `Wants=` rather than `Requires=` means a failed guestd does not stop the agent (fail-open at boot). The host reports the sandbox as degraded.
- `TimeoutStartSec=10s` bounds how long a broken guestd can delay kata-agent.
- `Restart=always` with `StartLimitIntervalSec=0` restarts guestd without limit. Its pinned links keep enforcing while it is down.

### Unit hardening

guestd runs as root with this capability bounding set:

| Capability | Why |
|---|---|
| `CAP_BPF` | `bpf(2)`: maps and program load |
| `CAP_PERFMON` | tracing/LSM program types, tracepoint attach, `bpf_probe_read_kernel`/`d_path` |
| `CAP_NET_ADMIN` | attaching `cgroup/connect4`/`connect6` |
| `CAP_DAC_READ_SEARCH` | `stat` on exec-rule paths inside container rootfs trees that root does not own |

There is no `CAP_SYS_ADMIN`: program ids and tags are read from the fds guestd holds, and pins are reopened with `BPF_OBJ_GET`. The privileged smoke test checks this by running load, attach, pin, detach and restart adoption with only these four capabilities (`VESTA_SMOKE_UNIT_CAPS=1`).

Other hardening:

- **Filesystem:** `ProtectSystem=strict`, `ProtectKernelTunables`, `ProtectControlGroups` (read-only), `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`. `/sys/fs/bpf` is the only writable path.
- **Syscalls and sockets:** `RestrictAddressFamilies=AF_VSOCK AF_UNIX`. `SystemCallFilter` is `@system-service` plus `bpf` and `perf_event_open`, so mount syscalls are not allowed.
- **Why guestd must not mount bpffs:** systemd mounts bpffs at boot. A bpffs mounted inside the unit's private mount namespace would hide guestd's pins.
- **Misc:** `NoNewPrivileges`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `TasksMax=64`, `OOMScoreAdjust=-997` (same as kata-agent).

### Kernel command line

The kernel command line is not set in the image. vesta-install appends `lockdown=integrity` to the effective `kernel_params` of the vesta runtime config (`config.d/90-vesta.toml`), keeping Kata's own parameters:

- **No `lsm=`:** the fragment's `CONFIG_LSM` already lists `bpf`, and `lsm=` would override Kata's LSM order.
- **No cgroup parameter:** Kata 4.2 already passes `cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1`.

### Not supported

The initrd variant (`AGENT_INIT=yes`, kata-agent as PID 1) has no init to order guestd against. It is out of scope for the MVP (ARCHITECTURE Q7).
