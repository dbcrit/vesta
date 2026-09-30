// SPDX-License-Identifier: Apache-2.0
//! Builds the BPF object and its libbpf-rs skeleton from `bpf/`, and the
//! prost types from `api/proto`. Needs clang and protoc (guest/Dockerfile.build).

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

/// libbpf-cargo 0.27.2 names the local for each map after the map. The ABI
/// map `config` then shadows the generated `config: &ObjectSkeletonConfig`
/// parameter used for `.rodata` mmap lookups. Rename the local; fail loudly
/// if the generated code changes shape (e.g. after a libbpf-cargo upgrade).
fn patch_skeleton(path: &std::path::Path) {
    let src = std::fs::read_to_string(path).expect("reading skeleton");
    let replacements = [
        ("let mut config = None;", "let mut config_map = None;"),
        (
            "\"config\" => config = Some(map),",
            "\"config\" => config_map = Some(map),",
        ),
        ("config: config.expect(", "config: config_map.expect("),
    ];
    let mut out = src;
    for (from, to) in replacements {
        let n = out.matches(from).count();
        assert!(n > 0, "skeleton patch: `{from}` not found; re-check the libbpf-cargo `config` shadowing workaround");
        out = out.replace(from, to);
    }
    std::fs::write(path, out).expect("writing patched skeleton");
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo = manifest.join("../..");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    let bpf = repo.join("bpf");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let (vmlinux_arch, target_arch) = match arch.as_str() {
        "x86_64" => ("x86_64", "x86"),
        "aarch64" => ("arm64", "arm64"),
        other => panic!("vesta-guestd: unsupported target arch {other}"),
    };
    // Same flags as bpf/Makefile.
    SkeletonBuilder::new()
        .source(bpf.join("vesta.bpf.c"))
        .obj(out.join("vesta.bpf.o"))
        .clang_args([
            "-mcpu=v3".to_string(),
            "-std=gnu11".to_string(),
            "-Wall".to_string(),
            "-Wextra".to_string(),
            "-Werror".to_string(),
            "-Wno-unused-parameter".to_string(),
            format!("-D__TARGET_ARCH_{target_arch}"),
            format!("-I{}", bpf.join("include").display()),
            format!("-I{}", bpf.join("vmlinux").join(vmlinux_arch).display()),
        ])
        .build_and_generate(out.join("vesta.skel.rs"))
        .expect("building the BPF object and skeleton");
    patch_skeleton(&out.join("vesta.skel.rs"));

    let proto_root = repo.join("api/proto");
    prost_build::Config::new()
        .compile_protos(
            &[
                proto_root.join("vesta/channel/v1/control.proto"),
                proto_root.join("vesta/channel/v1/events.proto"),
                proto_root.join("vesta/event/v1/event.proto"),
            ],
            &[&proto_root],
        )
        .expect("compiling protos");

    for p in [
        bpf.join("vesta.bpf.c"),
        bpf.join("include/vesta_abi.h"),
        bpf.join("vmlinux").join(vmlinux_arch).join("vmlinux.h"),
        proto_root,
    ] {
        println!("cargo:rerun-if-changed={}", p.display());
    }
}
