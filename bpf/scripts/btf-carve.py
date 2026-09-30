#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Carve the kernel's .BTF blob out of an uncompressed kernel image.

Works on an ELF vmlinux and on a raw arm64 `Image` (which has no section
headers). Looks for the little-endian BTF header (magic 0xeB9F, version 1,
hdr_len 24), validates the section layout and writes the largest candidate
as raw BTF, which `bpftool btf dump file <out> format c` accepts.
"""
import struct
import sys

MAGIC = b"\x9f\xeb\x01\x00\x18\x00\x00\x00"  # magic, version 1, flags 0, hdr_len 24
HDR = struct.Struct("<HBBIIIII")
MIN_SIZE = 1 << 20  # vmlinux BTF is several MiB; ignore small module-like blobs


def candidates(data: bytes):
    pos = data.find(MAGIC)
    while pos != -1:
        if pos + HDR.size <= len(data):
            _, _, _, hdr_len, type_off, type_len, str_off, str_len = HDR.unpack_from(data, pos)
            end = pos + hdr_len + max(type_off + type_len, str_off + str_len)
            if type_off == 0 and str_off == type_len and str_len > 0 and end <= len(data):
                yield pos, end
        pos = data.find(MAGIC, pos + 1)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: btf-carve.py <uncompressed-kernel-image> <out.btf>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    best = max(candidates(data), key=lambda c: c[1] - c[0], default=None)
    if best is None or best[1] - best[0] < MIN_SIZE:
        print("no vmlinux BTF blob found", file=sys.stderr)
        return 1
    with open(sys.argv[2], "wb") as f:
        f.write(data[best[0]:best[1]])
    print(f"BTF at offset {best[0]:#x}, {best[1] - best[0]} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
