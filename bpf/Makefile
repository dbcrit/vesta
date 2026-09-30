# SPDX-License-Identifier: Apache-2.0
#
# Builds the vesta BPF objects for every supported guest arch. Run inside
# the builder image (guest/Dockerfile.build), e.g. `guest/hack/in-builder.sh make -C bpf`.
# vesta-guestd's build.rs compiles the same source with the same flags for
# its libbpf-rs skeleton.

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LLVM_READELF ?= llvm-readelf
BPFTOOL ?= bpftool
OUTPUT ?= .output
ARCHES := x86_64 arm64

TARGET_ARCH_x86_64 := x86
TARGET_ARCH_arm64 := arm64

BPF_CFLAGS := -g -O2 -target bpf -mcpu=v3 -std=gnu11 -Wall -Wextra -Werror \
	-Wno-unused-parameter -fno-stack-protector -Iinclude

OBJS := $(foreach a,$(ARCHES),$(OUTPUT)/$(a)/vesta.bpf.o)

.PHONY: all clean check
all: $(OBJS)

$(OUTPUT)/%/vesta.bpf.o: vesta.bpf.c include/vesta_abi.h vmlinux/%/vmlinux.h
	@mkdir -p $(@D)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(TARGET_ARCH_$*) -Ivmlinux/$* -c $< -o $@
	$(LLVM_STRIP) -g $@

# Sanity-checks each object: BTF parses and every MVP program section exists.
check: all
	@for o in $(OBJS); do \
		$(BPFTOOL) btf dump file $$o >/dev/null || exit 1; \
		for s in tp_btf/sched_process_exec lsm/bprm_check_security cgroup/connect4 cgroup/connect6; do \
			$(LLVM_READELF) -S $$o | grep -qF " $$s " || { echo "$$o: missing section $$s"; exit 1; }; \
		done; \
		echo "$$o: OK"; \
	done

clean:
	rm -rf $(OUTPUT)
