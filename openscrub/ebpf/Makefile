# OpenScrub eBPF build.
#
# Compiles openscrub.bpf.c into openscrub.bpf.o (BPF bytecode object)
# that the Rust userspace loader embeds at build time.
#
# Requirements: clang >= 14, libbpf-dev, kernel headers.

CLANG     ?= clang
ARCH      ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_INC ?= /usr/include
BPF_CFLAGS = -O2 -g -Wall -Werror \
             -target bpf \
             -D__TARGET_ARCH_$(ARCH) \
             -I$(KERNEL_INC)

OBJ = openscrub.bpf.o

.PHONY: all clean

all: $(OBJ)

$(OBJ): openscrub.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
