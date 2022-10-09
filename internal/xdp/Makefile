CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror $(CFLAGS)

# From: https://github.com/cilium/ebpf/blob/master/Makefile
CONTAINER_ENGINE ?= docker
CONTAINER_IMAGE ?= quay.io/cilium/ebpf-builder
CONTAINER_VERSION ?= 1648566014

SOURCE_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: generate
# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate -tags xdp ./

.PHONY: clean
clean:
	-$(RM) *.o
	-$(RM) bpf_bpfeb.go bpf_bpfel.go

.PHONY: build
build:
	${CONTAINER_ENGINE} run --rm \
		-v "${SOURCE_DIR}":/ebpf -w /ebpf --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/ebpf=." \
		--env HOME="/tmp" \
		"${CONTAINER_IMAGE}:${CONTAINER_VERSION}" \
		make build-in-container

# Due to missing <asm/types.h> in the container, the workaround is to install gcc-multilib. The down side is that we
# won't have an identical build environment each time due to the remote package dependency.
.PHONY: build-in-container
build-in-container:
	apt update
	apt install -y gcc-multilib
	make generate


.PHONY: container-shell
container-shell:
	${CONTAINER_ENGINE} run --rm -ti \
		-v "${SOURCE_DIR}":/ebpf -w /ebpf \
		"${CONTAINER_IMAGE}:${CONTAINER_VERSION}"
