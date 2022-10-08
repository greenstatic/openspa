CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror $(CFLAGS)

.PHONY: generate
# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./

.PHONY: clean-generate
clean-generate:
	-$(RM) *.o
	-$(RM) bpf_bpfeb.go bpf_bpfel.go

