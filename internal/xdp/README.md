# XDP
This package contains XDP/eBPF code to accelerate ADK.

It is container in its own Go module because of the way the bpf ELF file is built.

This repo already contains the built ELF artifacts (`bpf_bpfeb.o`, `bpf_bpfel.o`) and associated Go files 
(`bpf_bpfeb.go`, `bpf_bpfel.go`). 
In order to build them from scratch you can use the provided container image:

```sh
# Docker is required
$ make build
```
