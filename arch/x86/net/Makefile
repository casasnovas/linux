#
# Arch-specific network modules
#
obj-$(CONFIG_BPF_JIT) += bpf_jit.o bpf_jit_comp.o

arch/x86/net/bpf_jit_comp.o: arch/x86/net/bpf_jit_comp.c
	/home/quentin/repos/afl-kernel/afl-gcc $(c_flags) -c arch/x86/net/bpf_jit_comp.c -o arch/x86/net/bpf_jit_comp.o
