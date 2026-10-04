# Build recipe for the BPF object, verified on this machine.
#
# The non-obvious parts, all of which were necessary to get a BTF-carrying BPF
# ELF without clang or root:
#
#   1. bpfel-unknown-none has NO prebuilt std on any rustup channel, not even
#      nightly. `-Z build-std=core` plus the rust-src component is the only way
#      to get a `core` for it. Hence nightly, and the -Z flag in build.rs.
#   2. debug = 2 is not optional. bpf-linker derives the .BTF and .BTF.ext
#      sections from the bitcode's debug info; build with debug info disabled
#      and the object links fine but carries no BTF, so aya cannot load it.
#   3. opt-level must not be "z". That lowers to -Oz, which current LLVM
#      rejects for BPF ("no longer supported"); use 3.
#   4. The linker is a prebuilt static bpf-linker, not a cargo install. Building
#      it from source needs llvm-config and matching system LLVM libraries.

[build]
# Produces target/bpf/bpfel-unknown-none/{debug,release}/blackbox-bpf.o
target-dir = "target"