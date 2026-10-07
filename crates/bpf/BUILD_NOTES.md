# Building the BPF object

`blackbox-bpf` is **not** a workspace member. It targets `bpfel-unknown-none`
and needs a different toolchain and a BPF linker, so it is built on its own:

```sh
./crates/bpf/build.sh release     # or `debug`
```

The script installs the result at `crates/bpf/target/.../blackbox-bpf` **and**
copies it to `<repo>/blackbox-bpf.o`, which is where the daemon's default
search looks (`[bpf].object_path` / `BLACKBOX_BPF_OBJECT` override it). The
copy is gitignored via the repo's `*.o` rule.

## Why the flags are what they are

1. **Nightly + `-Z build-std=core`.** `bpfel-unknown-none` has no prebuilt
   `core` on any rustup channel, not even nightly, so `core` must be built from
   source. That also requires the `rust-src` component.
2. **`debug = 2` is mandatory.** `bpf-linker` derives `.BTF` and `.BTF.ext`
   from the bitcode's debug info. With debug info disabled the object links
   fine but carries no BTF, and aya refuses to load it.
3. **`opt-level = 3`, never `"z"`.** `"z"` lowers to `-Oz`, which current LLVM
   rejects for BPF ("no longer supported").
4. **A prebuilt static `bpf-linker`.** Building it with `cargo install` needs
   `llvm-config` and a matching system LLVM. Use the static release binary
   (`bpf-linker-x86_64-unknown-linux-musl`, v0.11.1) instead.
5. **`.cargo/config.toml`** sets `linker = "bpf-linker"` and
   `-C link-arg=--btf` for the `bpfel-unknown-none` target.

## Reading the tracepoint context, and the licence

The program reads the `sched_switch` context with `TracePointContext::read_at`,
which lowers to `bpf_probe_read`. That helper is **GPL-only**: the kernel
refuses to load a program that calls it unless the program declares a
GPL-compatible licence. The object therefore declares `Dual MIT/GPL` — still
MIT for anyone who wants it, with the GPL option present only so the kernel
permits the helper. Userspace crates remain MIT.

Direct field loads would avoid the helper and keep the object plain MIT, but
Rust/LLVM does not fold the field offset into a load for a `PTR_TO_CTX` access:
it emits `r2 = r1; r2 += offset; ld*(r2)`, which the verifier rejects as
"dereference of modified ctx ptr". `read_at` is required, not just convenient.

The context is the whole trace event record (common header included), so its
offsets come from `/sys/kernel/tracing/events/sched/sched_switch/format`:

| field        | offset |
|--------------|--------|
| `prev_comm`  | 8      |
| `prev_pid`   | 24     |
| `prev_state` | 32     |
| `next_comm`  | 40     |
| `next_pid`   | 56     |

Reading the wrong offset is silent — no error, just wrong names and pids — so
these are checked against the format file in review, and the wire struct they
are packed into is asserted to stay 64 bytes.
