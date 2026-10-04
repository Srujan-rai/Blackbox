#!/usr/bin/env bash
# Build the BPF object.
#
# Kept as a script rather than an xtask because it has to switch toolchains and
# targets, and the flags that make it work are all non-obvious. See BUILD_NOTES.md.
#
#   bpfel = little-endian BPF (x86_64, arm64)
#   bpfeb = big-endian BPF (ppc64le, s390x) -- needs a separate target + build
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
profile="${1:-release}"

if ! command -v bpf-linker >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: bpf-linker not found on PATH.

Install the prebuilt static binary; building it from source additionally needs
llvm-config and matching system LLVM, which is the hard way:

  curl -LO https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst
  tar --zstd -xf bpf-linker-x86_64-unknown-linux-musl.tar.zst
  install -m755 bpf-linker ~/.cargo/bin/
EOF
  exit 1
fi

# -Z build-std=core is mandatory: bpfel-unknown-none ships no prebuilt core on
# any rustup channel, stable or nightly.
cd "$here"
cargo build \
  --profile "$profile" \
  --target bpfel-unknown-none \
  -Z build-std=core

obj="target/bpfel-unknown-none/$profile/blackbox-bpf"
if [[ ! -f "$obj" ]]; then
  echo "error: expected $obj" >&2
  exit 1
fi

# Fail loudly rather than shipping an object aya cannot load: without .BTF the
# program still links, but aya rejects it at load time with an opaque error.
if ! readelf -S "$obj" | grep -q '\.BTF'; then
  echo "error: $obj has no .BTF section." >&2
  echo "       debug info must be enabled; check [profile.$profile] in Cargo.toml." >&2
  exit 1
fi

echo "built $obj ($(stat -c%s "$obj") bytes, .BTF present)"