#!/bin/bash
# Static musl builds of x2rp and x2rp-connector, written to dist/.
#   scripts/build.sh [server|connector|all] [--arch x86_64|aarch64] [--debug]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHAT=all ARCH="$(uname -m)" PROFILE=release

while [ $# -gt 0 ]; do
    case "$1" in
        server|connector|all) WHAT="$1" ;;
        --arch) ARCH="${2:?--arch needs x86_64 or aarch64}"; shift ;;
        --debug) PROFILE=debug ;;
        -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

TARGET="$ARCH-unknown-linux-musl"
TOOLS="$ROOT/target/toolchains/$ARCH-linux-musl-cross"
if [ ! -d "$TOOLS" ]; then
    echo "fetching $ARCH musl cross toolchain"
    mkdir -p "$(dirname "$TOOLS")"
    curl -fsSL "https://musl.cc/$ARCH-linux-musl-cross.tgz" | tar -xz -C "$(dirname "$TOOLS")"
fi
export PATH="$TOOLS/bin:$PATH"
# cargo wants the triple upper-cased for the linker var; cc-rs wants it as-is.
TRIPLE="${TARGET//-/_}"
export "CARGO_TARGET_${TRIPLE^^}_LINKER=$ARCH-linux-musl-gcc"
export "CC_$TRIPLE=$ARCH-linux-musl-gcc" "CXX_$TRIPLE=$ARCH-linux-musl-g++"
rustup target add "$TARGET" >/dev/null 2>&1 || true

case "$WHAT" in
    server) BINS=(x2rp) ;;
    connector) BINS=(x2rp-connector) ;;
    all) BINS=(x2rp x2rp-connector) ;;
esac

FLAGS=(--target "$TARGET" --manifest-path "$ROOT/Cargo.toml")
[ "$PROFILE" = release ] && FLAGS+=(--release)
for bin in "${BINS[@]}"; do
    FLAGS+=(-p "$bin")
done
cargo build "${FLAGS[@]}"

mkdir -p "$ROOT/dist"
for bin in "${BINS[@]}"; do
    install -m 755 "$ROOT/target/$TARGET/$PROFILE/$bin" "$ROOT/dist/$bin-$ARCH"
    ls -lh "$ROOT/dist/$bin-$ARCH"
done
