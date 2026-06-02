#!/usr/bin/env bash
# Build the RISC-V differential-test oracle as a static RV64GC ELF for qemu-user.
# No-op friendly: prints the path on success, exits non-zero if toolchain absent.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${RISCV64_CC:-riscv64-linux-gnu-gcc}"
out="$here/oracle"
if ! command -v "$cc" >/dev/null 2>&1; then
    echo "cross compiler '$cc' not found" >&2
    exit 1
fi
"$cc" -static -O2 -march=rv64gc -mabi=lp64d -Wall -Wextra -o "$out" "$here/oracle.c"
echo "$out"
