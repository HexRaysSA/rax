#!/usr/bin/env bash
# Records fixture results on a real Linux 6.19 x86-64 kernel booted under
# qemu-system-x86_64: the i386 cases (programs built into bin/i386), which
# no Docker host here can run on an x86-64 kernel, and on request (the
# second argument `x86_64`) the x86-64 cases for comparison with the
# Docker recordings.
#
#     tests/fixtures/user/linux/oracle/record-kernel.sh BZIMAGE [x86_64]
#
# BZIMAGE is Linux 6.19 built as kernel-config.txt describes (x86_64_defconfig
# with CONFIG_IA32_EMULATION and the listed changes). The initramfs holds
# vminit (PID 1), the case list, the binaries, and input/; vminit runs each
# case and writes its output to the serial console, which this script
# decodes into expected/<arch>/<case>.{stdout,status} (i386), or into
# oracle-x86_64/ (the comparison run, not committed). expected/ORACLE-i386
# records the kernel, QEMU, and recording time.
#
# Requirements: Zig 0.16.0 (to build vminit), qemu-system-x86_64, cpio.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kernel="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
compare="${2:-}"
cd "$here"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"
mkdir -p "$root/w"
zig cc -target x86_64-linux-musl -static -Os -s -o "$root/init" oracle/vminit.c
cp -R input "$root/w/input"
arches=(i386)
[[ "$compare" == x86_64 ]] && arches+=(x86_64)
for arch in "${arches[@]}"; do
    cp -R "bin/$arch" "$root/w/$arch"
done
# The cases each architecture has a binary for (cases-i386.txt: the
# i386-only programs').
for arch in "${arches[@]}"; do
    cat cases.txt cases-i386.txt | grep -v '^#' | while read -r name prog input args; do
        [[ -z "$name" ]] && continue
        [[ -f "bin/$arch/$prog" ]] || continue
        echo "$arch $name $prog $input $args"
    done
done > "$root/cases.txt"
(cd "$root" && find . | LC_ALL=C sort | cpio -o -H newc --quiet) > "$work/initramfs.cpio"

console="$work/console.txt"
qemu-system-x86_64 -machine q35 -cpu max -smp 2 -m 1024 \
    -kernel "$kernel" -initrd "$work/initramfs.cpio" \
    -append "console=ttyS0 quiet loglevel=0 panic=-1 rdinit=/init" \
    -display none -monitor none -serial "file:$console" -no-reboot

grep -q '^@@done' <(tr -d '\r' < "$console") || {
    echo "error: the oracle did not finish; console log follows" >&2
    tail -40 "$console" >&2
    exit 1
}

# Decode: "@@case ARCH NAME", hex lines, "@@status N".
tr -d '\r' < "$console" | awk -v here="$here" '
    /^@@case / { arch = $2; name = $3; dir = (arch == "i386") ? "expected/i386" : "oracle-x86_64";
                 system("mkdir -p " here "/" dir);
                 out = here "/" dir "/" name ".stdout"; printf "" > out; hex = ""; next }
    /^@@status / { close(out); cmd = "xxd -r -p > " out; printf "%s", hex | cmd; close(cmd);
                   print $2 > (here "/" dir "/" name ".status"); close(here "/" dir "/" name ".status");
                   print arch " " name " -> " $2; next }
    /^@@done/ { next }
    /^[0-9a-f]+$/ { hex = hex $0; next }
'

{
    echo "i386 oracle: Linux on qemu-system-x86_64 (TCG), not Docker"
    echo "kernel: $(strings "$kernel" | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+.*#')"
    echo "build: oracle/build-kernel.sh from tag v6.19 (x86_64_defconfig with CONFIG_IA32_EMULATION)"
    echo "kernel-sha256: $(shasum -a 256 "$kernel" | cut -d' ' -f1)"
    echo "qemu: $(qemu-system-x86_64 --version | head -1)"
    echo "machine: q35, -cpu max, 2 CPUs, 1 GiB"
    echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > expected/ORACLE-i386
