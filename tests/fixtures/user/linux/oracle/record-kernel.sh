#!/usr/bin/env bash
# Records fixture results on a real Linux 6.19 kernel booted under QEMU
# (TCG): the compatibility cases, which no Docker host here can run on a
# 64-bit kernel, and on request (`compare`) the native 64-bit cases for
# comparison with the Docker recordings.
#
#     tests/fixtures/user/linux/oracle/record-kernel.sh KERNEL [x86_64|arm64] [compare]
#
#   x86_64 (default)  KERNEL is a bzImage; qemu-system-x86_64 runs the i386
#                     cases (programs built into bin/i386), and with
#                     `compare` the x86_64 ones
#   arm64             KERNEL is an Image; qemu-system-aarch64 runs the ARM
#                     EABI cases, as A32 (bin/arm) and as Thumb-2 code
#                     (bin/thumb), and with `compare` the aarch64 ones
#
# KERNEL is Linux 6.19 built by build-kernel.sh for the same architecture.
# The initramfs holds vminit (PID 1), the case list, the binaries, and
# input/; vminit runs each case and writes its output to the serial
# console, which this script decodes into expected/<arch>/<case>.{stdout,
# status} (i386, arm, thumb), or into oracle-<arch>/ (the comparison run,
# not committed). expected/ORACLE-<arch> records the kernel, QEMU, and
# recording time.
#
# Requirements: Zig 0.16.0 (to build vminit), qemu-system-x86_64 or
# qemu-system-aarch64, cpio.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kernel="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
machine="${2:-x86_64}"
compare="${3:-}"
cd "$here"

case "$machine" in
x86_64) compat=(i386) native=x86_64 ;;
arm64) compat=(arm thumb) native=aarch64 ;;
*)
    echo "error: unknown machine $machine" >&2
    exit 1
    ;;
esac
[[ -z "$compare" || "$compare" == compare ]] || {
    echo "error: the third argument is \`compare\` or nothing" >&2
    exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"
mkdir -p "$root/w"
zig cc -target "$native-linux-musl" -static -Os -s -o "$root/init" oracle/vminit.c
cp -R input "$root/w/input"
arches=("${compat[@]}")
[[ -n "$compare" ]] && arches+=("$native")
for arch in "${arches[@]}"; do
    cp -R "bin/$arch" "$root/w/$arch"
done
# The cases each architecture has a binary for (cases-i386.txt and
# cases-arm.txt: the i386-only and ARM-only programs').
for arch in "${arches[@]}"; do
    cat cases.txt cases-i386.txt cases-arm.txt | grep -v '^#' | while read -r name prog input args; do
        [[ -z "$name" ]] && continue
        [[ -f "bin/$arch/$prog" ]] || continue
        echo "$arch $name $prog $input $args"
    done
done > "$root/cases.txt"
(cd "$root" && find . | LC_ALL=C sort | cpio -o -H newc --quiet) > "$work/initramfs.cpio"

console="$work/console.txt"
case "$machine" in
x86_64)
    # nopku: rax-user's tasks run without CR4.PKE (CPUID reports PKU but
    # not OSPKE, and XCR0 has no PKRU state), as under a kernel that leaves
    # protection keys off; with them on, the kernel makes PROT_EXEC-only
    # mappings execute-only (arch/x86/mm/pkeys.c), which mlock cannot
    # fault in.
    qemu=qemu-system-x86_64
    machine_desc="q35, -cpu max, 2 CPUs, 1 GiB; kernel command line: nopku"
    "$qemu" -machine q35 -cpu max -smp 2 -m 1024 \
        -kernel "$kernel" -initrd "$work/initramfs.cpio" \
        -append "console=ttyS0 quiet loglevel=0 panic=-1 rdinit=/init nopku" \
        -display none -monitor none -serial "file:$console" -no-reboot
    ;;
arm64)
    # A Cortex-A72 runs AArch32 at EL0 (the compat tasks); no fixture reads
    # the hardware capabilities its crypto extensions add to AT_HWCAP2.
    qemu=qemu-system-aarch64
    machine_desc="virt, -cpu cortex-a72, 2 CPUs, 1 GiB"
    "$qemu" -machine virt -cpu cortex-a72 -smp 2 -m 1024 \
        -kernel "$kernel" -initrd "$work/initramfs.cpio" \
        -append "console=ttyAMA0 quiet loglevel=0 panic=-1 rdinit=/init" \
        -display none -monitor none -serial "file:$console" -no-reboot
    ;;
esac

grep -q '^@@done' <(tr -d '\r' < "$console") || {
    echo "error: the oracle did not finish; console log follows" >&2
    tail -40 "$console" >&2
    exit 1
}

# Decode: "@@case ARCH NAME", hex lines, "@@status N".
tr -d '\r' < "$console" | awk -v here="$here" -v compat=" ${compat[*]} " '
    /^@@case / { arch = $2; name = $3; dir = index(compat, " " arch " ") ? "expected/" arch : "oracle-" arch;
                 system("mkdir -p " here "/" dir);
                 out = here "/" dir "/" name ".stdout"; printf "" > out; hex = ""; next }
    /^@@status / { close(out); cmd = "xxd -r -p > " out; printf "%s", hex | cmd; close(cmd);
                   print $2 > (here "/" dir "/" name ".status"); close(here "/" dir "/" name ".status");
                   print arch " " name " -> " $2; next }
    /^@@done/ { next }
    /^[0-9a-f]+$/ { hex = hex $0; next }
'

case "$machine" in
x86_64) config="x86_64_defconfig with CONFIG_IA32_EMULATION" ;;
arm64) config="arm64 defconfig with CONFIG_COMPAT and the compat-task options" ;;
esac
for arch in "${compat[@]}"; do
    {
        echo "$arch oracle: Linux on $qemu (TCG), not Docker"
        # bzImage's setup header holds the version; an Image, linux_banner
        # (after init/version.c's placeholder, which has no build number).
        echo "kernel: $(strings "$kernel" | sed -nE 's/^(Linux version )?([0-9]+\.[0-9]+\.[0-9]+ \(.*#[0-9]+ .*)/\2/p' | head -1)"
        echo "build: oracle/build-kernel.sh from tag v6.19 ($config)"
        echo "kernel-sha256: $(shasum -a 256 "$kernel" | cut -d' ' -f1)"
        echo "qemu: $("$qemu" --version | head -1)"
        echo "machine: $machine_desc"
        echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "expected/ORACLE-$arch"
done
