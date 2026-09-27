#!/usr/bin/env bash
# Builds a kernel oracle: Linux 6.19 for x86-64 with CONFIG_IA32_EMULATION
# (bzImage; the i386 cases), or for arm64 with CONFIG_COMPAT (Image; the ARM
# EABI cases), cross-compiled with LLVM in an Alpine container.
#
#     tests/fixtures/user/linux/oracle/build-kernel.sh LINUX_SRC OUT [x86_64|arm64]
#
# LINUX_SRC is a clean checkout of tag v6.19 (mounted read-only; the build
# is out of tree in a Docker volume per architecture); OUT receives the
# kernel image and the .config. The configuration is the architecture's
# defconfig (x86_64_defconfig enables CONFIG_IA32_EMULATION, arm64's
# defconfig CONFIG_COMPAT) with these changes:
#
#   CHECKPOINT_RESTORE on   as the Docker oracle's kernel has it, and as
#                           rax-user models it
#   HZ_250                  rax-user's CONFIG_HZ (compat_sys_times' ticks)
#   no debug information    build time only
#   no modules              everything the oracle needs is built in
#   SECCOMP_FILTER, FHANDLE, USERFAULTFD, CROSS_MEMORY_ATTACH, MEMBARRIER,
#   RSEQ, KCMP on           calls the fixtures exercise
#   NETFILTER off           unused; on a case-insensitive file system (a
#                           macOS checkout) its xt_* sources collide
#
# and, for arm64, the compat task rax-user models (a distribution kernel's):
#
#   KUSER_HELPERS on        the [vectors] page
#   COMPAT_VDSO off         no compat vDSO (no AT_SYSINFO_EHDR)
#   ARMV8_DEPRECATED, CP15_BARRIER_EMULATION, SWP_EMULATION on
#                           A32 CP15 barriers emulated; SWP built but off
#                           by default (abi.swp), so SIGILL
#   SETEND_EMULATION off    SETEND is SIGILL, as without mixed-endian EL0
#   ARM_ARCH_TIMER_EVTSTREAM off
#                           no event stream (no EVTSTRM hardware capability)
#   DRM off                 unused; its MSM driver's generated headers would
#                           otherwise dominate the build
set -euo pipefail

src="$(cd "$1" && pwd)"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
arch="${3:-x86_64}"
case "$arch" in
x86_64)
    defconfig=x86_64_defconfig image=arch/x86/boot/bzImage
    check=CONFIG_IA32_EMULATION extra=""
    ;;
arm64)
    defconfig=defconfig image=arch/arm64/boot/Image check=CONFIG_COMPAT
    extra="-e KUSER_HELPERS -d COMPAT_VDSO -e ARMV8_DEPRECATED \
        -e CP15_BARRIER_EMULATION -e SWP_EMULATION -d SETEND_EMULATION \
        -d ARM_ARCH_TIMER_EVTSTREAM -d DRM"
    ;;
*)
    echo "error: unknown architecture $arch" >&2
    exit 1
    ;;
esac
volume="rax-linux-$arch-build"
[[ "$arch" == x86_64 ]] && volume=rax-linux-x86-build

docker run --rm -v "$src:/src:ro" -v "$volume:/build" -v "$out:/out" -w /build \
    -e ARCH="$arch" -e DEFCONFIG="$defconfig" -e IMAGE="$image" -e CHECK="$check" \
    -e EXTRA="$extra" alpine:latest sh -ec '
    apk add -q --no-cache clang lld llvm make flex bison bc perl elfutils-dev \
        linux-headers openssl-dev diffutils findutils bash coreutils gawk \
        binutils musl-dev gcc python3 >/dev/null
    cd /src
    make -s O=/build ARCH=$ARCH LLVM=1 $DEFCONFIG
    scripts/config --file /build/.config \
        -e CHECKPOINT_RESTORE -d HZ_1000 -e HZ_250 \
        -d DEBUG_INFO -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT -e DEBUG_INFO_NONE \
        -d MODULES -e SECCOMP -e SECCOMP_FILTER -e FHANDLE -e USERFAULTFD \
        -e CROSS_MEMORY_ATTACH -e MEMBARRIER -e RSEQ -e KCMP -d NETFILTER $EXTRA
    make -s O=/build ARCH=$ARCH LLVM=1 olddefconfig
    grep -q "^$CHECK=y" /build/.config
    make -s O=/build ARCH=$ARCH LLVM=1 -j"$(nproc)" "$(basename $IMAGE)"
    cp /build/$IMAGE /build/.config /out/
'
echo "built $out/$(basename "$image")"
