#!/usr/bin/env bash
# Builds the kernel oracle's bzImage: Linux 6.19 for x86-64 with
# CONFIG_IA32_EMULATION, cross-compiled with LLVM in an Alpine container.
#
#     tests/fixtures/user/linux/oracle/build-kernel.sh LINUX_SRC OUT
#
# LINUX_SRC is a clean checkout of tag v6.19 (mounted read-only; the build
# is out of tree in a Docker volume); OUT receives the bzImage and the
# .config. The configuration is x86_64_defconfig, which enables
# CONFIG_IA32_EMULATION, with these changes:
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
set -euo pipefail

src="$(cd "$1" && pwd)"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
volume=rax-linux-x86-build

docker run --rm -v "$src:/src:ro" -v "$volume:/build" -v "$out:/out" -w /build alpine:latest sh -ec '
    apk add -q --no-cache clang lld llvm make flex bison bc perl elfutils-dev \
        linux-headers openssl-dev diffutils findutils bash coreutils gawk \
        binutils musl-dev gcc >/dev/null
    cd /src
    make -s O=/build ARCH=x86_64 LLVM=1 x86_64_defconfig
    scripts/config --file /build/.config \
        -e CHECKPOINT_RESTORE -d HZ_1000 -e HZ_250 \
        -d DEBUG_INFO -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT -e DEBUG_INFO_NONE \
        -d MODULES -e SECCOMP -e SECCOMP_FILTER -e FHANDLE -e USERFAULTFD \
        -e CROSS_MEMORY_ATTACH -e MEMBARRIER -e RSEQ -e KCMP -d NETFILTER
    make -s O=/build ARCH=x86_64 LLVM=1 olddefconfig
    grep -q "^CONFIG_IA32_EMULATION=y" /build/.config
    make -s O=/build ARCH=x86_64 LLVM=1 -j"$(nproc)" bzImage
    cp /build/arch/x86/boot/bzImage /build/.config /out/
'
echo "built $out/bzImage"
