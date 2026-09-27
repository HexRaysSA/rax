#!/usr/bin/env bash
# Compile-only cross-checks. Temporary COFF objects are removed at exit.
set -euo pipefail

probe_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
x86_cc="${CC_X86:-i686-w64-mingw32-gcc}"
x64_cc="${CC_X64:-x86_64-w64-mingw32-gcc}"
zig_bin="${ZIG_BIN:-zig}"
task_dir="$(mktemp -d "${TMPDIR:-/tmp}/rax-windows-layout.XXXXXX")"
trap 'rm -f "$task_dir/x86.obj" "$task_dir/x64.obj" "$task_dir/arm64.obj" "$task_dir/kuser-x86.obj" "$task_dir/kuser-x64.obj" "$task_dir/dispatcher-x64.obj" "$task_dir/dispatcher-arm64.obj"; rmdir "$task_dir"' EXIT

probe() {
    local guest="$1"
    shift
    printf '%s compiler: ' "$guest"
    "$@" --version | sed -n '1p'
    "$@" -std=c11 -Werror -c "$probe_dir/public.c" -o "$task_dir/$guest.obj"
    printf '%s header macros:\n' "$guest"
    "$@" -std=c11 -dM -E "$probe_dir/public.c" |
        awk '/^#define __MINGW64_VERSION_(MAJOR|MINOR|BUGFIX|STATE) /'
    local assertions
    assertions="$("$@" -std=c11 -E -P "$probe_dir/public.c" | awk '/rax-layout:/ { n++ } END { print n+0 }')"
    printf '%s public layout: PASS (%s assertions)\n' "$guest" "$assertions"
}

probe x86 "$x86_cc"
probe x64 "$x64_cc"
printf 'Zig driver: '
"$zig_bin" version
probe arm64 "$zig_bin" cc -target aarch64-windows-gnu

"$x64_cc" -std=c11 -Werror -c "$probe_dir/dispatcher.c" -o "$task_dir/dispatcher-x64.obj"
printf 'x64 public DISPATCHER_CONTEXT: PASS (3 assertions)\n'
"$zig_bin" cc -target aarch64-windows-gnu -std=c11 -Werror -c "$probe_dir/dispatcher.c" -o "$task_dir/dispatcher-arm64.obj"
printf 'ARM64 public DISPATCHER_CONTEXT: PASS (4 assertions)\n'

# The MinGW DDK requires its own include directory. Its bundled ARM64 DDK
# rejects the architecture, so only x86/x64 named KUSER members are checked.
for guest in x86 x64; do
    if [[ "$guest" == x86 ]]; then compiler="$x86_cc"; else compiler="$x64_cc"; fi
    ddk_dir="$("$compiler" -print-file-name=include)/ddk"
    if [[ ! -f "$ddk_dir/ntddk.h" ]]; then
        ddk_dir="$("$compiler" -print-sysroot)/include/ddk"
    fi
    if [[ ! -f "$ddk_dir/ntddk.h" ]]; then
        # GCC's install prefix points at the target sysroot on MinGW builds.
        compiler_prefix="$("$compiler" -print-search-dirs | sed -n 's/^install: //p')"
        ddk_dir="$(cd "$compiler_prefix/../../../../$("$compiler" -dumpmachine)/include/ddk" && pwd)"
    fi
    "$compiler" -std=c11 -Werror -I"$ddk_dir" -c "$probe_dir/kuser.c" -o "$task_dir/kuser-$guest.obj"
    printf '%s public KUSER_SHARED_DATA: PASS (27 assertions)\n' "$guest"
done
