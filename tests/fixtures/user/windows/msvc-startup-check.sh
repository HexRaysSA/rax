#!/usr/bin/env bash
# Prove ordinary MSVC CRT startup under the Windows personality: a console
# program linked against the dynamic UCRT and VCRUNTIME140, as MSVC builds it
# by default, for x86, x64 and ARM64.
#
# Nothing this check uses or produces belongs in the repository. It downloads
# Microsoft's CRT and Windows SDK with xwin into a cache outside the tree --
# accepting Microsoft's license only when told to -- writes its C source and
# executables to a temporary directory, runs each executable under rax-user,
# and deletes the build. It fails when a prerequisite is missing; it never
# passes by skipping.
#
# Usage:
#   tests/fixtures/user/windows/msvc-startup-check.sh --accept-msvc-license [--arch x86,x64,arm64]
#
# All three architectures are checked unless --arch names a subset.
#
# Environment:
#   RAX_MSVC_CACHE    download/splat cache (default: $XDG_CACHE_HOME or
#                     ~/.cache, then rax-msvc-startup)
#   RAX_USER          rax-user to test (default: build target/release/rax-user)
#   XWIN_BIN, CLANG_CL_BIN, LLD_LINK_BIN, LLVM_OBJDUMP_BIN   tool overrides
set -euo pipefail

usage() {
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

accepted=0
arches="x86 x64 arm64"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --accept-msvc-license) accepted=1 ;;
        --arch)
            shift
            arches="$(printf '%s' "${1:-}" | tr ',' ' ')"
            for arch in $arches; do
                case "$arch" in
                    x86|x64|arm64) ;;
                    *) echo "msvc-startup-check: unknown architecture: $arch" >&2; exit 2 ;;
                esac
            done
            [ -n "$arches" ] || { echo "msvc-startup-check: --arch needs a list" >&2; exit 2; }
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "msvc-startup-check: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ "$accepted" -ne 1 ]; then
    echo "msvc-startup-check: refusing to download Microsoft's CRT and SDK without --accept-msvc-license" >&2
    echo "  (passing it accepts the license xwin presents for the Visual Studio Build Tools packages)" >&2
    exit 2
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
xwin_bin="${XWIN_BIN:-xwin}"
clang_cl_bin="${CLANG_CL_BIN:-clang-cl}"
lld_link_bin="${LLD_LINK_BIN:-lld-link}"
objdump_bin="${LLVM_OBJDUMP_BIN:-llvm-objdump}"
for tool in "$xwin_bin" "$clang_cl_bin" "$lld_link_bin" "$objdump_bin"; do
    if ! command -v "$tool" > /dev/null; then
        echo "msvc-startup-check: required tool not found: $tool" >&2
        exit 2
    fi
done

cache="${RAX_MSVC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rax-msvc-startup}"
splat="$cache/splat"
case "$cache" in
    "$repo"|"$repo"/*)
        echo "msvc-startup-check: the cache must be outside the repository: $cache" >&2
        exit 2
        ;;
esac
if [ ! -d "$splat/crt/lib/x86" ] || [ ! -d "$splat/crt/lib/x86_64" ] || [ ! -d "$splat/crt/lib/aarch64" ]; then
    echo "msvc-startup-check: downloading the CRT and SDK into $cache"
    "$xwin_bin" --accept-license --cache-dir "$cache/download" --arch x86,x86_64,aarch64 \
        splat --output "$splat"
fi

if [ -n "${RAX_USER:-}" ]; then
    rax_user="$RAX_USER"
else
    cargo build --manifest-path "$repo/Cargo.toml" --release --no-default-features \
        --features x86_64-suite,smir-jit --bin rax-user
    rax_user="$repo/target/release/rax-user"
fi
if [ ! -x "$rax_user" ]; then
    echo "msvc-startup-check: rax-user is not executable: $rax_user" >&2
    exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/rax-msvc-startup.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cat > "$work/main.c" <<'SOURCE'
/* Ordinary MSVC startup: mainCRTStartup -> __scrt_common_main_seh, which
 * initializes the CRT (InitializeSListHead among it), runs initializers,
 * calls main, and exits through exit(). */
#include <stdio.h>
#include <windows.h>

static SLIST_HEADER list;
static SLIST_ENTRY entry;

int main(void) {
    InitializeSListHead(&list);
    if (InterlockedPushEntrySList(&list, &entry) != NULL) return 1;
    if (QueryDepthSList(&list) != 1) return 2;
    if (InterlockedPopEntrySList(&list) != &entry) return 3;
    if (!IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE)) return 4;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    if (now.dwHighDateTime == 0) return 5;
    if (fwrite("msvc-startup ok\n", 1, 16, stdout) != 16) return 6;
    return 42;
}
SOURCE

failures=0
for arch in $arches; do
    case "$arch" in
        x86) target=i686-pc-windows-msvc; machine=x86; lib=x86 ;;
        x64) target=x86_64-pc-windows-msvc; machine=x64; lib=x86_64 ;;
        arm64) target=aarch64-pc-windows-msvc; machine=arm64; lib=aarch64 ;;
    esac
    exe="$work/$arch/msvc_startup.exe"
    mkdir -p "$work/$arch"
    "$clang_cl_bin" --target="$target" /nologo /c /O1 /MD /GS /Brepro \
        -imsvc "$splat/crt/include" -imsvc "$splat/sdk/include/ucrt" \
        -imsvc "$splat/sdk/include/um" -imsvc "$splat/sdk/include/shared" \
        "$work/main.c" /Fo"$work/$arch/main.obj"
    "$lld_link_bin" /nologo /machine:"$machine" /subsystem:console /Brepro /dynamicbase /nxcompat \
        /libpath:"$splat/crt/lib/$lib" /libpath:"$splat/sdk/lib/ucrt/$lib" \
        /libpath:"$splat/sdk/lib/um/$lib" \
        "$work/$arch/main.obj" kernel32.lib /out:"$exe"

    # Linked the way MSVC links by default: the startup code is static, the
    # runtime is the dynamic UCRT and VCRUNTIME140.
    imports="$("$objdump_bin" -p "$exe")"
    for needed in VCRUNTIME140.dll api-ms-win-crt-runtime-l1-1-0.dll KERNEL32.dll InitializeSListHead; do
        if ! grep -qi "$needed" <<< "$imports"; then
            echo "FAIL $arch: the executable does not import $needed" >&2
            failures=$((failures + 1))
        fi
    done

    for slice in 1 4096; do
        status=0
        RAX_NO_JIT=1 "$rax_user" --os windows --memory 64M --slice "$slice" --seed 1 "$exe" \
            > "$work/$arch/stdout" 2> "$work/$arch/stderr" < /dev/null || status=$?
        # The UCRT writes stdout in text mode, so the line ends in CRLF, as on
        # Windows. rax-user reports a nonzero exit status itself; nothing else
        # may reach stderr.
        printf 'msvc-startup ok\r\n' > "$work/$arch/expected_stdout"
        printf 'rax-user: %s: exited with status 42 (0x2a)\n' "$exe" > "$work/$arch/expected_stderr"
        stdout="$(cat "$work/$arch/stdout")"
        stderr="$(cat "$work/$arch/stderr")"
        if [ "$status" -ne 42 ] || ! cmp -s "$work/$arch/stdout" "$work/$arch/expected_stdout" \
            || ! cmp -s "$work/$arch/stderr" "$work/$arch/expected_stderr"; then
            echo "FAIL $arch slice=$slice: exit $status, stdout '$stdout', stderr '$stderr'" >&2
            failures=$((failures + 1))
        else
            echo "ok   $arch slice=$slice: exit 42, 'msvc-startup ok'"
        fi
    done
done

if [ "$failures" -ne 0 ]; then
    echo "msvc-startup-check: $failures failure(s)" >&2
    exit 1
fi
echo "msvc-startup-check: $arches start, run main and exit through the MSVC CRT"
