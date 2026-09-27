#!/usr/bin/env bash
set -euo pipefail

probe_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
task_dir="$(mktemp -d "${TMPDIR:-/tmp}/rax-windows-lock-layout.XXXXXX")"
trap 'rm -f "$task_dir/x86.obj" "$task_dir/x64.obj" "$task_dir/arm64.obj"; rmdir "$task_dir"' EXIT
"${CC_X86:-i686-w64-mingw32-gcc}" -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/x86.obj"
printf 'x86: PASS (9 assertions)\n'
"${CC_X64:-x86_64-w64-mingw32-gcc}" -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/x64.obj"
printf 'x64: PASS (9 assertions)\n'
"${ZIG_BIN:-zig}" cc -target aarch64-windows-gnu -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/arm64.obj"
printf 'ARM64: PASS (9 assertions)\n'
