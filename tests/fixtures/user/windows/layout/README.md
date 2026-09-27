# Public Windows layout probes

Run `bash tests/fixtures/user/windows/layout/check.sh` from any directory.
The script cross-compiles `public.c` for x86, x64, and ARM64, `kuser.c`
for x86/x64, and `dispatcher.c` for x64/ARM64. Every expected size and offset
is in bytes. `_Static_assert`
failures stop the script. Temporary COFF objects are removed at exit; no
executable is linked or run. Override `CC_X86`, `CC_X64`, or `ZIG_BIN` to
select equivalent tools. All assertions concern members actually declared
by the selected headers; no undocumented PEB/TEB fields are inferred.

The installed headers are MinGW-w64's declarations, not a native Microsoft
SDK or runtime oracle. Upstream sources are
[MinGW-w64 headers](https://github.com/mingw-w64/mingw-w64/tree/master/mingw-w64-headers/include)
and [Zig's bundled Windows headers](https://github.com/ziglang/zig/tree/master/lib/libc/include/any-windows-any).
The precise upstream header commits for the installed packages are unknown;
the versions and SHA-256 hashes below identify the actual inputs used.

Verified 2026-09-27 on an AArch64 macOS host:

| Guest | Compiler identity | Header macros | Public assertions | Result |
| --- | --- | --- | ---: | --- |
| x86 | `i686-w64-mingw32-gcc (GCC) 16.2.0` | `14.0.0`, state `alpha` | 44 + 27 KUSER | PASS |
| x64 | `x86_64-w64-mingw32-gcc (GCC) 16.2.0` | `14.0.0`, state `alpha` | 54 + 27 KUSER | PASS |
| ARM64 | Zig `0.16.0`, delegated `Homebrew clang version 21.1.8` | `13.0.0`, state `alpha` | 35 | PASS |

`dispatcher.c` additionally checks three x64 and four ARM64 named
`DISPATCHER_CONTEXT` assertions: x64 size `0x50` bytes and `ScopeIndex`/`Fill0`
offsets; ARM64 size `0x58` bytes and `ScopeIndex`/`ControlPcIsUnwound`/
`NonVolatileRegisters` offsets. These seven assertions are separate from the
public/KUSER counts above.

Exact commands executed by the script, with `probe_dir` pointing at this
directory and `task_dir` a new temporary directory:

```sh
i686-w64-mingw32-gcc -std=c11 -Werror -c "$probe_dir/public.c" -o "$task_dir/x86.obj"
x86_64-w64-mingw32-gcc -std=c11 -Werror -c "$probe_dir/public.c" -o "$task_dir/x64.obj"
zig cc -target aarch64-windows-gnu -std=c11 -Werror -c "$probe_dir/public.c" -o "$task_dir/arm64.obj"
x86_64-w64-mingw32-gcc -std=c11 -Werror -c "$probe_dir/dispatcher.c" -o "$task_dir/dispatcher-x64.obj"
zig cc -target aarch64-windows-gnu -std=c11 -Werror -c "$probe_dir/dispatcher.c" -o "$task_dir/dispatcher-arm64.obj"
i686-w64-mingw32-gcc -std=c11 -Werror -I"$ddk_x86" -c "$probe_dir/kuser.c" -o "$task_dir/kuser-x86.obj"
x86_64-w64-mingw32-gcc -std=c11 -Werror -I"$ddk_x64" -c "$probe_dir/kuser.c" -o "$task_dir/kuser-x64.obj"
```

Here `ddk_x86` and `ddk_x64` are the respective compiler's target
`include/ddk` directories; the script locates them from compiler metadata.
It also prints compiler identity and the `__MINGW64_VERSION_*` macros.
Zig `-fsyntax-only` failed `FileNotFound` for both stdin and a real source
file in this environment. Ordinary compile-only mode above passed.
Zig's bundled `ntddk.h`/`wdm.h` reject ARM64 with `Unknown Architecture`,
so no ARM64 KUSER probe result is claimed. `NtBuildNumber` and
`NativeProcessorArchitecture` are absent from these `ntddk.h` revisions
and are not asserted as named members for any architecture.

Input SHA-256 hashes:

| Input | SHA-256 |
| --- | --- |
| `public.c` | `8f58c4ebe3077b4449567fe8fa9bba72fad13875c08483f1aaea9c0808f3b47e` |
| `kuser.c` | `899c8b954cf423331c4d0f0cf57967912f0d1565c9063f83267444829f047377` |
| `dispatcher.c` | `50cbaaa27cabe6e0d9098636f1e6124117acd087235ae37ecfec6b507daddf99` |
| MinGW 14.0.0 x86/x64 `winnt.h` | `d9924297c155c1e955d5262a1a6fa1dcccf12608afcc5327d7b848fb7514af0b` |
| MinGW 14.0.0 x86/x64 `winternl.h` | `f66418638586233a872c3ff6dd850a1dfad27a47a96ce84e065835f4a5111e6b` |
| MinGW 14.0.0 x86/x64 `ddk/ntddk.h` | `d623c5b6017d437423c3eedf00879a8605ced49f6d7070995363270470c40c7c` |
| Zig-bundled MinGW 13.0.0 `winnt.h` | `1bffc405c3dff7133fbb03d5902b384d31db8e76d6a6dffa89f495a2e2728828` |
| Zig-bundled MinGW 13.0.0 `winternl.h` | `f66418638586233a872c3ff6dd850a1dfad27a47a96ce84e065835f4a5111e6b` |

The non-public modern PEB/TEB/LDR/process-parameter fields in
`src/user/windows/layout.rs` are not validated by these probes. Their
claimed Windows public-symbol build/PDB provenance is unknown unless
independently recorded. A matching documented padding span is not proof
of a private member's name or semantics. The probes therefore establish
public header layout compatibility only, not native Windows startup,
floating-point state, context-restoration behavior, or unwind equivalence.
