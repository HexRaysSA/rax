# Freestanding SList, processor-feature and system-time fixture

`build.sh` produces one custom-entry Windows PE per guest ABI: PE32 x86,
PE32+ x64, and PE32+ ARM64. The C source is compiled without a Windows SDK or
C runtime. Only `KERNEL32.dll` is imported; x86 import-library names use
`stdcall` decorations, while x64/ARM64 names do not.

The guest exercises the public SList imports — initialization, last-in
first-out push and pop with the depth query, an empty pop, flushing a chain
with its links intact, and pushing a prepared chain with
`InterlockedPushListSListEx` — then checks that KERNEL32's
`InitializeSListHead` and `RtlCaptureContext` are the very NTDLL functions
`GetProcAddress` returns for `RtlInitializeSListHead` and
`RtlCaptureContext`. It asks `IsProcessorFeaturePresent` for fast fail (true)
and index 64 (false), and on x86/x64 compares SSE2 against the guest's own
`CPUID`. `GetSystemTimeAsFileTime` must be after 2020-01-01 and must not run
backwards. Finally two threads each push and then pop 1,000 entries on one
shared list; every pop returns an entry and the list ends empty. Each failed
check exits with a distinct nonzero code; success exits with 0.

The [integration runner](../../../../suites/user/windows/slist.rs) is
registered in the existing `user_windows` Cargo target through
`tests/suites/user/windows/main.rs`. It runs each binary at scheduler slices
of 1 and 4,096 guest instructions, seed 1, a 64 MiB guest arena, and
`RAX_NO_JIT=1`, with a 30 s external watchdog. A separate test checks the
generator/source hashes, tool identities, artifact hashes and sizes, PE
architecture and timestamp, and the fourteen named KERNEL32 imports.

Before the SList exports existed, all three binaries stopped at
`emulator failure: unimplemented Windows export: KERNEL32.DLL!InitializeSListHead`.

## Rebuild and provenance

From the repository root:

```sh
bash tests/fixtures/user/windows/slist/build.sh
```

This standalone generator writes only its own `bin/{x86,x64,arm64}/slist.exe`
files and `manifest.toml`. `manifest.toml` records the SHA-256 of the build
script, C source, both `.def` files, three binaries, and installed
compiler/linker/dlltool binaries, plus executable byte counts. The zero COFF
timestamp and source prefix remapping support reproducible output with the
recorded toolchain. The [retained Microsoft references](../../../../../docs/specifications/windows/services/slist/README.md)
define the public API surface; native Windows execution is unknown.
