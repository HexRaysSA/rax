# ARM64 dynamic function-table unwind probe

This is one freestanding, custom-entry Windows ARM64 PE. Clang 23 and LLD 23
produce the static source function, but the guest copies its instructions and
handler into an anonymous executable page. The guest builds a new 8-byte ARM64
function-table entry in a different read/write page and copies its full
version-0 `.xdata` into a third read-only page. The guest changes the copied
handler RVA to point into the anonymous code page. Its `BaseAddress` is that
code page; the table itself is at `BaseAddress+0x1000`, and the `.xdata` is at
`BaseAddress+0x2000`. The pages are separately committed/protected within one
anonymous 12,288-byte reservation. This distinguishes the table pointer from
the RVA base without depending on host-side metadata.

The PE imports only `ExitProcess`, `RaiseException`, `RtlAddFunctionTable`,
`RtlDeleteFunctionTable`, `RtlLookupFunctionEntry`, `VirtualAlloc` and
`VirtualProtect` from KERNEL32.
It does not link a CRT or a Windows SDK library. After registration, the
anonymous function calls `RaiseException(0xE1234567, 0, 0, NULL)` through a
caller-supplied function pointer. Its anonymous handler checks the code,
increments a read/write-page marker exactly once, and returns
`ExceptionContinueExecution`. The function must then return 7. The entry
requires that value and marker 1, deletes the table by its original array
pointer, and exits 0. Before registration, `RtlLookupFunctionEntry` must miss;
after registration it must return the exact guest table pointer and write the
code-page `BaseAddress`; after deletion it must miss again. On both misses,
the guest initializes the output base to `0xA55A112233447788` and checks that
the bytes remain unchanged. Preserving that output on a miss is an explicit
RAX policy, not a native Windows guarantee: the public page specifies a NULL
entry return but not the output value in that case. The second-delete result
is not asserted. Each failed check has a distinct nonzero exit code.

The [Microsoft ARM64 exception specification](../../../../../docs/specifications/windows/microsoft-docs/arm64-exception-handling.md)
defines the 8-byte function record and `.xdata` RVA/packed alternatives.
Microsoft's [RtlAddFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable),
[RtlDeleteFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtldeletefunctiontable)
and [RtlLookupFunctionEntry](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry)
pages define registration, deletion and active-table lookup; the
[ARM64 ABI conventions](../../../../../docs/specifications/windows/microsoft-docs/arm64-windows-abi-conventions.md)
explicitly call for dynamic function tables for generated code. Native Windows
execution of this fixture is unknown. The selected RAX profile validates the
guest-resident array and `.xdata` when registering and reads live guest bytes
during lookup; this is not claimed as the native mutation/fault-timing rule.

Rebuild and inspect with:

```sh
bash tests/fixtures/user/windows/dynamic_unwind_arm64/build.sh
llvm-readobj --unwind --coff-imports tests/fixtures/user/windows/dynamic_unwind_arm64/bin/arm64/dynamic.exe
```

`llvm-readobj` reports one static ARM64 `.pdata` record with a 52-byte
function, full handler-bearing `.xdata`, and unwind bytes `E1 81 E4 E3`.
The guest copies 16 metadata bytes from that record and retargets its handler
RVA before registration. Two consecutive builds produced identical
`manifest.toml` SHA-256
`16055f0d9f1aefd41901f9a668a1093ecb6b215fa8e72a2075a7867df2da4585`
and `dynamic.exe` SHA-256
`bbad2b50597a47934470a6c78d9c080ecbe78bbc96c8b62e78bd0727f6deba29`.
The manifest records tool, source and PE hashes and PE size. The integration
runner checks those bytes, the exact imports and source `.pdata` form, then
executes the guest at 1 and 4,096 instructions per slice. The expected exit
code comes from the independent guest checks above, not an emulator output.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| D1 | The pinned assembler emits the source `.xdata` as a 4-byte header, one 4-byte code word, a 4-byte handler RVA and a 4-byte handler parameter. | `llvm-readobj` observation; the guest additionally checks the header before copying. | A 16-byte copy and RVA patch at byte 8. | Change assembler/version or epilog shape. | Rebuild and inspect `.pdata`/`.xdata`; a changed layout must exit 11 before registration. | confirmed for pinned toolchain |
| D2 | The three separately committed pages remain at offsets 0, `0x1000` and `0x2000` within the reserved block. | Every `VirtualAlloc` result is compared against its requested address. | Base-relative RVAs fit in 32 bits. | Force a commit failure or address collision. | Guest exits 13 before publishing the table. | confirmed for successful path |
| D3 | A miss leaves the `ImageBase` output unchanged in the selected RAX profile; native Windows behavior is unknown. | The public lookup page specifies a NULL return on miss but not the output value. | Pre-registration and post-deletion sentinel checks. | Query the same anonymous control PC before Add and after Delete. | Guest exits 18 or 20 if either miss changes the output. | retained profile |

High-impact boundary: image-only unwind lookup would treat this anonymous
nonleaf function as a leaf or fail to find its handler, so it cannot satisfy
this fixture. Unsorted/overlapping dynamic-table precedence, callbacks,
growable tables, live mutation and native Windows fault timing remain outside
this compiled probe. Copy and hash verification take O(B) time and O(B) output
space for B PE bytes; the fixture itself registers one record and copies fewer
than 4,096 code bytes and 16 metadata bytes.
