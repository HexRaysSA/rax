# x64 dynamic function-table unwind witness

This is a freestanding PE32+ AMD64 executable with a custom `entry`, no CRT,
and no Windows SDK linkage. `build.sh` uses Clang, `llvm-dlltool`, and LLD;
`manifest.toml` pins source/tool SHA-256 digests, the 2,560-byte PE artifact,
the six imported names, and the expected zero exit status. Rebuild and inspect:

```sh
bash tests/fixtures/user/windows/dynamic_unwind_x64/build.sh
llvm-readobj --file-headers --coff-imports --unwind \
  tests/fixtures/user/windows/dynamic_unwind_x64/bin/dynamic_unwind.exe
llvm-objdump -d \
  tests/fixtures/user/windows/dynamic_unwind_x64/bin/dynamic_unwind.exe
```

The executable imports only `ExitProcess`, `RaiseException`,
`RtlAddFunctionTable`, `RtlDeleteFunctionTable`, `VirtualAlloc`, and
`VirtualProtect` from `KERNEL32.dll`. The PE exception directory has RVA 0 and
size 0: no static `.pdata` entry describes the JIT routine. `entry` allocates
4,096 bytes of writable guest memory, copies an internally PC-relative
176-byte assembly template, patches two 64-bit pointers, and changes the page
to execute-read. A writable, 12-byte `RUNTIME_FUNCTION` on the guest stack
describes the copied function, not the original PE `.text` bytes. Its
`BeginAddress=0x0`, `EndAddress=0x37` (exclusive), and `UnwindData=0x38` are
relative to the allocated page supplied as `BaseAddress` to
`RtlAddFunctionTable`. The same table pointer remains live through
`RtlDeleteFunctionTable`.

The source and object-symbol inspection establish the copied layout:

| Copied-page offset | Bytes or meaning |
|---|---|
| `0x00..0x36` | 55-byte nonleaf function; `push rbx` (1 byte), `sub rsp,48` (4 bytes), nested `RaiseException` call, and an `add rsp,48; pop rbx; ret` epilog. |
| `0x38..0x3f` | `09 05 02 00 05 52 01 30`: version 1, `UNW_FLAG_EHANDLER`, 5-byte prolog, two unwind slots, no frame register; `UWOP_ALLOC_SMALL` at prolog offset 5 allocates `5×8+8=48` bytes, then `UWOP_PUSH_NONVOL` at offset 1 restores RBX. |
| `0x40..0x43` | `60 00 00 00`: handler RVA `0x60`, relative to the allocated page. |
| `0x48`, `0x50` | Patched `RaiseException` and marker-address literals, each 8 bytes. |
| `0x60..` | Leaf exception handler; copied blob ends at `0xb0`. |

After the 5-byte prolog, the dynamic routine's `RSP` is the base of its
48-byte fixed allocation. The 32-byte outgoing home area occupies
`[RSP+0,RSP+31]`; a marker pointer and a 64-bit cookie occupy `RSP+32` and
`RSP+40`. The x64 handler receives this fixed-allocation base as
`EstablisherFrame` in `RDX`. It validates the exception code
`0xE1234567`, continuable flags, marker pointer, and cookie, increments the
marker once, and returns `ExceptionContinueExecution` (`0`). Its wrong-frame
branch writes `0xBAD`, also resumes, and causes a nonzero exit in `entry`.
The dynamic routine returns `0x42` only after `RaiseException` resumes.

The source assigns distinct nonzero exits: 10 for allocation, 11 for an
invalid blob layout, 12 for protection change, 13 for failed registration,
14 for an unexpected dynamic return, 15 for a missing/repeated/wrong-frame
handler after return, and 16 for failed exact-pointer deletion. If no frame
handles the raised exception, dispatch can terminate the process before
`entry` regains control; the exact native termination status in that case is
unknown. `ExitProcess(0)` requires successful registration, one correct
handler invocation, continuation through the dynamic function, and successful
deletion. It does not claim that a second deletion must fail on native Windows.
The expected status is derived from the guest source and the public API/ABI
contract, not from RAX execution.

Primary contracts: Microsoft
[x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64),
[RtlAddFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable),
[RtlDeleteFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtldeletefunctiontable),
and [RaiseException](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception).
The x64 exception contract defines the 32-bit base-relative table fields,
unwind-code encodings, fixed-allocation establisher frame, and four-argument
handler ABI. Native Windows execution of this fixture is unknown.

## Runner contract

The Windows user-mode integration module verifies the manifest/source/binary
digests, PE machine/import set/zero exception directory, and the unique
`09 05 02 00 05 52 01 30 60 00 00 00` sequence in the mapped image. Run
the same immutable PE at 1 and 4,096 guest instructions per slice and require
an exit status of 0. The PE intentionally does not import
`RtlLookupFunctionEntry`; post-delete lookup and duplicate-deletion policy
belong to API-specific unit tests, not this executable.

## Assumption Register and bounded scope

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| D1 | The allocated page remains mapped and the stack-local table remains writable/live until deletion. | `probe.c` control flow retains both objects; the table is passed by exact pointer. | Valid registration and exception search. | Instrument guest memory at Add, handler, and Delete; any unmap or pointer change falsifies this. | confirmed from source; guest execution pending |
| D2 | The copied blob has no absolute references besides the two patched 64-bit literals. | Assembly uses internal RIP-relative references and base-relative handler RVA; disassembly and object symbols were inspected. | Relocation from PE `.text` to `VirtualAlloc` page. | Copy at a different guest base and compare handler/return behavior; scan relocations to the template in the linked PE. | confirmed for checked-in binary |
| D3 | `EstablisherFrame` denotes the base of the fixed 48-byte allocation for this no-frame-register function. | Microsoft x64 exception-handling contract; actual prolog is 1+4 bytes. | Marker pointer/cookie reads at +32/+40. | Mutate the encoded allocation or pass a shifted establisher; marker must not become 1. | confirmed by contract; native run unknown |

High impact: if dynamic-table lookup excludes a `BeginAddress` of zero, the
registered JIT frame will be missed; this fixture deliberately exercises that
boundary. Medium impact: malformed/out-of-range unwind records and duplicate
deletion are outside this one valid-table witness and require separate
fail-closed unit tests. Low impact: the PE keeps the allocated page until
process termination after deletion; this does not affect the table-lifetime
claim. Template copying takes O(B) time and O(B) allocated space for
`B=176` bytes; the function table has one entry and search depth here is
bounded by the guest call stack.
