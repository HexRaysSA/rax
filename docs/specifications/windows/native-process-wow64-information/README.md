# ProcessWow64Information: owned-process identity and copy boundaries

`NtQueryInformationProcess` class 26 returns an `ULONG_PTR`. Microsoft documents
zero/nonzero WoW64 detection, not the exact nonzero value or private fault
ordering: [API reference](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
(last updated 2024-02-22, accessed 2026-10-27).

## Independent native controls

`native-query-v1.cpp` called the real installed entry in ARM64, x64 compatibility,
and x86 processes on an ARM64 Windows 10.0.29695 kernel. It produced 409, 409,
and 405 cases. `native-query-v3.cpp` additionally measures actual handle grants
with `NtQueryObject` and repeats tagged real handles. The unchanged ARM64
`native-family-launcher-v2.cpp` creates owned x86 children with default, enabled,
and disabled CHPE attributes, producing 433 cases per family. No machine policy,
installed library, emulator result, or original exception fixture was changed.

`local-29695-v1.json` is a decoded copy of six preserved raw outputs: 2,522 cases.
The native sources, controller receipts, compiler/binary/library hashes, and exact raw
outputs (base64 in JSON) are retained beside it. v2 of the query source failed compilation due to a
shadowed local under `/WX`; v3 renames it. Only completed controls are in the
replay corpus. The family launcher source is identical to the previously
published native x86 profile launcher, including its bounded child lifetime.

| Process view | Output bytes | Value for self | Successful ReturnLength |
|---|---:|---|---:|
| ARM64 | 8 | 0 | 8 |
| x64 compatibility on ARM64 | 8 | 0 | 8 |
| x86, default/CHPE enabled/CHPE disabled | 4 | Independently queried PEB32 address | 4 |

Each x86 identity control separately obtains `ProcessBasicInformation` and
compares its PEB32 field with class26. Four distinct observed PEB32 addresses
agree. A generic nonzero sentinel would lose that identity contract. Native64
self queries describe their own 64-bit process and return zero, including x64
compatibility on ARM64.

## Checked entry and caller writes

Native64 checks ULONG output alignment and the complete upper user span before
visiting the optional four-byte `ReturnLength`. It probes that destination before
length/handle/output access. Output pages are first visited after exact-size and
handle validation. Four-byte alignment suffices for an eight-byte result.

WoW64 accepts unaligned output, checks exact length and the process handle, then
stores the converted four-byte PEB32 before the optional four-byte length. An
invalid late length destination can therefore leave the PEB32 output written.
Both paths require exactly the pointer width, leave the failure length untouched,
and write the successful length after output. In particular, class7's translated
`0xFFFFFFFC` failure length does not apply to class26. Alias cases freeze the
observable last-store ordering.

Direct writes to read-only guarded pages return access violation without visiting
the guard. Writable guards return guard violation and consume the reached guard.
Native64's earlier length preprobe instead consumes even a read-only length guard.
The replay compares status, exception absence, both 16-byte destination windows,
guard protection, ABI continuation, stack restoration, and frame cleanup.

The real process handle needs `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`).
The measured kernel automatically grants `0x1400` when creation requests `0x400`;
the replay represents those actual rights rather than attributing success to
`0x400` alone. Exact zero-right handles fail with access denied; the separate
failed `OpenProcess(0)` input is an invalid handle. Thread/event handles yield
object-type mismatch. Low-two-bit process-handle tags retain their object identity.

## Guest representation and scope

The implementation uses the existing guest `p.peb` for x86 and zero for the
64-bit personalities. Synthetic x86 already models a virtual AMD64 kernel;
installed x86 requires captured native64 metadata. Unknown installed native
architecture remains unsupported. No guest pointer or handle is used for a host
process query. A process outside this personality remains explicitly unsupported
because its PEB/architecture is not represented by the existing object record.

Copy/fault behavior is a measured build-29695 contract. These ARM64-kernel
controls do not qualify a physical AMD64 kernel, every Windows build, an actual
native32 kernel, or foreign-process emulation. Linux and macOS execute the same
portable guest implementation and frozen replay; those runs are not native
Windows oracle evidence. No public C ABI, exported service ordinal, ISA, SMIR,
JIT, package layout, dependency pin, or product default changes.

`python3 -B verify.py` verifies raw-byte hashes, decoded corpus equality, all
2,522 ordinals, native identity results, and source/controller receipt bindings.

## Original startup observation

`stopped-observer-v3.rs` runs the original, unchanged x86 hardware-fault fixture
with its existing limits (60 s, 16,384 slices of 4,096 instructions, at most
67,108,864 instructions). It records the original stop at class26, current PEB32
`0x7FFDF000`, self pseudo-handle, four-byte output, and absent ReturnLength.
The installed wrapper's `RET 20` agrees with the existing five argument slots.
The observer binds the pre-change rlib and fixture hashes in its receipt; it
neither supplies a syscall result nor edits the fixture. This establishes the
concrete startup consumer without claiming that class26 alone completes startup.

## Validation and retained frontier

| Host | Process-query filter | Complete C API | Capture verifier |
|---|---:|---:|---|
| macOS ARM64 | 27 passed | 191 passed | Passed |
| Linux x86-64 configuration under ARM64-hosted Docker | 27 passed | 191 passed | Passed |
| Native Windows ARM64, including installed ARM64/x86 leaves | 32 passed | 191 passed | Passed |

These selected gates have zero failures and ignored cases. An initial replay
version rebased only the output window, missing PEB bytes also visible through
an implicitly overlapping page-end ReturnLength window. Its 26/1 macOS and Linux,
and 31/1 Windows verdicts are retained; the final replay compares both windows.
This correction did not change the handler's returned bytes or status.

The unchanged original hardware-fault fixture was rerun separately: 0 passed,
1 failed. ARM64 completes its fault/RTL handler/context continuation and exit0;
x86 advances past class26 and now stops at unimplemented
`NtSetInformationProcess` class34. The fixture source, three binaries, assertions,
and execution budgets remain unchanged. No full-green Windows-personality or
complete host-library-backed process claim follows from these selected gates.

Validation uses the existing combined tree, including five pre-existing tracked
changes and a separate native-entry draft. Those files and the original fixture
are excluded from this changeset. The shared class26 implementation and its
portable replay do not depend on that draft. Shipping plugin/package/installed
Assist runtime qualification remains separate from the paired source pin.

The handler performs constant work and uses O(1) auxiliary storage. A successful
call stores W bytes of output and optionally 4 bytes of length, with W=4 for
x86 and W=8 for native64: at most 8 or 12 store bytes, respectively. Overlap can
reduce the number of distinct destination bytes. No caller-proportional host
allocation or host process query is performed.
