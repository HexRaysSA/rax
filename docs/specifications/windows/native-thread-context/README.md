# Native thread context

The primary capture binds `NtGetContextThread` and `NtSetContextThread` observations
to Windows 10.0.29704.0 and seven installed DLL images, including NativeXTA.
The three v21 probes each create their own worker, observe its ready handshake
and at least 10,000 atomic increments, suspend it, and restore its original
context before resuming it. Each probe and worker completes naturally. No
emulator is linked into these controls.

The capture contains 4,957 observation cases, six export-code records, three
processor-feature records, and three setup records. An unavailable ARM64
extended-context initializer is an observation, not an executed NT context call.
Provenance binds source, compiler commands, executable identities and stdout.
The seven installed DLL hashes hold before and after execution.

The exports are syscall leaves: ARM64 uses `SVC #0xfa` and `SVC #0x19a`;
AMD64 uses the corresponding `SYSCALL` entries; WoW64 reaches its installed
transition thunk. The measured AMD64 conversion belongs to the syscall
compatibility boundary. These observations do not locate its implementation
precisely between user-mode translation and kernel code.

Cases cover selected groups, output byte changes, alignment, get/set grants,
low handle tags, wrong owned object types, closed duplicates, own pseudo
handles, protected and crossing spans, debug-register normalization, retained
exited-thread objects, extended chunks, and informational flags. LastError and
escaping exceptions are recorded separately from returned status.

Each get-context output uses two poison patterns. In the first 2,048 mask
digits, `0` means both input bytes survived, `1` means the outputs agree, and
`2` means they differ. The following 4,096 digits encode the first returned
buffer. A same-value store to a preloaded flag cannot be detected by this
method. Compatibility scratch bytes are not stable register values.

Record categories are:

- `0`: get flags and output mask; `1`: set flags; `2`: alignment.
- `3`: access, object type and protection; `4`: readable span.
- `5`, `8`, `9`, `10`: debug readback, control bits, address bounds and modes.
- `6`: retained exited thread; `7`: export metadata.
- `11`, `12`, `13`: initialized extended frames, requested masks and direct input.
- `15`: processor features; `16`: extended chunk metadata.

Index `0xffffffff` is setup; `0xfffffffe` is export metadata; `0xfffffffd`
is processor-feature metadata. Numeric fields use hexadecimal.

`context-information-states-v1.json` contains explicitly derived flag records
from startup, system-call waiting, ordinary user execution, and the current thread. Its source
programs and input stdout hashes are retained. ARM64/AMD64 informational
flags depend on the target's stopped state; WoW64 preserves a separately
measured selection of requested flags.

The independent cross-view controller creates an AMD64 or WoW64 child, which
creates its own suspended worker. It compares both directions of native ARM64
and translated context updates. For AMD64, upper YMM halves and `V16–V31`
alias at these context interfaces; `DR6` maps through `BVR4`, with the measured
normalization. WoW64 exposes separate banks. These API observations are distinct
from the [ARM64EC ABI register restrictions](https://learn.microsoft.com/en-us/cpp/build/arm64ec-windows-abi-conventions?view=msvc-170).

The AMD64 cross-view child and controller complete naturally. The WoW64 child
returns the recorded API results but exits with `0xc0000409` after restoration
and resume; its controller exits 24. The same WoW64 failure was observed with
the documented Win32 XState helpers, including a control modifying only the
eight i386 YMM registers. Its cause is unknown. WoW64 nonzero-YMM execution
is not qualified by these captures. No failed control is counted as a native
completion. All seven DLLs and staged inputs held during cross-view v2.

Primary contracts are the pinned SDK `winnt.h`,
[PHNT declarations](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h),
[GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext),
[SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext),
and [Working with XState Context](https://learn.microsoft.com/en-us/windows/win32/debug/working-with-xstate-context).
The first AMD64 experiment stopped at an incorrect ARM64-layout precondition;
it supplies no qualified cases.

These are independent native controls, not emulator completion evidence.
Full-suite, three-host, C API and Assist integration checks are separate gates
whose receipts must identify the exact source and binaries. The CHPE ownership
change is separate from these independent native controls.
