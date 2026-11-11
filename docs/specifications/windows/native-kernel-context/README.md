# Native kernel context for AMD64 processes on ARM64 Windows

The process machine, current instruction machine, and kernel context format
are separate contracts. An AMD64 image executing installed ARM64EC NTDLL code
still exposes an AMD64 logical `CONTEXT` through the emulator's public context
API. Its ARM64 kernel entry and raw ARM64 context services use
`ARM64_NT_CONTEXT` instead.

## Independent native control

`startup-context-probe.cpp` is an ARM64 Windows program using SDK declarations
and native APIs, with no RAX library linked. It creates each owned thread-start
fixture suspended, reads the primary thread context, resumes it exactly once,
and waits for natural process completion. It never calls `TerminateProcess`.
Compile it as ARM64 with the Windows SDK, for example:

```text
cl /nologo /MT /std:c++20 startup-context-probe.cpp /Fe:startup-context-probe.exe
startup-context-probe.exe <owned-fixture.exe>
```

The supplied captures bind the executable and all 196 compiler inputs by
SHA-256. Retained stdout files normalize CRLF to LF; the original and retained
stdout hashes are both recorded. The three native child processes (ARM64, AMD64, x86) each exited zero.
The controller requested `CONTEXT_FULL | CONTEXT_ARM64_X18`: the returned
context was 912 bytes with flags `0x00400017` in every case. The AMD64 child's
native PC was NTDLL RVA `0x23b8b0`, in an ARM64EC code range. This differs from
the selected AMD64 `RtlUserThreadStart` export at RVA `0x31d850`.

The selected image's CHPE row redirects `0x31d850` to `0x23b8b0`. Its canonical
ten-byte AMD64 prefix is followed by an `E9` displacement of `-925614` bytes:
`0x31d850 + 14 - 925614 = 0x23b8b0`. These are captured observations for this
image, not production constants. The implementation uses the selected image's
owned metadata, checks the canonical instruction bytes and displacement, and
requires the destination to belong to an ARM64 or ARM64EC code range.

The additional `NtGetContextThread` request placed AMD64 flags `0x0010000f`
at offset `0x30` in a zeroed 1232-byte buffer. The native call returned success
and changed only the native architecture tag at offset zero to `0x00400000`.
No register groups were returned; AMD64 RSP and RIP remained zero. Success
alone therefore does not establish that the kernel returned an AMD64 context.

Primary declarations are the Windows SDK `winnt.h` structures
`ARM64_NT_CONTEXT`, `CONTEXT`, and `ARM64EC_NT_CONTEXT`, and the documented
[retained Microsoft ARM64EC ABI register mapping](../native-arm64ec-bridge/arm64ec-abi.md).
The retained SDK-input hashes identify the declarations used in this capture.

## Emulator contract

For a logical AMD64 process whose discovered native kernel machine is ARM64:

- Native loader entry receives a 912-byte ARM64 context. Saved SP is aligned
  to 16 bytes; AMD64's eight-byte callable-entry adjustment is not applied to
  this native frame. Native X0 identifies the saved context, X1 the selected
  NTDLL module; saved X0/X1 identify application entry and its parameter.
- Raw `NtContinue` and `NtRaiseException` reached through ARM64 NTDLL syscall
  instructions parse the ARM64 context layout. API dispatch and a coincidental
  flags-like value at offset `0x30` cannot select this layout.
- Both paired CPU views are prepared before context publication. Selected
  native register groups are applied while native-only registers and the
  original cores' instruction-counter ownership are retained. X18 remains
  independently selected by `CONTEXT_ARM64_X18`.
- First-chance native exception contexts are projected into the existing
  logical personality representation. Second-chance input-capture and process
  termination ordering remain unchanged.
- Public logical-context APIs retain AMD64 layout and reject ARM64 input.
  Native ARM64, pure AMD64, and x86 startup retain their respective contracts.

The implementation does not infer context format from arbitrary buffer bytes,
replace the guest program, or implement a host DLL call as a substitute for
executing the selected guest DLL instructions.

## Validation and remaining boundary

`qualification-29704.json` records exact executable hashes, compiler-source
bindings, selected test counts, and observed frontiers. The source manifest
held unchanged through compilation and execution. This directory was added
after the compiled source frame was frozen; its provenance documents are not
compiler inputs to those Rust images.

Before this fix, the installed AMD64 loader treated a logical AMD64 startup
frame as native ARM64. In particular, the x87 control word at AMD64 offset
`0x100` was consumed as native SP, and continuation eventually failed with
`STATUS_BAD_STACK` (`0xc0000028`). The original saved AMD64 SP remained valid;
the failure was a context-format error rather than a missing stack allocation.

With this fix, the unchanged AMD64 fixture reaches its application entry,
creates and resumes its worker, and reaches the worker's return path. A bounded
4096-turn diagnostic then observes an indefinite main-thread wait after the
worker disappears from the runnable-thread set. This is an unresolved join /
context-resume frontier, not an exit-zero result. The ordinary unbounded run
is retained while that boundary is investigated.

| Assumption | Basis and dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| Raw ARM64 context services consume the native layout even for logical AMD64. | SDK layout, native child context, and the installed loader's observed converter; owns startup and raw service parsing. | Change the selected kernel machine or instruction machine; logical HLE continuation must still consume AMD64 layout. Malformed native flags plus plausible AMD64 flags must be rejected. | Confirmed for the captured configuration; other Windows builds remain independent qualification work. |
| The kernel entry is owned by verified selected-image CHPE metadata. | Native child PC agrees with the selected redirection row; owns startup entry selection. | Alter prefix/displacement or classify the target as AMD64; startup must reject the image. | Confirmed by native control and executable regressions. |
| Native controls establish emulator completion. | No evidence supports this proposition. | Compare the original fixture's emulator terminal state with its native exit code. | Falsified; the emulator join frontier remains unresolved. |

Change surfaces: Windows startup, paired interpreter context transfer, raw
NTDLL service parsing, and first-chance context projection. Shared Windows
semantics compile and run in the macOS, Linux, and Windows regression images.
No C API layout, feature default, package ABI, dependency pin, or installed-host
library selection policy changes in this RAX changeset. Assist must separately
pin and compile this exact RAX commit. GUI callback and mixed exception-frame
completion are outside this qualification and are not claimed as completed.

The remaining join / context-resume frontier has high impact on full AMD64
process completion and blocks the overall process-emulation goal. It does not
invalidate the independently reproduced native startup-format correction.
