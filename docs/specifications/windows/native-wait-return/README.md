# Native wait return register in ARM64EC

A raw NT service returns in the executing instruction ABI. For an AMD64
process executing ARM64EC instructions, native X0 is represented by RCX in the
public AMD64 context. RAX represents native X8. Immediate returns already use
`WinCpu::set_call_gpr(0, value)`; a parked service must preserve that same
mapping when it later restores its saved logical context.

`process/services/wait.rs` now captures the result-register choice when the
service parks. Its continuation writes RCX for ARM64EC and register 0 for
native ARM64, pure AMD64, and x86. The saved context retains its original
logical format. Object lifetime, signaling, deadlines, APC policy, native
guard-stack cleanup, and the public context API do not change. Selection costs
O(1) time and O(1) additional storage; the existing saved-context allocation is
unchanged.

The register mapping is specified by the retained primary
[Microsoft ARM64EC ABI document](../native-arm64ec-bridge/arm64ec-abi.md) and the
Windows SDK `ARM64EC_NT_CONTEXT` declaration identified in the independent
[native kernel-context capture](../native-kernel-context/README.md).

## Reproduction and regression

The published baseline `200fd9a0` fails the added immediate-versus-parked
regression: a successful parked event wait leaves native X0 equal to handle
`16`, while the immediate path returns zero. Its continuation writes the result
into RAX/native X8 instead of RCX/native X0.

The final regression covers immediate and parked event success and abandoned
mutex status (`0x80`). It compares the complete native register context and
executes `MOV X13,X0` as the first resumed guest instruction. Thus it checks the
value actually consumed by guest execution, including retention of native-only
registers and the saved PC/SP, rather than only inspecting a host-side value.
The ordinary x86, AMD64, and ARM64 wait tests remain selected, alongside APC,
guarded-stub, semaphore, mutex, context, and CHPE regressions.

`qualification-29704.json` binds the selected test counts, executable and
library hashes, source-frame digest, independent installed-image identities,
and diagnostic sources. These provenance documents were added after the
35476-file compiler source frame was frozen; they are not compiler inputs to
the recorded Rust images.

## Original fixture and remaining shutdown boundary

The guest programs are unchanged copies of
[`thread-start-probe-v1.c`](../native-nt-thread-lifecycle/thread-start-probe-v1.c).
The ordinary ARM64 and x86 emulator runs exit zero. In the AMD64 bounded trace,
the main thread now accepts the join result, verifies shared state
`0xcafebeef`, verifies the worker's `0x37` exit code, and closes the thread
handle. It then reaches the original fixture's `ExitProcess(0)` call.

The call is independently identified from the unchanged AMD64 PE import
table. `XOR ECX,ECX` at `0x140001162` supplies argument zero. The six-byte
indirect call at `0x140001164` uses displacement `3854` bytes:

```text
next RIP = 0x140001164 + 6 = 0x14000116a
IAT address = 0x14000116a + 3854 = 0x140002078
IAT RVA = 0x140002078 - 0x140000000 = 0x2078
```

That slot imports `KERNEL32.dll!ExitProcess`; the witness is retained in
`fixture-exit-path-29704.json`. This establishes the zero-status exit call,
not completion of native shutdown.

The separate 900-turn diagnostic still ends with a native NTDLL wait on
nonsignaled event object 45, handle `0x70`, after the thread handle has closed.
Its harness exit is diagnostic exhaustion, not guest exit. Both ordinary
AMD64 runs remain live without a terminal result. Native process shutdown is
therefore a high-impact unresolved boundary blocking the overall process
emulation goal. The wait-register correction does not claim to solve it.

The candidate diagnostic's inherited descriptive scope label incorrectly
names the baseline and a 795-turn bound. Its source, image, linked-library
hashes and actual 900-turn source are retained; the qualification explicitly
records the label correction. No metadata label is used as execution proof.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| A1 | Parked ARM64EC native services need the X0/RCX result alias; owns the result-register choice. | Compare immediate and blocked zero/nonzero returns, retain native-only registers, and execute the first resumed instruction. A pre-fix parity pass would falsify the diagnosis. | Confirmed: baseline fails; corrected regression passes. |
| A2 | The original AMD64 fixture reaches its zero-status exit call after the fix; owns the application-path result. | Verify the executed call bytes against the unchanged PE import table and its SHA-256. An error-path call or different import would falsify the claim. | Confirmed for this fixture and captured installed images. |
| A3 | Reaching `ExitProcess(0)` proves process completion. | Require an actual terminal emulator result, not a diagnostic bound or successful controller exit. | Falsified: native shutdown remains waiting. |

Affected surfaces are the shared Windows personality's parked raw-service
continuation and its tests. The same implementation is compiled and tested on
macOS, Linux, and native Windows. There is no C API layout, package ABI,
dependency default, or host-library selection change. The actual Assist
embedding must separately pin and qualify this RAX commit. GUI callbacks and
complete mixed-mode exception/APC execution remain independently qualified
surfaces, not consequences of this focused wait-return result.
