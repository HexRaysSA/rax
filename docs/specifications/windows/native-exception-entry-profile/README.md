# Native Windows exception entry observations

The installed build-20348 x64 clock function executes a user-mode store. Its
split-page guard fault reaches a guest NTDLL language handler through RAX's
synthetic dispatcher. The bounded continuation at `df84a8f6` reaches
`NtRaiseException` with `STATUS_BAD_FUNCTION_TABLE` (`0xC00000FF`), flags `0x81`
and first-chance argument zero. The causal role of the synthetic callback frame
or cold process initialization remains unknown. Increasing the fixture's
instruction limit cannot implement that missing kernel boundary. Upstream
`a7aa0089` now includes `NtRaiseException` and a conditional x64 frame-chain
anchor; the observations below retain their original source attribution.

This independent control records native exception-record/context placement
before constructing a native kernel-to-NTDLL frame. It does not change RAX
runtime code, service admission, execution budgets, public C API 1.15.0, the
Assist private ABI or the original clock test's failed verdict.

```text
python docs/specifications/windows/native-exception-entry-profile/run-v2.py
```

The default compiler ABIs are x64 and x86. On ARM64 Windows, select
`--architectures arm64 x64 x86`. `--environment` accepts an existing private
Visual Studio environment snapshot. Its values are never logged. The driver
otherwise locates Visual Studio and selects the native compiler explicitly.
Source, compiler and pre/post-execution executable hashes bind each view.
The PE machine must match the requested compiler ABI. All objects, executables
and temporaries remain inside this worktree and are removed after each view.
The entry point rejects non-Windows hosts; it is an NT control, separate from
the portable Rust implementations and Unix configuration gates.

Each view runs four bounded hardware-fault cases against its own 4,096-byte
allocation: inaccessible read, readonly write, guarded read and guarded write.
A process-local vectored handler copies scalar metadata and returns continue
search. The native frame handler catches the exception. Every scratch mapping
is released, and the vectored handler is removed before successful exit.
The output records the exception code/flags, `CONTEXT` flags and SDK sizes,
record/context offsets relative to the fault's stack pointer, alignment residues
and whether saved PC equals exception address. It does not emit exception
parameters, stack contents or register addresses. Dispatcher instruction bytes
are captured privately by the driver; only the export RVA, bounded extent and
SHA-256 are emitted, including on failure. An absent nonexported
`RtlDispatchException` is reported explicitly; hardware-fault observations still
run through the actual OS dispatcher.
The instruction hashes identify the observed loaded bytes; relocations can
change those hashes across processes or boots.
Offsets are observed at vectored-handler entry. They do not alone establish
the stack layout at the first instruction of `KiUserExceptionDispatcher`;
intermediate context copying must be checked before using them as an entry ABI.

## Local observation

The original private producer completes twelve cases on one ARM64 kernel,
Windows 10.0.29683. Every case has one vectored observation, the expected caught
access/guard status, matching PC/address and successful cleanup. The values
below are stable across the four cases in each compiler ABI. Offsets are signed
byte differences; these are measured views, not universal Windows layouts.

| View | SDK `CONTEXT` size / B | `EXCEPTION_RECORD` size / B | Record minus context / B | Context minus fault SP / B | `ContextFlags` |
| --- | --- | --- | --- | --- | --- |
| ARM64 | 912 | 152 | +944 | -1120 | `0040000F` |
| x64 | 1232 | 152 | +2688 | -2880 | `0010005B` |
| x86 | 716 | 80 | -80 | -1128 | `0001007F` |

The private producer and its raw capture remain unchanged. This public driver
adds filtered instruction identities and worktree containment. Its exact source
replays all twelve native cases with the same scalar layouts; its six projection
tests pass on macOS, Linux and Windows. The bounded filtered observations and
producer/compiler/executable identities are in [local-29683-v2.json](local-29683-v2.json).
Independent Windows 2022/2025 controls at `7efd2bb2` complete all sixteen
native fault cases, eight per kernel (builds 20348 and 26100). Their x64
record-minus-context offset is 1,264 bytes; the local x64 view on ARM64 uses
2,688 bytes. These remain VEH observations. Three views of the local ARM64
kernel do not establish independent x64-kernel dispatcher-entry parity or an
emulator pass.

## Owned-child dispatcher entry

```text
python docs/specifications/windows/native-exception-entry-profile/run-dispatch-v3.py
```

This separate producer creates its own debug child from the same executable.
After the child's controlled readonly-page write faults, the debugger verifies
its selected NTDLL file identity and dispatcher instruction prefix, installs a
temporary breakpoint, and continues the exception as unhandled by the debugger.
At the first dispatcher instruction it reads at most 8,192 stack bytes privately
and locates exactly one SDK context and exception record by the original fault's
PC, SP, code and access parameters. The breakpoint and PC are restored before
continuing. Success requires the native child handler, removed VEH, released
mapping, exit code zero and a signaled owned process handle. A bounded failure
path terminates only that owned child.

The public producer emits scalar offsets and a bounded instruction identity.
It does not save or emit raw stack bytes or register addresses. The driver
filters its private 192-byte instruction observation before public output and
rejects undeclared record fields. Seven projection/lifecycle tests run on
Windows, macOS and Linux; only Windows supplies the kernel observation. CI now
runs the exact entry control on Windows 2022 and 2025 in addition to the four
original fault cases per ABI. The `e55e70eb` run completes both independent
x64 and WoW64 entry captures on each kernel, with native child cleanup.
The x64 record offset is 1,264 bytes and context offset zero on both; the
WoW64 offsets are 8 and 88 bytes. Entry/VEH pointer identity holds in all four
captures. These controls establish frame geometry, not emulator completion.

The exact public source completes all three local views. Its paired entry and
VEH offsets satisfy, in bytes:
`entry_offset - frame_bytes == VEH_pointer - fault_SP` for both records.
The total frame extent changes with the fault SP and need not match a different
producer. These values are measurements, not universal kernel ABI constants.

| Local view | Entry SP modulo 16 / B | Context from entry SP / B | Record from entry SP / B | Captured extent / B |
| --- | --- | --- | --- | --- |
| ARM64 | 0 | 0 | 944 | 1120 |
| x64 on ARM64 | 8 | 8 | 2696 | 2880 |
| x86 on ARM64 | 12 | 88 | 8 | 1216 |

[local-dispatch-29683-v3.json](local-dispatch-29683-v3.json) binds the exact
producer, compilers, pre/post executable identities and filtered observations.
`IsWow64Process2` reports `native_machine=0xAA64` in all three views.
`GetNativeSystemInfo` reports architecture 9 in the x64 and x86 views; that API
alone therefore does not establish an independent x64 kernel on this host.
The native fault and debug-event sequence follows Microsoft's
[debugger exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
and [WaitForDebugEventEx](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugeventex)
contracts. Neither source specifies the private entry offsets.
The scan is O(B) time and O(B) space for B <= 8,192 bytes, with a 512-event,
15,000-millisecond observation limit, a bounded termination drain, and a
30-second driver process deadline. All build outputs are worktree-local and
removed after each view; no emulator execution bound changes.

## Assumptions and scope

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SEH1 | Native kernel exception placement is identical across supported ABIs. | Initial generic-layout hypothesis. | Native exception-frame construction. | Native ARM64, x64 and WoW64 faults. | Compare signed record/context offsets and SDK sizes. | Falsified by the twelve local observations. |
| SEH2 | A local x64 process view establishes independent x64-kernel evidence. | x64 executable on the ARM64 kernel. | Broader x64 frame admission. | Independent Windows 2022/2025 kernels. | Run this same bounded control and compare exact fields and dispatcher identities. | Falsified as independence evidence; independent layouts remain unknown. |
| SEH3 | The synthetic callback frame causes the clock unwind failure. | One synthetic frame remains when NTDLL raises bad-function-table status. | Choice of runtime repair. | Invalid image metadata or missing initialization may also cause it. | Trace actual unwind inputs and compare a measured native dispatcher entry. | Unknown; no runtime repair claimed. |
| SEH4 | Vectored-handler record pointers retain the initial kernel dispatcher placement. | This producer observes pointers supplied to the vectored handler. | Interpreting these offsets as a kernel-entry ABI. | RTL may copy or extend a context before invoking handlers. | Compare an owned child stopped at the actual dispatcher entry with decoded dispatcher arguments and these observations. | Confirmed for three local views and four independent x64/WoW64 captures at `e55e70eb`; broader versions remain unmeasured. |

High impact: complete native exception delivery remains unqualified and
blocks full installed-Windows userland support. The upstream conditional
x64 bridge passes its selected clock case; broader frame shapes still require
implementation and runtime proof. Older NLS
fault profiles and DPI remain separate unfinished boundaries. This changes only
the native control, portable driver, engineering record and independent CI
workflow. Plugin/UI, conversation/backend, prompts/tools, permissions, persistence,
mesh/crypto, SDK/ABI, feature defaults and packaging consume no changed contract.
Windows runtime observations are mandatory here; macOS/Linux can validate the
driver source and workflow structure but cannot supply an NT kernel observation.

The producer inspects at most two 192-byte code extents and runs four cases per
view. Driver output is limited to 65,536 captured characters. Time and storage
are bounded constants apart from compiler, OS API and process-start costs.
Microsoft documents the involved structures and language-handler contract in
[EXCEPTION_POINTERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers)
and [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64).
Those sources do not establish the private dispatcher-entry offsets measured
here.

Additional falsified assumption: `GetNativeSystemInfo` alone identifies the native
kernel architecture from an emulated process. The paired `IsWow64Process2`
measurement is now required; Microsoft's
[GetNativeSystemInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo)
and [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)
contracts define that distinction. Stress test: compare all three same-kernel
views; falsification probe: disagreement with the reported native machine.
This affects kernel attribution, not the measured per-process ABI geometry.

## Extended context and native unwind metadata

`run-dispatch-v4.py` keeps the same owned-child fault and cleanup contract while
also recording the six signed offset/length fields of `CONTEXT_EX`, first stack
word matches for the x86 argument pair, candidate machine-frame offsets, and
selected dispatcher unwind metadata. Only bounded offsets, lengths, RVA fields
and 16-bit unwind slots are published. The private stack buffer is never saved
or exported. A machine-frame candidate matches the saved PC and SP tuple; that
match alone does not establish that the dispatcher unwind codes consume it.

The exact source completes ARM64, x64 and x86 views on the local build-29683
ARM64 kernel. The x64 export is a wrapper with no unwind slots, so its metadata
cannot stand in for a native x64-kernel dispatcher. Independent Windows 2022 and
2025 metadata observations at `4c1507e8` both pass. The x64 views share a
1,424-byte allocation followed by `UWOP_PUSH_MACHFRAME`, matching the observed
saved-PC/SP tuple at entry SP + 1,424 bytes (`0x590`). Their XSTATE extents
differ; those sizes must not be treated as a universal constant. Filtered
results and source/job identities are in [hosted-dispatch-v4.json](hosted-dispatch-v4.json).
The Windows checkout converts LF to CRLF; the exact transformed source hash
matches both hosted producer records. The x86 argument pair points to the
measured record and context. `CONTEXT_EX` ranges must fit the captured extent;
XSTATE placement can vary with stack alignment. Full filtered source/compiler/
executable identities are in [local-dispatch-29683-v4.json](local-dispatch-29683-v4.json).

Four additional projection tests reject raw stack fields, oversized candidate
lists and offsets, malformed unwind-slot widths and missing absence reasons.
They pass on macOS, Linux and native Windows; the native driver also passes all
three local ABI captures. Existing projection tests remain separate and run in
the same CI job. Runtime Rust, C API 1.15.0, private Assist ABI275 and execution
limits are unchanged by this control group.

Assumption `SEH5`: the selected export's unwind metadata represents the native
kernel entry path. Basis: the breakpoint reaches that export; dependent result:
constructing a compatible native exception frame. Stress test: compare a native
x64 kernel with x64 emulation on ARM64. Falsification probe: a wrapper with no
unwind slots or different frame contract. Status: falsified as a cross-kernel
substitution; native x64 metadata must be measured independently.

High impact: native exception delivery and the unsupported portions of the
conditional x64 anchor still require direct runtime proof. This metadata control
does not resolve older NLS profiles, DPI or full process completion. Its C++
producer uses MSVC structured exception handling to observe the native ABI;
replacing that small native control with Rust would require a separate compiler/
ABI boundary. The implementation under test remains Rust.

## Second-chance delivery

`run-second-chance-v1.py` measures `NtRaiseException` with `FirstChance=FALSE`
using only its own child processes. A valid record and context terminate the
child with the supplied exception code, without entering its registered VEH or
frame handler. Unreadable record and context pointers instead return
`STATUS_ACCESS_VIOLATION`; those cases remove the handler and exit normally.
All nine cases pass across ARM64, x64 and WoW64 views of the local kernel.
The filtered measurements and compiler/executable identities are recorded in
[local-second-chance-v1.json](local-second-chance-v1.json).

The Rust service now captures both input buffers before interpreting the
one-byte `BOOLEAN`. A zero low byte terminates the process; a nonzero low byte
retains first-chance dispatch in the supplied context. The previous handler
ignored the flag and could re-enter user handlers for a second-chance raise.
Unit tests cover all three guest ABIs, unspecified upper argument bits, both
unreadable buffers and a context whose final byte crosses into an inaccessible
page. Service-level regression tests require termination even with a registered
VEH and retain the explicit first-chance context test.

The native control runs through the existing independent Windows 2022/2025
workflow. Its three result-validation tests pass on Windows, macOS and Linux.
The native C++ source uses MSVC structured exception handling; all model and
service behavior remains in Rust. A bounded cleanup retry handles the observed
short-lived Windows executable lock after child termination; it neither kills
unrelated processes nor ignores a permanent cleanup failure.

An earlier broader private prototype failed its WoW64 first-chance case with
`0xC0000409`. Inspection showed that this NTDLL `RtlCaptureContext` uses the
caller's EBP frame. A fresh producer with a real capture helper frame passes
that same first-chance case and all three other WoW64 cases. The failed producer
and its receipts remain separate evidence; no model assertion was weakened.

Assumption `SC1`: these controls have no attached debugger. Basis: ordinary
child launches and the observed process exit/handler sequence. Dependent result:
second-chance termination without debugger interception. Stress test: an
attached debugger can consume a last-chance event. Falsification probe: repeat
under an explicitly supported guest-debugger event path. Status: confirmed for
the measured no-debugger profile; guest-debugger interception is unqualified.
Microsoft documents the first/last-chance distinction in
[debugger exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling).

High impact: the complete native dispatcher entry and unsupported conditional
anchor cases still require runtime implementation and proof. Older NLS and DPI
remain separate unfinished boundaries. This second-chance correction does not
change the public C API, private Assist ABI, optional features or package layout.

Current targeted model validation for the second-chance correction:

| Host | Raise unit/service tests | Related clock tests | Result-validator tests |
| --- | --- | --- | --- |
| macOS ARM64 | 6 passed | 4 passed | 3 passed |
| Linux x64 | 6 passed | 4 passed | 3 passed |
| Windows ARM64 | 6 passed | 6 passed | 3 passed |

Each selected group has zero failures and zero ignored tests. The Windows
native API control additionally completes nine cases across three compiler ABI
views. These counts are selected checks, not whole-suite or installed Assist
qualification. The native test executable is ARM64; the model/service tests
exercise x86, x64 and ARM64 guest argument layouts. The clock slice includes
installed ARM64/WoW64 calls only on Windows. C API and shipping-product gates
remain separate evidence.

The model checks are reproducible with `cargo test --locked
--no-default-features --lib` and selectors
`user::windows::dll::native::raise::tests::`,
`native_second_chance_exception_bypasses_handlers_and_terminates`,
`native_raise_exception_`, and `system_time`, each with `--test-threads=1`.
The native control accepts `--architectures arm64 x64 x86` on ARM64 Windows.
Dependency-cache failures before compilation were retained separately; the
successful reruns use the same two Rust source hashes and restored dependency
sources.

## Native dispatcher implementation under validation

The native-library personality now constructs an exception-entry frame and
resolves `KiUserExceptionDispatcher` in the live, executable selected NTDLL
image. The built-in DLL personality retains its host-managed dispatch. The
native path publishes the complete frame after stack write preflight, then
changes only the thread's PC and SP. It does not manufacture an HLE call frame
or run the host-managed vectored-handler list before entering NTDLL.

The construction below is a legacy-context profile. Offsets and lengths are
bytes relative to the new entry SP; they do not describe every observed kernel
allocation, which can also contain XSTATE and additional padding.

| Guest ABI | Context offset | Record offset | Payload length | Entry SP modulo 16 |
| --- | ---: | ---: | ---: | ---: |
| x86 | 88 | 8 | 828 | 12 |
| native AMD64 | 0 | 1264 | 1472 | 0 |
| ARM64 | 0 | 944 | 1104 | 0 |

ARM64 leaves the interrupted thread's 16-byte reserved area above the payload.
For x86, the two entry words point to the record and context; the selected SP
residue aligns `CONTEXT.ExtendedRegisters` to 16 bytes. For AMD64, the saved
RIP, CS, EFLAGS, RSP and SS occupy five 8-byte slots starting at offset 1424.
The selected export must begin at its runtime-function entry and have the
observed unwind tail: `UWOP_ALLOC_LARGE` with 178 units of 8 bytes, followed by
`UWOP_PUSH_MACHFRAME` without an error code. The allocation is therefore
178 x 8 = 1424 bytes, followed by the 5 x 8 = 40-byte machine frame. Qualification
also requires aligned unwind data, no handler/chaining flags, no frame register
and a zero-length prolog. Preceding register restores must read the matching
legacy `CONTEXT` offsets; extra stack adjustments fail qualification. The two
version-2 epilog slots observed on both native AMD64 hosts are recognized
explicitly. Recipe checking takes O(n) time and O(n) temporary bytes for n unwind
slots, bounded by the one-byte slot count (255 slots / 510 bytes).

A wrapper, missing metadata or incompatible recipe fails explicitly before
stack publication. This prevents substituting an x64-on-ARM64 wrapper for the
independently measured native AMD64 frame. The slot meanings follow Microsoft's
[x64 exception handling specification](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64).

`CONTEXT_EX` records the legacy extent and an empty XSTATE extent. The frame
does not claim to capture XSTATE; a request carrying that flag is rejected.
Readonly stack failure leaves the CPU and frame bytes unchanged. Existing
owned-stack guard growth remains governed by the stack adapter.

The current implementation passes 60 selected SEH tests, eight native-startup
tests and 191 C API tests on both macOS ARM64 and the Linux x86-64 container.
Windows ARM64 passes 61 SEH tests, nine native-startup tests and 191 C API tests,
including the unchanged hardware-fault fixture with installed ARM64 and WoW64
libraries. The two new qualification
tests replay both independent AMD64 metadata captures and reject incompatible
headers, stack adjustments and register-save offsets. The original test source,
three PE fixtures, assertions and budgets remain unchanged.

An earlier combined-tree full macOS library run passed 8,396 tests with two
unrelated microkernel tests ignored; that historical run predates the final
metadata guard. The independent AMD64
[candidate run](https://github.com/HexRaysSA/rax/actions/runs/40591957315)
passes the whole unchanged hardware-fault test on native kernels 20348 and
26100, including installed NTDLL registration, fault delivery and context
continuation. The same run retains a separate image-owner test failure and is
not a fully passing CI run; its correction and fresh gates are recorded in
[the image-extension specification](../native-image-extension-amd64/README.md).
These are model and selected native-library results, not installed
Assist or complete process-userland qualification.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NE1 | The qualified AMD64 unwind recipe describes the constructed machine frame. | Independent build-20348/26100 entry and unwind observations. | Native AMD64 entry. | Callable wrappers, extra stack operations and changed restore offsets. | Replay captured and altered metadata; execute the original installed-NTDLL fault fixture on AMD64. | Confirmed by metadata replay and the whole original fixture on both measured AMD64 kernels. |
| NE2 | Native RTL accepts the captured legacy groups with no XSTATE payload. | The original fault fixture completes on build-29695 ARM64/WoW64 and native AMD64 builds 20348/26100 without an advertised XSTATE payload. | Legacy native dispatch and continuation. | ARM64, AMD64 and WoW64 faults. | Run the original fixture and inspect continuation/termination. | Confirmed for the measured original-fixture paths; other context profiles remain unqualified. |
| NE3 | Native NTDLL owns native vectored-handler registration. | Installed registration exports and observed hardware-fault continuation with an empty HLE handler list. | Bypassing the HLE handler list. | Registered native handlers and nested faults. | Compare actual native handler invocation and final context. | Confirmed for the measured single-fault ARM64/WoW64 cases; nested faults remain unqualified. |

High impact: wrapper-specific entry, XSTATE, older NLS, DPI and complete
Windows process execution remain outside this qualified legacy-frame profile.
They remain work for the full installed-userland objective. The implementation
changes no public C API layout, private Assist ABI, permission grant, library
selection default or package naming.

The first independent second-chance run at `3779418c` passes on Windows 2022.
Windows 2025 passes the x64 cases and the first two WoW64 cases, but its WoW64
invalid-context case fails validation. The v1 driver validates before printing
the child result, so that log cannot establish the failing exit code or output.
`run-second-chance-v2.py` retains the same native source and validator and emits
a bounded scalar failure receipt before propagating the failure. Unknown fields,
objects and excess rows are omitted. Three tests cover failure propagation,
quiet successful validation and diagnostic filtering. This adds evidence; it
does not turn the failed native observation into a passing result.
