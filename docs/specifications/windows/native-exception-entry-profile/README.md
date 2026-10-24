# Native Windows exception entry observations

The installed build-20348 x64 clock function executes a user-mode store. Its
split-page guard fault reaches a guest NTDLL language handler through RAX's
synthetic dispatcher. The bounded continuation at `df84a8f6` reaches
`NtRaiseException` with `STATUS_BAD_FUNCTION_TABLE` (`0xC00000FF`), flags `0x81`
and first-chance argument zero. The causal role of the synthetic callback frame
or cold process initialization remains unknown. Increasing the fixture's
instruction limit cannot implement that missing kernel boundary.

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
Independent Windows 2022/2025 x64-kernel results remain pending. Three views of the local
ARM64 kernel do not establish independent x64-kernel parity or an emulator pass.

## Assumptions and scope

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SEH1 | Native kernel exception placement is identical across supported ABIs. | Initial generic-layout hypothesis. | Native exception-frame construction. | Native ARM64, x64 and WoW64 faults. | Compare signed record/context offsets and SDK sizes. | Falsified by the twelve local observations. |
| SEH2 | A local x64 process view establishes independent x64-kernel evidence. | x64 executable on the ARM64 kernel. | Broader x64 frame admission. | Independent Windows 2022/2025 kernels. | Run this same bounded control and compare exact fields and dispatcher identities. | Falsified as independence evidence; independent layouts remain unknown. |
| SEH3 | The synthetic callback frame causes the clock unwind failure. | One synthetic frame remains when NTDLL raises bad-function-table status. | Choice of runtime repair. | Invalid image metadata or missing initialization may also cause it. | Trace actual unwind inputs and compare a measured native dispatcher entry. | Unknown; no runtime repair claimed. |
| SEH4 | Vectored-handler record pointers retain the initial kernel dispatcher placement. | This producer observes pointers supplied to the vectored handler. | Interpreting these offsets as a kernel-entry ABI. | RTL may copy or extend a context before invoking handlers. | Compare an owned child stopped at the actual dispatcher entry with decoded dispatcher arguments and these observations. | Retained; pointer identity across that boundary is unknown. |

High impact: native exception delivery and the clock guard case remain
unqualified; they block full installed-Windows userland support. Older NLS
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
