# Native Windows clock fault profiles

The installed x64 `NtQuerySystemTime` export on build 20348 jumps to a user
routine that reads `KUSER_SHARED_DATA.SystemTime` and stores it through the
caller pointer. Build 29683's selected ARM64, x64 and x86 exports execute system
calls. Their output-pointer validation cannot be assumed identical. This control
measures the native contract before changing the runtime or installed-leaf tests.

Run on an x64 Windows kernel with Visual Studio C++ tools installed:

```text
python docs/specifications/windows/native-clock-profile/run-v3.py
```

The default architectures are x64 and x86. A native ARM64 host can additionally
select `--architectures arm64 x64 x86`. The optional `--environment` names an
existing private compiler-environment snapshot; its values are not logged.
Both routes select the installed developer command and validate the actual
compiler output's PE machine before execution. Compiler temporaries, objects,
executables and intermediate directories remain inside this worktree and are
removed after each completed architecture. Source, compiler and pre/post-run
executable hashes bind each observation. The source digest is rechecked at exit.

`native-clock-profile-v1.cpp` runs 16 bounded own-process cases. Each owns six
4,096-byte scratch pages, initialized to `0xA5`, with ordinary writable,
readonly, inaccessible and guarded regions. It tests aligned/unaligned output,
NULL, address one, the top pointer value, readonly/noaccess output, split stores
and guard/alignment priority. Every scratch allocation is explicitly released.
Only ordinary writable pages are read after the query, so observation cannot
consume a guard. Reported writes and fault addresses are scratch-relative.

Each case distinguishes a returned NTSTATUS from a caller SEH exception and
records guard protection, changed bytes, last-error and last-status. Valid
native clock samples bracket each call in FILETIME ticks of 100 ns since
1601-01-01 UTC. These are native NT-clock samples, not the precise Win32 clock.
The producer also reports the selected NTDLL's PE machine, export RVA and first
48 bytes. No host address, token, process memory outside these fixed inputs,
guest operand or callback is emitted or forwarded to a native service.

The driver validates complete captures and successful producer cleanup; it does
not assert that different Windows builds must return identical service statuses.
`windows-clock-profile.yml` runs the control independently on Windows 2022 and
2025 x64 runners, including their WoW64 views. It needs no Rust compilation, so
native measurements remain available separately from emulator regression jobs.

## Recorded local qualification

The first controller failed before compilation: Python's argument-vector
quoting inserted literal escaped quotes into the developer-command path. Its
source and failed record remain preserved. A fresh version passes the exact
Windows command line directly to `cmd.exe`, disables AutoRun/delayed expansion,
keeps captured environment output private and completes all three architectures.
The developer command changes only its child process environment.
The next hosted attempt exposed a case-sensitive dictionary lookup after copying
Windows environment variables. Version 3 normalizes inherited and snapshot keys
before selecting `PROGRAMFILES(X86)` or the compiler directory. Version 2 is
retained as the executed historical producer; the workflow selects version 3.

All three views run on one ARM64 kernel, build 29683. They are not independent
x64-kernel measurements. Each has 16 returned calls, zero caller exceptions,
unchanged seeded last-error and unchanged sampled last-status. Representative
statuses are identical in those three views:

| Cases | NTSTATUS | Ordinary writable output | Guard effect |
| --- | --- | --- | --- |
| Aligned 8/4-byte outputs and last valid 8 bytes | `00000000` | Clock value written | None |
| Unaligned 1/2/3, address one, top value, split readonly at +4095 | `80000002` | Unchanged | None |
| NULL, readonly, noaccess, split readonly at +4092 | `C0000005` | Unchanged | None |
| Guarded output and four-byte split into guard | `80000001` | Unchanged | Selected guard clears to `PAGE_READWRITE` |
| Unaligned guarded output | `80000002` | Unchanged | Guard retained |

These 48 calls are native observations, not 48 emulator regression passes.
The captured x64-kernel build-20348 jump/body and zero guest output explain
the missing shared-time input. Subsequent controls at `4b1e7059` complete
32 calls per hosted kernel across x64 and WoW64:
[build 20348](https://github.com/HexRaysSA/rax/actions/runs/40088814997/job/120857097948)
and [build 26100](https://github.com/HexRaysSA/rax/actions/runs/40088814997/job/120857098210).
Both accept ordinary output pointers at offsets 1, 2 and 3. Readonly and
inaccessible outputs return `C0000005`; guarded outputs, including the
unaligned guarded case, return `80000001` and clear the touched guard.
Failed calls leave ordinary writable scratch bytes unchanged. All 64 calls
return NTSTATUS without caller SEH and preserve last-error/last-status.
These two x64 kernels are independent of the local ARM64 kernel. Their
differences do not isolate build, architecture or thunk shape as a universal
cause. The measurements establish the selected profiles.

The producer inspects a fixed 8,192 ordinary scratch bytes per case, with at most
16 cases per architecture; time and space are bounded constants. Compiler and
OS query costs are external. Public output is bounded by the fixed producer;
the driver rejects captures exceeding 262,144 characters.

## Runtime publication

The Windows personality now owns the `SystemTime` snapshot rather than leaving
the field zero for installed code that reads it directly. Startup marks the
original readonly 4,096-byte KUSER mapping with a Windows-only VMA flag.
Guest allocation/section APIs do not set that flag. Publication verifies the
mapping's complete extent and ownership; unmapping/replacement stops updates
instead of redirecting writes into another guest mapping. No diagnostic name
is used as an ownership credential.

The CPU publishes the 12-byte `KSYSTEM_TIME` before the first instruction and
at intervals of at most 1,024 guest instructions. Its layout is the low DWORD,
first high DWORD and duplicate high DWORD. The cooperative guest thread writes
the complete snapshot between instructions. No host updater races guest
memory. A long CPU run can observe changes without returning to the scheduler;
the instruction bound is not a host-time precision guarantee.

The AArch64 adapter's observation hook preserves its existing run path,
including exact budgets, zero-instruction runs, synchronous exits, early
WFI/WFE yields and exclusive-monitor lifetime. Other personalities use the
default no-op observation. The x86 Windows loop invokes the same publisher.
Raw CPU address spaces without the owned KUSER mapping remain untouched.

On Windows the publisher samples the native NT clock into an aligned private
`LARGE_INTEGER`; other hosts retain their existing wall-clock conversion.
Installed syscall handling uses that NT domain. Its output alignment is
acquired with four fixed private scratch queries at offsets 1, 2, 3 and 4,
checking status, exact output extent and untouched surrounding bytes. Only the
measured byte-aligned or ULONG-aligned patterns are admitted. The result is
cached for the host process. Guest pointers, names, values and protections
never enter these native calls. Built-in replay retains its previous precise
clock and four-byte-alignment contract. Generic host clocks and Win32 time
services are unchanged.

The regression guest reads a baseline and spins until a subsequent shared-page
read differs, within one CPU invocation. A startup-only or once-per-run
snapshot cannot satisfy it. Additional checks cover the complete 12-byte store,
unchanged adjacent bytes, guest write denial, replacement mapping lifetime,
instruction/error boundaries, wait hints and reservations. The installed-leaf
test independently samples native NT time and unaligned output behavior;
the existing 820-call captured replay remains unchanged. The service decoder
does not follow jumping exports or acquire a broader identity policy.

For `n` guest instruction attempts across `r` nonempty CPU invocations and
`m` VMAs, publication performs
`O((r + floor(n / 1024)) * log(m))` mapping lookup work plus native clock-query
cost; the additional instruction dispatch cost is `O(n)`. Only one fixed page can
intersect the checked range, so auxiliary publication storage is bounded.
Native profile acquisition uses four 24-byte scratch buffers sequentially.

## Assumptions and boundaries

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CLKF1 | Different selected clock paths can have different output alignment. | Native 20348/26100 accept unaligned outputs; 29683 rejects them. Build and kernel architecture are confounded. | Installed profile acquisition and test expectations. | Another build, kernel or thunk. | Repeat all sixteen native cases and compare exact statuses, guards and writes. | Confirmed differences; a universal cause is unknown |
| CLKF2 | Local ARM64/x64/x86 instruction views establish independent kernel parity. | All report build 29683 on one ARM64 VM. | Independent x64-kernel claims. | Hosted Windows 2022/2025 x64 controls. | Compare actual kernel builds, selected images and outcomes. | Falsified; local scope is one kernel |
| CLKF3 | The loaded host NT clock's output profile remains stable during the process. | Fixed native acquisition and repeated independent controls. | Cached byte/ULONG alignment. | Changed native DLL behavior or partial scratch writes. | Repeated owned-buffer observations disagree, or statuses/extents leave the admitted patterns. | Retained for the selected host; unexpected acquisition fails explicitly |
| CLKF4 | The selected guest syscall view has the acquired host-native output alignment. | All three 29683 views agree; both hosted x64/WoW64 pairs agree on 20348 and 26100. | Installed syscall alignment, especially WoW64. | Different guest thunk or kernel build. | Run the independent native matrix in that executable ABI and compare with the host-native profile. | Confirmed for the recorded views; broader equivalence unknown |
| CLKF5 | Mapping changes are serialized with Windows guest execution. | `WindowsProcess::run`, `run_slice` and `state` already require this for retained address-space clones. | Ownership check followed by shared-page publication. | A retained clone replaces the page during execution. | Audit callers for concurrent mapping mutation; such a caller violates the existing address-space execution contract. | Confirmed contract; concurrent host remapping is outside it |
| CLKF6 | Thirty-two CPU slices of at most 64 instructions suffice for every installed clock call. | Local 29683 syscall leaves return within that fixture bound. | Installed-function return classification. | User-mode implementation and exception dispatch on another build. | Capture the call stage, module-relative PCs, stop/outcome kinds, frame depth, stack delta and entry alignment through the unchanged bound. | Falsified by the hosted 20348 x64 split-store guard call; finite unwind versus loop remains unknown |

At `73fbca13`, the [hosted Windows 2022 clock step](https://github.com/HexRaysSA/rax/actions/runs/40096712922/job/120880390804)
passes both shared-page tests. Its next filter has five passed tests and one
installed-function failure at the helper's bounded-return assertion. The
original message does not identify which of its three argument cases failed.
Diagnostics now retain at most 32 execution observations and name each case.
PCs are module-relative; stack values are deltas and alignment residues.
Runtime code, the execution bound and status/guard/last-error assertions are
unchanged. A longer budget requires evidence of the actual control-flow cause.

At `2e52a54f`, the [instrumented x64 job](https://github.com/HexRaysSA/rax/actions/runs/40099263819/job/120887946589)
identifies `split-guard4`, after the aligned call passes. The store faults in
the installed user-mode clock body, then one exception-dispatch frame remains
active through all 32 slices. Repeated PCs and stack deltas alone do not prove
a loop. The follow-up probe therefore continues a failed call for at most 512
additional slices of 64 instructions, retaining at most 64 diagnostic records.
It distinguishes an internal callback return from the outer function's return,
reports selected NTDLL service identities and bounded instruction bytes, and
retains the original failed verdict even if the continuation completes. No
production code, accepted execution limit or semantic assertion is changed.

High impact: native valid-call success alone does not qualify NLS fault/alias
semantics or admit another NLS profile. Other shared timing fields, older NLS
profiles, DPI/GUI work and full userland completion remain unfinished. The
Windows native producer requires Windows NT and MSVC SEH; the driver rejects
other operating systems. Runtime publication uses the existing Rust modules on
all three hosts. No platform skip or availability stub is added. Earlier
producer qualification replayed the control over 14 unrelated
ISA/HVF commits ending at `0106a4d5336478a25b274057029292c3ec08e63c`.
Its native producer/driver bytes remain identical; those observations do not
qualify the combined Rust/product frame. Earlier compiled/runtime evidence
retains its original revision, and the new parent requires separate gates.

Microsoft documents the function's FILETIME units and NTSTATUS interface in
[NtQuerySystemTime](https://learn.microsoft.com/en-us/windows/desktop/api/Winternl/nf-winternl-ntquerysystemtime)
and the guard's one-shot behavior in
[Creating Guard Pages](https://learn.microsoft.com/windows/win32/memory/creating-guard-pages).
The precise alignment, exception and partial-write results here are native
observations bound to the selected build and instructions.
