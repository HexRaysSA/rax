# Windows process emulation

`rax-user` selects the Windows personality for an `MZ` executable, or with
`--os windows`. Supported guest machine types are PE32 i386 (`0x014C`), PE32+
AMD64 (`0x8664`), and PE32+ ARM64 (`0xAA64`). The personality currently requires
a Unix host; all three guests execute through the existing software ISA cores.
The x86 guest uses the x86 core's architectural compatibility mode; this does
not implement the complete WoW64 subsystem, its thunk DLLs, or its native NT
service dispatch. The synthetic TEB selector does not establish WoW64 fidelity.

```sh
cargo run --bin rax-user --no-default-features -- program.exe argument
cargo run --bin rax-user --no-default-features -- --os windows --drive C=/guest --dll-path /guest/dll program.exe
```

The loader validates PE structure, maps sections, applies relocations, resolves
imports and forwarders, constructs synthetic system DLLs, and builds process
parameters, environment, PEB, TEB, and loader lists. Native DLL dependencies run
their TLS callbacks and `DllMain` before the executable starts. Built-in exports
occupy readable non-executable trap slots; the CPU's fetch fault enters checked
host implementations with the guest's original calling-convention state.
Unknown DLLs and imports produce explicit loader or execution failures.

`GetCommandLineA` converts the process's UTF-16 command line with the named
Windows-1252 best-fit process-code-page profile and returns one process-owned
guest buffer on repeated calls. This includes mappings that can change narrow
command-line syntax (U+FF02 to `0x22`, for example); it does not imply that
every host Windows process uses code page 1252. The retained
[GetCommandLineA contract and mapping evidence](../../specifications/windows/crt-startup/README.md)
identify the conversion profile and its unknown surrogate-pair behavior.
For at most 32,768 scanned UTF-16 code units, the single-byte profile writes
at most 32,768 encoded bytes plus one NUL byte. Initial conversion costs
O(N log 698) time and O(N) guest bytes for N code units; later calls reuse
the pointer in O(1) time without another guest allocation.

`VirtualMemory` distinguishes reserved and committed pages, allocation
granularity (65,536 bytes), page size (4,096 bytes), guard consumption,
decommit/recommit zero filling, protection, and `MEMORY_BASIC_INFORMATION`
layouts. Reserved-page metadata uses sparse state runs rather than one entry per
virtual page. The scheduler executes one guest thread at a time so
personality-controlled mapping changes cannot race an executing CPU. Embedders
must not change mappings through retained address-space clones concurrently
with execution; the underlying address-space contract forbids that operation.
Commitment is charged against
the configured guest arena, refunded on decommit/release, and checked before
allocating an image-sized host buffer. Heap reservations commit pages lazily;
failed initialization/reallocation preserves allocation metadata and old blocks.

The current DLL surface is defined by `src/user/windows/dll/`, including core
process, memory, heap, console handle, loader, exception registration, TLS,
thread/APC, synchronization, handle and synchronous file services. The
implemented service profiles are recorded in
[windows-services.md](windows-services.md),
[windows-threading.md](windows-threading.md), and
[windows-files.md](windows-files.md), with checked dynamic DLL and notification
profiles in [windows-dll-lifecycle.md](windows-dll-lifecycle.md). API names alone do not establish complete
parameter coverage. Raw NT
service-number tables, complete CRT/GUI/network/registry personalities, modern
LoadLibraryEx/search policies and host Windows support remain
incomplete. ARM64EC is a distinct ABI and is not admitted as ARM64. Nonzero
`NtContinue.TestAlert`, over-aligned static TLS, aggregate/vectorcall signatures,
ARM64 authenticated-return behavior under FEAT_PAuth, SVE/custom unwind records,
and x64 unwind versions other than 1 are explicitly outside the admitted
implementation. API parameter branches must be checked individually; available
exports do not imply complete Windows coverage.

The named MSVCRT/UCRT allocation, error-state and locale-independent memory/string
foundation, plus the stateless VCRUNTIME140 buffer/search subset, is recorded in
[windows-crt.md](windows-crt.md).
Its custom-entry import fixtures do not establish normal compiler CRT startup,
standard I/O, complete runtime export/ordinal ABI, or native CRT equivalence.

The required `_initterm` / `_initterm_e` constructor-table dependency is covered
by [windows-crt-initializers.md](windows-crt-initializers.md), including lazy,
reentrant guest callbacks and first-error termination. Ordinary compiler startup
has argument/environment dependencies covered by
[windows-crt-startup.md](windows-crt-startup.md), including true data cells,
CP1252-before-parse conversion, width transitions and wildcard expansion.
Explicit UCRT on-exit table infrastructure is implemented in
[windows-crt-onexit.md](windows-crt-onexit.md), with real guest callbacks,
independent detached generations and checked ownership/fault continuations.
Real CRT stream/descriptor storage and bounded binary/ANSI-text byte I/O are
implemented in [windows-crt-stdio.md](windows-crt-stdio.md), with genuine
per-ABI bindings, actual guest buffers, flush/close and captured I/O frontiers.
Genuine UCRT runtime-global ordinary/quick registration is implemented in
[windows-crt-global-registration.md](windows-crt-global-registration.md),
separately from DLL-local tables. Table execution and registration share a
recursive exit lock. That registration group's historical validation did not
admit termination.
Dynamic retail desktop UCRT termination is now implemented in
[windows-crt-exit.md](windows-crt-exit.md): full/quick/minimal cleanup,
executable TLS callbacks, per-thread terminate handlers, software-global
SIGABRT/SIGTERM and bounded abort controls. Normal terminating UCRT DLL detach
flushes initialized streams; forced termination does not. Synthetic HLE
filters are offered after inner guest exception search; selected handlers
run after available inner unwind handlers, with explicit diagnostic rejection
of unsupported collided-unwind protocols.
Ordinary compiler startup remains incomplete: application-type, locale, FP
and language-personality dependencies remain, alongside formatted/Unicode
stdio and separate legacy CRT registration/termination surfaces. Custom-entry
probes do not establish ordinary startup. Native opaque-table private behavior
remains unknown.

CFG enforcement and enabled mitigation-policy reporting are not implemented.
An instrumented image may retain its own no-op CFG fallback; admitting that
image does not mean CFG target validation ran. Microsoft documents compatibility
with CFG-unaware systems in [Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard).

Ordinary-thread creation retains its eager-commit stack profile. Fiber stacks
now honor initial commitment and checked guard growth, including HLE/SEH setup;
exact native private margins and growth quantum remain unknown. See
[Windows fibers/FLS](windows-fibers.md). x64 unwind version 1 and supported ARM64 unwind
records have explicit decoders; unsupported metadata must fail before applying
an invented context. The fixed ARM64 Windows CPU is ARMv8.2 without FEAT_PAuth:
`pacibsp` and `autibsp` execute as hints. Its unwinder admits full `.xdata`
`0xFC` and packed `CR=2` records, counting the PAC instruction in partial
prolog and epilog selection without claiming authenticated-return support. The
[Microsoft ARM64 unwind format](../../specifications/windows/microsoft-docs/arm64-exception-handling.md)
defines both records. A compiled PE fixture exercises exception search and
resume across full and packed PAC-marked frames. Native Windows differential
coverage is unknown.

PE32 x86 `KERNEL32!RtlUnwind` admits a non-null target registration and
continuation PC. It calls handlers on inner records with
`EXCEPTION_UNWINDING`, unlinks each only after `ExceptionContinueSearch`, and
resumes at the target PC with `ReturnValue` in EAX. It checks both target-record
words before any callback or synthetic allocation, including a page crossing.
The continuation stack pointer is the post-stdcall caller ESP in this bounded
profile; the public
[Microsoft RtlUnwind contract](../../specifications/windows/microsoft-docs/rtlunwind.md)
does not specify that private ESP formula. Exit unwind and collided unwind
remain unsupported. A compiled PE32 fixture imports the public export and
checks the inner callback, chain head, EAX, ESP, and non-returning continuation.

`RtlAddFunctionTable` and `RtlDeleteFunctionTable` admit fixed, guest-owned
function tables for x64 and ARM64. The table pointer is the deletion identity;
entries remain in guest memory and are read again during lookup, so code,
table, and unwind metadata may reside in separate mappings. `BaseAddress` is
added to 32-bit relative fields with checked arithmetic. A dynamic table can
supply a match when PE `.pdata` misses, including a PC inside a loaded image;
overlap between static and dynamic matches is rejected because native
precedence has not been established. Unsorted dynamic entries are scanned
linearly. A malformed live entry, inaccessible
guest metadata, or ambiguous dynamic match fails closed instead of creating
a leaf frame. The RAX registration profile rejects zero-length arrays,
duplicate table pointers, and registrations that would exceed 65,536 total
entries across tables; these are admission policies, not asserted native-Windows
return behavior. The public
[add](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable)
and [delete](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtldeletefunctiontable)
contracts define fixed-array registration and pointer-based deletion;
[Microsoft's function-table types](https://learn.microsoft.com/en-us/windows/win32/devnotes/function_table_type_enum)
include sorted and unsorted dynamic tables. Callback, growable and history-table
interfaces remain unsupported. Native overlap precedence and mutation semantics
are unknown.

For x64 and ARM64, the public `RtlLookupFunctionEntry` HLE consults the same
active image and fixed dynamic tables used by exception search. A hit returns
the original guest address of its architecture-specific function-table record
and writes the 64-bit image or registered base to `ImageBase`. A miss returns
NULL without changing `ImageBase`; this no-write miss behavior is an explicit
RAX profile, since the published contract does not specify that output on a
miss. Only a NULL `HistoryTable` is admitted; non-NULL history-table behavior
remains unknown and is rejected with a diagnostic. Ambiguous matches and
malformed or inaccessible live entries retain the existing fail-closed lookup
policy. The public [lookup contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry)
specifies a pointer to the matching record or NULL; the dynamic-base output is
inferred from the [registration base contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable).

Exception walks retain visited registration/frame states across guest handler
continuations and stop explicitly on cycles or after 4,096 distinct states.
This ceiling and malformed-walk diagnostics are personality policies, not
measured native Windows limits or error-status equivalence. Guest record/TEB
faults remain checked; a failed table read must not become an invented leaf
frame. Failed frame restoration marks the stack invalid and follows the checked
unhandled path with the original classified exception. Active dispatcher-record
or TEB access faults remain terminal after guard classification rather than
recursively redispatching through the broken walker.

An x64 table-search `EHANDLER` callback now uses checked guest-call setup. If
setup faults before the callback starts, the selected continuation remains in
its pseudo-dispatcher frame. RAX classifies the fault, places the nested
exception below the retained dispatcher scratch, and saves a synthetic retry
context at a private `ntdll` trap. A guest handler that repairs the fault can
resume at that exact PC and stack pointer; the trap admits the retry only while
the matching dispatcher frame still owns it. A mismatched trap PC/SP is
rejected; same-height diversion to another PC abandons the pending call,
while a lower nested-handler stack retains it. The adjacent `+8` resume
half-slot is not a retry entry. At most four callback-setup faults are admitted
cumulatively per dispatcher frame; a fifth fails with a diagnostic before
another nested dispatch. This limit and the private frontier are RAX policies,
not measured native Windows behavior. The four arguments of the ARM64
`EHANDLER` call use registers without a callback-stack write in the current
ABI path, so the x64 guard-write witness does not establish an analogous
ARM64 fault. Vectored, vectored-continue, unhandled-filter, and x86
frame-search callbacks still use unchecked setup. Native nested-handler
precedence and private retry semantics are unknown.

If a repaired dispatcher later needs to raise another exception, such as for
an invalid `EHANDLER` disposition or continuing a noncontinuable exception,
RAX fails closed with a diagnostic. It does not unwind from the private trap's
invalid `+8` half-slot or reinterpret its scratch as a guest return frame.
The precise native nested-raise context is unknown.

Function-table binary search still requires sorted `.pdata` input.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Classic x86/x64/ARM64 ABI machine types select separate guest modes; ARM64EC is outside these machine types | Microsoft PE/ABI references and `WinArch::from_machine` | CPU and scalar call ABI selection | Machine/header mismatch and reserved machine type | `user_windows` unsupported-image test and ABI register/stack unit tests | Confirmed within admitted scalar scope |
| A2 | Guest instructions are interpreted, with no additional Windows native-JIT admission | `WinCpu::run` uses bounded stepping | Instruction frontier, code invalidation and scheduling | Self-modifying memory and budget 0/1 | CPU budget and executable-write epoch tests | Confirmed by source and unit execution |
| A3 | RAX accepts its documented format-validation profile, not the unpublished Windows loader acceptance set | Microsoft PE Format, parser bounds | Image loading | Truncated headers/directories, hostile relocations | 49 PE parser tests; compare patched images under native Windows to test equivalence | Confirmed for parser suite; native equivalence unknown |
| A4 | Private PEB/TEB fields use the supplied compatibility offsets | Existing layout tables; private Windows layouts are not fully documented | Guest-visible environment and TLS | Compiled FS/GS/X18 reads and memory structure sizes | Compare private fields against a specific Windows build's symbols; run public layout probes | Retained for private fields; public MinGW probes confirmed; native symbols unknown |
| A5 | Reported Windows version is configuration, not proof of service-number compatibility | Version object and missing verified numeric service tables | Version fields and raw-syscall rejection | Direct SYSCALL/SVC for each guest | Scheduler raw-service diagnostic tests | Confirmed by explicit rejection |
| A6 | Malformed context groups, alignment, selectors, or MXCSR use a configured rejection policy, not a native NTSTATUS oracle | SetThreadContext documentation and checked ISA restoration APIs | NtContinue and continuation restoration | Late selector/FP rejection after integer changes | Context transaction tests and NtContinue unit test; native malformed-context run would falsify status equivalence | Confirmed transactionality; exact native status unknown |
| A7 | Guest mappings remain stable through memory preflight and bounded-buffer initialization/copy | One-host-thread scheduler; AddressSpace::probe populates every checked page | Heap rollback and guest-byte preservation | Fault on last page; source/destination protections differ; partial commitment exhaustion | Heap adversarial tests; concurrent mapping mutation would falsify this contract | Confirmed within serialized process execution |
| A8 | Compiler-profile TLS storage, IAT, SafeSEH, cookie and PE-owned unwind metadata/handler locations belong to the owning image; dynamically registered tables follow A14 instead | PE typed VA/RVA fields and explicit RAX admission policy | Restricted image acceptance, initialization and unwind reads | Foreign but mapped PEB/other-image pointers | Loader/unwind negatives; compare identical patched images under native Windows | Retained PE admission restriction; native cross-image acceptance unknown |
| A9 | Exception function tables are sorted by function address as the PE Format requires | PE Format .pdata section and binary-search parser | Function-table absence and lookup | Reordered or overlapping entries in otherwise bounded directories | Full-table order validation or a reordered-table regression would falsify sorted-input conformance | Retained format prerequisite; global order validation is incomplete |
| A10 | CI reachability checks consume the inspected indentation and simple shell forms | Current ci.yml/full-suite.yml commands | Workflow target-selection regression | Commented flags, harness arguments, unrelated jobs, --no-run | Matcher-negative tests; alternate workflow syntax requires re-audit | Confirmed current forms; retained syntax prerequisite |
| A11 | The process code-page profile is fixed at Windows-1252, and a successfully materialized ANSI command line remains process-owned | Retained Microsoft `GetCommandLineA`/best-fit mapping evidence and the current code-page table | Narrow command-line bytes and repeated-call pointer | Best-fit syntax changes, unmappable BMP character, failed first read/write, repeated call | Three-ABI kernel tests; a native process configured for another ACP falsifies universal-1252 interpretation | Retained fixed-ACP profile; tested within RAX |
| A12 | The Windows ARM64 guest CPU remains ARMv8.2 without FEAT_PAuth; PACIBSP/AUTIBSP are hint-space no-ops | `WinCpu::new(Arm64)` selects `A64UserCpu::new`, whose v8.2 feature set excludes PACA/PACG | Admit `0xFC` and packed `CR=2` unwind markers as counted no-ops | Exception in a partially executed PAC prolog/epilog, full and packed records | CPU-profile unit assertion and compiled-PE unwind tests; enabling PACA/PACG without propagating feature state to the unwinder falsifies this admission | Confirmed in the fixed Windows profile; future configurable PAuth unsupported |
| A13 | The admitted x86 `RtlUnwind` continuation uses post-stdcall caller ESP; the public API contract does not expose native ESP restoration details | Existing HLE x86 `Stdcall` callsite and Microsoft `RtlUnwind` TargetIp/ReturnValue contract | Guest continuation stack and EAX after unwinding inner records | Inner handler mutates context or registration links; unreadable/cross-page target; caller has nested frames | Compiled PE32 callback/ESP witness, target preflight and post-callback fault tests; native Windows context trace would falsify ESP equivalence | Retained RAX continuation profile; native ESP equivalence unknown |
| A14 | Fixed dynamic function tables retain the original guest array pointer and live entry bytes until deletion; ambiguous overlap and malformed mutation are rejected instead of selecting an undocumented native winner | Public `RtlAddFunctionTable`/`RtlDeleteFunctionTable` pointer contracts and documented sorted/unsorted table classes; native precedence is not specified | x64/ARM64 dynamic lookup, unwind provenance and deletion | Unsorted entries, duplicate pointer, code inside a PE with no static match, mutated or inaccessible entry, two matching tables | Unit and compiled-PE tests for registration, guest-owned metadata, handler continuation, deletion and failure paths; a native Windows differential for overlap/mutation would distinguish this RAX policy from native behavior | Retained RAX admission policy; native overlap/mutation behavior unknown |
| A15 | Public lookup with NULL `HistoryTable` writes the registered base for a dynamic hit, preserves caller `ImageBase` bytes on a miss, and rejects non-NULL history tables | Microsoft documents hit/miss pointer and `ImageBase` output but not miss-side effects; `RtlAddFunctionTable` defines the dynamic RVA base; no verified non-NULL history-table layout is available | x64/ARM64 `RtlLookupFunctionEntry` HLE and compiled lookup witnesses | Static versus dynamic hit; deleted-table miss with sentinel; invalid output pointer; non-NULL history table; overlapping tables | Unit and compiled-PE lookup tests establish the RAX profile; a native Windows differential with sentinel outputs and a history table would falsify claimed native equivalence | Retained RAX profile; native miss-side effects and history-table behavior unknown |
| A16 | A repairable x64 `EHANDLER` setup fault may resume a retained callback only at the private retry PC and its saved scratch SP; four setup faults per dispatcher frame are admitted cumulatively | Checked `Flow::CallChecked` table search, dispatcher frame ownership and retry trap; no verified native private-frontier or retry-limit contract | Nested fault dispatch, exact continuation identity, abandonment and bounded rearm behavior | One-shot and repeatedly rearmed guards; fresh trap, `+8` half-slot, changed PC/SP, nested handler declining the fault | `x64_ehandler_callback_guard_fault_veh_repair_preserves_selected_handler`, `x64_rearmed_dispatcher_callback_guard_faults_stop_before_fifth_nested_dispatch`, `x64_dispatcher_retry_is_abandoned_when_nested_veh_changes_context_pc_or_sp`, and exact-frontier bridge tests; native Windows context trace would test equivalence | Retained RAX policy; native retry frontier, limit and nested precedence unknown |
| A17 | The current ARM64 four-argument `EHANDLER` setup uses register arguments and performs no guest callback-stack write | `call_guest_on` ARM64 argument branch and four-argument table-search call | Reachability of the x64 guard-write regression on ARM64 | Protect the would-be callback stack; add more than eight arguments or a checked stack allocation | `arm64_four_register_callback_args_need_no_stack_write`; an added stack store for the four-argument call would falsify this bounded claim | Confirmed for the current four-argument path; other ARM64 callback faults remain possible |
| A18 | A post-repair pseudo-dispatcher `Flow::Raise` cannot safely use the generic export `+8` frontier as a guest nested-raise context | The private retry slot has no resume half-slot or guest return frame; no verified native context rule | Invalid-disposition and noncontinuable-continuation handling after repair | Return both invalid and noncontinuable dispositions after a repaired callback; attempt outer VEH catch | `x64_repaired_dispatcher_rejects_unsupported_ehandler_raise_without_scratch_search`; a native context trace could establish a different supported continuation | Retained fail-closed RAX policy; native nested-raise context unknown |

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode/execute | Unchanged by dispatcher retry; existing ISA semantics are reused |
| CPU state | Synthetic retry PC/SP use the existing `RegContext` transfer; no CPU-state representation change in this group |
| Memory/MMU | Existing checked guest access and guard classification handle callback setup faults; no mapping model change in this group |
| Windows loader/traps/scheduler | Affected: one private `ntdll` trap slot, exact-PC trap lookup and scheduler routing; no new export |
| Windows HLE/SEH | Affected: retained frame retry/count, exact nested-search bridge and checked table-search `EHANDLER` call |
| SMIR lift/IR/interpreter/optimizer/native lowering/JIT runtime | Unchanged: Windows CPU path steps existing direct interpreters |
| Backend/machine/device | Unaffected: no guest kernel, board, KVM/HVF backend or devices |
| Oracle/analysis/C ABI | Unchanged: no ISA analysis or C ABI surface change |
| Tests/docs | Affected: focused HLE/SEH unit tests and this architecture profile; no new compiled PE fixture in this group |

## Bounded findings and completion boundary

High: native Windows oracle and private modern layout validation remain unknown;
the fixture conformance tests cannot prove equivalence for all Windows binaries.
High: the unfinished DLL/CRT/NT surfaces listed above prevent declaring the full
Windows emulation objective complete. High: fixed-heap platform block ceilings
are not enforced; the precise x64 ceiling is unknown because HeapAlloc's numeric
limit and HeapCreate's architecture-dependent description differ. High: native
FLS callback ordering/reentrancy, mixed-flag FP state and private fiber teardown
remain unknown; restricted profiles are recorded in the fiber feature record.
Dynamic-load rollback and DLL
notifications now have the bounded, tested profile described in the lifecycle
record; native callback ordering/exception containment and private-allocation
generation identity remain unknown or restricted. High: host filesystem
check/unlink is not an atomic Windows namespace transaction against external
mutation. High: synchronous host console reads can block the sole guest
scheduler thread. High: x86 exit/collided unwinds remain unsupported;
dynamic callback/growable function tables, native dynamic-overlap precedence,
and non-NULL `RtlLookupFunctionEntry` history tables are not implemented. High: ARM64
authenticated-return handling remains unsupported if a PAuth-enabled CPU
profile is introduced. High: the internal x64/ARM64 `RtlUnwindEx` termination
walk uses an unchecked guest-handler continuation and does not validate the
returned disposition; it is not a guest export or Add/Delete call path today
and must be hardened before exposure. High: x64/ARM64 exception-search
`EHANDLER` callbacks now retain a checked setup continuation, but VEH/VCH and
unhandled-filter callbacks and x86 frame search remain unchecked. A fault in
those callback setup paths can still lose a repairable continuation. Native
nested-dispatch precedence and private retry behavior remain unknown.
High: a repaired dispatcher that subsequently needs `Flow::Raise` halts
emulation with a diagnostic. Guest handling of that nested exception is not
admitted; its native context is unknown.
High: `SehState` is public and adding its private dynamic-table field can
break external struct-literal construction;
no tracked consumer constructs it directly, while external usage is unknown.
Medium: public `hle::Frame` gained a private-policy retry counter field; no
tracked external struct-literal consumer was found, but external source
compatibility is unknown.
Medium: admitted image materialization still uses O(SizeOfImage) host memory;
checking guest commitment
first does not establish a separate host-allocation limit. Medium: dynamic
registration scans live guest entries on every unwind lookup; its aggregate
65,536-entry ceiling bounds but does not eliminate O(d) per-frame work.
Medium: exact Unicode case folding, ANSI code-page conversion, and verbatim path edge cases
are not a native path-resolution oracle. Host-to-guest parent components now
normalize lexically; this does not establish symlink-resolution equivalence. Medium:
interpreter-only stepping limits
throughput; performance is unmeasured. These findings do not prevent validating
the PE, ABI, virtual-memory and startup groups independently.

Run `cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1`
for the compiled PE integration target. Run the complete library target for
memory, ABI, scheduler and unwind unit coverage. Fixture provenance is in
`tests/fixtures/user/windows/manifest.toml`; public structure probes are under
`tests/fixtures/user/windows/layout/`; primary source copies and content hashes
are under `docs/specifications/windows/`.

## Algorithm and arithmetic bounds

Virtual reservations use O(r) metadata for r state/protection boundaries, not
O(reserved_bytes / 4096) pages. Heap best-fit indexes cost O(log b) for b free
blocks, with O(s) segment checks for s segments. Zero/copy work is O(n) for n
bytes and uses a 4096-byte temporary buffer. Guest-memory preflight can populate
resident pages before failing; rollback claims concern allocations, commitment,
indexes, and old guest bytes, not identical host frame residency.

Exception-walk state tracking costs O(f log f) time and O(f) space for f visited
states, bounded by 4,096. PE function-table binary lookup is O(log n) in n
entries. Dynamic registration validates O(k) live entries for a new k-entry
table. Lookup scans O(d) live entries and uses O(1) additional space for d
registered entries; all tables together admit at most 65,536 entries. Deletion
searches O(t) registered table pointers for t tables; table descriptors occupy
O(t) process memory.
Individual unwind decoding additionally traverses its bounded metadata stream.
Global `.pdata` ordering validation is not implied by binary lookup.

Page rounding uses checked `(bytes + 4095) & !4095`; stack reservations use
checked `(bytes + 65535) & !65535`. Overflow is an error, not wrapping host
arithmetic. UNICODE_STRING contains u16 byte lengths: `2 * UTF16_units <= 65532`
bytes and NUL-inclusive maximum length `<= 65534` bytes. GDT entry 10 produces
the synthetic user selector `(10 * 8) | 3 = 0x53`; this is not a native WoW64
selector guarantee. These are exact integer calculations with no rounding-error
interval beyond the specified page/granularity ceiling.

## Initial core verification record — 2026-09-27

Host: AArch64 macOS; Rust stable 1.98.1. The initial core group's combined run
(semantic commit 77e09436),
`cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=4 --quiet`,
passed 6,403 library tests, all 25 Windows integration tests, and all 10 CI
contract tests. The library
ignored two optional microkernel tests; no Windows integration test was ignored
or filtered. A separate final serial Windows integration run passed all 25.
The library includes 131 Windows unit tests and 49 PE parser tests.

Linux regression passed 36 tests and ignored its Docker oracle test, which was
not executed. This run preceded the final Windows-only loader/context changes;
it does not establish native Linux or Windows oracle execution. Workspace
all-target checks were run with `--locked --no-default-features`, both without
additional features and with `--features x86_64-suite,smir-jit`. Compilation
does not establish runtime JIT, KVM, or HVF coverage.

Public-header compile probes passed 44 x86, 54 x64, and 35 ARM64 layout
assertions, plus 27 KUSER_SHARED_DATA assertions each for x86 and x64. These
were supplemented by three x64 and four ARM64 DISPATCHER_CONTEXT assertions.
All probes
used the recorded MinGW-w64 headers, not a native Windows SDK or private symbol
oracle. All 205 declared u32 NTSTATUS/Win32 constants matched the installed
MinGW-w64 headers. All 26 retained specification/header SHA-256 values matched
their provenance manifest. `cargo fmt --all --check` passed.

## Service-group verification record — 2026-09-27

The service group adds thread/APC/object waits, address-keyed synchronization,
handle duplication/flags and synchronous files for all three guest ABIs.
The frozen combined tree passed 6,454 library tests (two optional microkernel
tests ignored), all 30 Windows integration tests and all 10 CI contract tests.
The library registry contains 182 Windows unit tests. No Windows integration
test was ignored or filtered; a separate serial run also passed all 30 tests.
Three compiled service PE fixtures each executed at scheduler slices of 1 and
4,096 instructions; all six runs passed. Both workspace all-target
configurations above passed again for this group. All 58 retained
service-reference entries and all service fixture hashes passed.
Native Windows differential execution remains unknown. Exact commands, the
service Assumption Register, change-surface map, bounded findings and Quality
Gates are in [Windows handle/service integration](windows-services.md).

## DLL-lifecycle verification record — 2026-09-27

The DLL-lifecycle group adds checked native loading, initialization, forwarding,
failed-attach rollback/retry, counted/pinned module handles, unload, static TLS
publication and normal-versus-forced termination for all three guest ABIs.
The frozen portable combined run passed 6,490 library tests, all 41 Windows
integration tests and all 10 CI contract tests. The feature-enabled library run
passed 8,662 tests. Each library run ignored two optional microkernel tests;
neither filtered tests. The library registry contains 218 Windows units. A
separate serial Windows integration run passed all 41 tests, with none ignored
or filtered. Nine lifecycle CLI cases executed at two scheduler slices, giving
18 actual guest runs. All 81 retained service-reference entries and lifecycle
fixture hashes passed. Both workspace all-target builds, Clippy and formatting
passed; the doctest command executed zero tests and ignored five.
Native Windows lifecycle equivalence remains unknown. Exact commands, the
reconciled register, callback/ownership profiles, full change-surface map,
bounded findings and Quality Gates are in
[Windows DLL lifecycle integration](windows-dll-lifecycle.md).

## Fiber/FLS verification record — 2026-09-27

The fiber group adds conversion, creation, switching, synchronized migration,
deletion and FLS callbacks for all three guest ABIs. Fiber stacks honor initial
commitment, controlled guard growth and an exhausted emergency dispatch page;
ordinary-thread creation retains eager commitment. The frozen portable library
passed 6,517 tests and the feature-enabled library passed 8,689. Each ignored
two optional microkernel tests and filtered none. The library includes 245
Windows units. All 66 Windows integration tests and 10 CI contract tests passed
without skips/filters; the final serial Windows run also passed all 66.
The independent fiber graph executed 48 actual PE cases across three ABIs and
two slices. Both all-target workspace builds, Clippy and formatting passed;
doctests executed zero cases and ignored five. All 113 registered service-reference
entries and 35 fiber fixture checks passed. The observed emergency-page reversal
failed before restoration. Native Windows execution, exact private state and
callback ordering remain unknown; the full Windows objective is not complete.
Commands, seven-field F1–F9 register, affected/unaffected execution planes,
bounded findings, ownership and Quality Gates are in
[Windows fiber/FLS integration](windows-fibers.md).

## Dynamic unwind-table verification record — 2026-09-28

The fixed-table group registers guest-owned x64 and ARM64 unwind records with
`RtlAddFunctionTable`, consults them during exception search, and removes them
by original pointer with `RtlDeleteFunctionTable`. The final portable command,
`cargo +stable test --locked --no-default-features --lib --test user_windows -- --test-threads=4 --quiet`,
passed 7,256 library tests (two optional microkernel cases ignored) and all
536 Windows integration tests; no tests were filtered. Seven focused dynamic
unit tests and four compiled-PE integration tests passed; two of those
integration tests executed each guest at slices of 1 and 4,096 instructions.
A negative control that
suppressed dynamic lookup left the two fixture-identity tests green but made
both guest-execution tests fail; the source was restored byte-for-byte before
the final green run. The feature-enabled workspace all-target check and all
536 feature-enabled Windows integration tests passed with
`--no-default-features --features x86_64-suite,smir-jit`; formatting and
fixture-script syntax checks passed. These are software-interpreter runs on
an AArch64 macOS host, not native Windows or native JIT equivalence evidence.

## Public function-table lookup verification record — 2026-09-28

The x64/ARM64 `RtlLookupFunctionEntry` HLE returns the original guest record
pointer and writes the 8-byte base on a hit. Five focused units passed after
an export-absent negative control failed all five. They cover image and
dynamic entries, Add/Delete transitions, a cross-page atomic output fault,
non-NULL history-table rejection, and x86 export exclusion. The x64 and ARM64
compiled fixtures each exercise misses before registration and after deletion,
and exact record/base output while registered; all four fixture tests passed,
including guest execution at slices of 1 and 4,096 instructions. Source,
binary, import and unwind-metadata provenance checks passed.

The final portable run passed 7,272 library tests (two optional microkernel
cases ignored) and 536 Windows integration tests, with no tests filtered. The
feature-enabled workspace all-target check and all 536 feature-enabled Windows
integration tests passed with `--no-default-features --features
x86_64-suite,smir-jit`; formatting, fixture-script syntax and diff checks
passed. These tests establish the documented NULL-history-table/RAX miss-output
profile, not non-NULL history-table support or native Windows equivalence.

## Checked EHANDLER callback-setup verification record — 2026-09-28

The x64 one-shot-guard witness failed on the prior dispatcher path: one
filtered test ran and the selected callback was lost after the setup fault.
After the checked-call change, the focused retry suite passed 14 tests,
including nested `ContinueSearch`, exact private-frontier admission, context
abandonment, repeated guard rearming, persistent protection failure and the
ARM64 no-stack-write control. A separate post-repair invalid-disposition
negative control failed before the fail-closed guard; its two disposition
cases passed afterward. The 15 focused synthetic-SEH tests and the scheduler
private-trap fetch test passed.

The final portable run passed 7,282 library tests (two optional microkernel
cases ignored) and all 536 Windows integration tests, with none filtered. The
feature-enabled workspace all-target check and all 536 feature-enabled Windows
integration tests passed with `--no-default-features --features
x86_64-suite,smir-jit`; formatting and diff checks passed. These are
software-interpreter tests on an AArch64 macOS host. They do not establish
native Windows nested-exception ordering, status, or context equivalence.
