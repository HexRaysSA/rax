# Windows process emulation

`rax-user` selects the Windows personality for an `MZ` executable, or with
`--os windows`. Supported guest machine types are PE32 i386 (`0x014C`), PE32+
AMD64 (`0x8664`), and PE32+ ARM64 (`0xAA64`). The personality currently requires
a Unix host; all three guests execute through the existing software ISA cores.

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
process, memory, heap, console handle, loader, exception registration, and TLS
services. API names alone do not establish complete parameter coverage. Raw NT
service-number tables, complete CRT/GUI/network/registry personalities, general
dynamic native-DLL initialization/unloading, and host Windows support remain
incomplete. ARM64EC is a distinct ABI and is not admitted as ARM64. Nonzero
`NtContinue.TestAlert`, over-aligned static TLS, aggregate/vectorcall signatures,
ARM64 PAC/SVE/custom unwind records, and x64 unwind versions other than 1 are
explicitly outside the admitted implementation. API parameter branches must be
checked individually; available exports do not imply complete Windows coverage.

CFG enforcement and enabled mitigation-policy reporting are not implemented.
An instrumented image may retain its own no-op CFG fallback; admitting that
image does not mean CFG target validation ran. Microsoft documents compatibility
with CFG-unaware systems in [Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard).

The current stack commits the reserved stack above a fixed bottom guard; demand
stack growth is not yet modeled. x64 unwind version 1 and supported ARM64 unwind
records have explicit decoders; unsupported metadata must fail before applying
an invented context. See source and tests for admitted operations. Native
Windows differential coverage is unknown.

Exception walks retain visited registration/frame states across guest handler
continuations and stop explicitly on cycles or after 4,096 distinct states.
This ceiling and malformed-walk diagnostics are personality policies, not
measured native Windows limits or error-status equivalence. Guest record/TEB
faults remain checked; a failed table read must not become an invented leaf
frame. Failed frame restoration marks the stack invalid and follows the checked
unhandled path with the original classified exception. Faults in active
dispatcher-record/TEB access or callback setup stop with a diagnostic after
guard classification instead of recursively exhausting the host stack.
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
| A8 | Compiler-profile TLS storage, IAT, SafeSEH, cookie and unwind metadata/handler locations belong to the owning image | PE typed VA/RVA fields and explicit RAX admission policy | Restricted image acceptance, initialization and unwind reads | Foreign but mapped PEB/other-image pointers | Loader/unwind negatives; compare identical patched images under native Windows | Retained admission restriction; native cross-image acceptance unknown |
| A9 | Exception function tables are sorted by function address as the PE Format requires | PE Format .pdata section and binary-search parser | Function-table absence and lookup | Reordered or overlapping entries in otherwise bounded directories | Full-table order validation or a reordered-table regression would falsify sorted-input conformance | Retained format prerequisite; global order validation is incomplete |
| A10 | CI reachability checks consume the inspected indentation and simple shell forms | Current ci.yml/full-suite.yml commands | Workflow target-selection regression | Commented flags, harness arguments, unrelated jobs, --no-run | Matcher-negative tests; alternate workflow syntax requires re-audit | Confirmed current forms; retained syntax prerequisite |

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode/execute | Existing ISA semantics reused; Windows guest programs exercise these cores |
| CPU state | Affected: x86 compatibility FS descriptor, x64 GS, ARM64 X18, FP state and context transfer |
| Memory/MMU | Affected: checked guest access, Windows allocation/protection and executable-write epochs |
| SMIR lift/IR/interpreter/optimizer/native lowering/JIT runtime | No new operations or admission; Windows CPU path steps existing direct interpreters |
| Backend/machine/device | Unaffected: no guest kernel, board, KVM/HVF backend or devices |
| Oracle/analysis/C ABI | Unaffected: personality API is Rust and CLI; ISA analysis/layout interfaces unchanged |
| Tests/docs | Affected: library unit suites, explicit `user_windows` target, compiled PE fixtures, CLI and source references |

## Bounded findings and completion boundary

High: native Windows oracle and private modern layout validation remain unknown;
the fixture conformance tests cannot prove equivalence for all Windows binaries.
High: the unfinished DLL/CRT/NT surfaces listed above prevent declaring the full
Windows emulation objective complete. High: fixed-heap platform block ceilings
are not enforced; the precise x64 ceiling is unknown because HeapAlloc's numeric
limit and HeapCreate's architecture-dependent description differ. High: process
and thread DLL detach/FLS teardown callbacks are incomplete. High: general
dynamic-load failure rollback is incomplete: failed native modules retain their
physical mapping and raw guest LDR entries, although checked module lookup hides
them and subsequent loads preserve the original error. High: dormant critical
section/SRW helper paths do not propagate every guest-memory fault; current
built-in DLL tables do not expose these synchronization APIs, and their helpers
are outside the admitted guest API profile. Medium: admitted image
materialization still uses O(SizeOfImage) host memory; checking guest commitment
first does not establish a separate host-allocation limit. Medium: exact
Unicode case folding, ANSI code-page conversion, and verbatim path edge cases
are not a native path-resolution oracle; host-to-guest path conversion also
does not correctly resolve parent components in every input path. Medium:
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
states, bounded by 4,096. Function-table binary lookup is O(log n) in n entries;
individual unwind decoding additionally traverses its bounded metadata stream.
Global `.pdata` ordering validation is not implied by binary lookup.

Page rounding uses checked `(bytes + 4095) & !4095`; stack reservations use
checked `(bytes + 65535) & !65535`. Overflow is an error, not wrapping host
arithmetic. UNICODE_STRING contains u16 byte lengths: `2 * UTF16_units <= 65532`
bytes and NUL-inclusive maximum length `<= 65534` bytes. GDT entry 10 produces
the synthetic user selector `(10 * 8) | 3 = 0x53`; this is not a native WoW64
selector guarantee. These are exact integer calculations with no rounding-error
interval beyond the specified page/granularity ceiling.

## Verification record — 2026-09-27

Host: AArch64 macOS; Rust stable 1.98.1. The final portable combined run,
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
