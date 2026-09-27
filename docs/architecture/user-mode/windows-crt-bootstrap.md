# Windows UCRT startup policy and floating-point reset

Implementation group against `9bc8ccdca85a5b0c9c74a7c446c85194efdc780d`
on `user-win`. Initial tracked worktree and index are clean; pre-existing
untracked content remains user-owned. Full Windows userland remains the active
objective. This group advances real ordinary-startup dependencies, not a
substitute entry point or a claim of complete compiler startup.

## Acceptance criteria

1. Admit only verified genuine UCRT/API-set names: `_set_app_type`,
   `_query_app_type`, `_configthreadlocale`, `__setusermatherr`, `_fpreset`
   and `__pxcptinfoptrs`, with exact 32-bit scalar/pointer/void ABIs.
2. Retain runtime application policy and math-handler registration; queries
   observe the application value. Do not validate enum/pointer values that
   the pinned source/body stores unconditionally; do not invoke a math handler
   during registration or fabricate legacy named exports.
3. Implement the previous-mode locale result, thread selection bits, SDK `-1`
   global-sync disable, invalid-parameter handling and errno precedence.
   Preserve captured requests and callbacks across memory faults.
4. Expose a thread-keyed, guest-authoritative exception-pointer slot,
   initially NULL, separately from errno and _doserrno. PTD establishment
   failure for these genuine getptd-based APIs reaches actual abort.
5. Match the pinned `_fpreset` architecture bodies. x86 establishes PTD and
   snapshots its exception pointer before nonwaiting x87 initialization,
   selects the actual FLDCW operand `0x023F`, resets MXCSR on the admitted
   SSE2 profile, then updates only
   saved CONTEXT StatusWord/TagWord for the specified flags. x64 changes only
   MXCSR; ARM64 changes only FPCR/FPSR. Preserve physical/vector payloads.
6. Retain exact instruction-boundary partial completion and selected pointers
   on saved-context faults; a repair must not replay architectural reset or a
   completed store. The unretired status AND retries both read and write.
7. Verify all affected ABI/state/consumer planes, independent compiled PEs,
   preserved pre-feature failures/controls, primary receipts and broad gates.
8. Exact-path stage, identical-path `red -m --staged --run`, immediate origin
   push; no amendments, coauthorship or session-link metadata.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| B1 | SDK source 10.0.26100.0 and its identified retail desktop UCRT bodies define the selected version profile | Publisher member/EAT/scoped disassembly receipts | Startup policy, errors, architecture-specific reset | Invalid scalar bit patterns, nondefault complete FP state, alternate binding | Run identical witnesses under identified native UCRT versions | Retained; native equivalence unknown |
| B2 | Admitted x86 Windows user CPUs provide OS-enabled SSE2 and take the publisher availability>=1 path | CPUID leaf 1 EDX bit 26 is unconditionally advertised; user-mode CR4 enables OSFXSR/OSXMMEXCPT; source initialization mapping itself is unknown | MXCSR reset on the fixed admitted profile only | Compare CPUID/CR4 and poisoned MXCSR | A selected CPU lacks SSE2/OS support or identified publisher initialization contradicts the path | Confirmed current guest configuration; retained publisher-path inference; downlevel equivalence unknown |
| B3 | Existing CRT PTD identity remains thread-keyed, and synthetic private storage need not reproduce native private PTD offsets | Existing error-cell/FLS personality boundary; genuine accessor exposes a pointer object, not a public full PTD layout | Locale and exception-slot lifetime/identity | Two threads, fibers, retirement, aliased runtime imports | Native FLS/private-layout witness requires a different admitted identity | Retained; native fiber/private-layout equivalence unknown |
| B4 | Runtime application-default global-state selection is admitted | Existing CRT runtime namespace; publisher dual-state lookup bodies | Application/math/locale process state | API-set aliases, two runtime identities and reentrant callbacks | Identified application/system-isolation witness selects another state | Retained; alternate isolation unfinished |
| B5 | Single scheduler execution serializes host metadata changes | Windows process scheduler explicitly runs all guest threads on one host thread | Policy mutation and selected phase capture | Reentrant invalid handlers, volatile formals and memory repair | Concurrent unsynchronized mutation of this process state | Confirmed current scheduler; adversarial callback/retry tests pass |

## Change-surface map

| Plane | Assessment |
|---|---|
| Direct decode | Unaffected; no instruction encoding added |
| Direct execute | Existing x87 initialization is consumed through a narrow embedder helper; no opcode semantics changed |
| CPU state | Affected: exact x87 environment, MXCSR and ARM64 FPCR/FPSR transitions; raw payload preservation |
| Memory/MMU | Affected checked formals/PTD slot/saved-CONTEXT accesses; no address-space permissions or translation change |
| SMIR lift | Unaffected; no new guest instruction |
| SMIR IR | Unaffected; no new operation |
| SMIR interpreter | Unaffected; existing x87 state representation retained |
| Optimizer | Unaffected; no transform change |
| Native lowering | Unaffected; no host opcode/admission added |
| JIT runtime | Unaffected: WinCpu::run uses precise x86 interpreter stepping and the AArch64 user adapter explicitly does not use native JIT; no native admission or helper marshalling changed |
| Backend | Unaffected; Windows process personality only |
| Machine/device | Unaffected; no board or MMIO path |
| Oracle/analysis | Unaffected; no analysis schema or instruction effects change |
| C ABI | Unaffected; no C layout/enum/header change |
| Public Rust | Narrow user-x87 environment initializer added; no FpuState exposure |
| Tests/docs | All-ABI runtime tests, compiled PE receipts, registered runner and primary archive |

## Bounded findings

| Impact | Evidence / boundary | Blocks this group? |
|---|---|---|
| High | Public locale documentation omits `-1`; SDK and real GCC startup use it to disable global synchronization without changing the queried per-thread bit | No; explicit source-version contract required |
| High | General locale/NLS and math-error consumer delivery are unfinished separate dependencies | No for the actual policy/registration bodies; blocks broader locale/math compatibility claims |
| High | Hardware-signal conversion is unfinished | No for an explicit guest-supplied exception-pointer slot; no fabricated linkage to SEH's current context |
| High | Genuine C/C++ language-personality and formatted/Unicode stdio remain separate compatibility dependencies | No for this group; compiler entry/exit completion is observed separately below |
| High | SDK raw-source redistribution permission and native source-to-binary equivalence are unknown | Keep raw SDK inputs outside tracked files; retain exact receipts and selected observations |
| Medium | Native PTD/FLS fiber identity and opaque private field layout remain unknown | Preserve and label the existing thread-keyed personality |
| High | Independent private assembly controls exposed valid x86 absolute-address FLDCW failure; shared direct x87 addressing helper treats mod=00,r/m=101 as relative without checking CS.L | No for these HLE bodies; affects general x87 memory operands and is a separate ISA correction. Successful fixture control uses register-indirect FLDCW and labels that distinction |
| High | Genuine ordinary main/wmain images reach exit(0) at slice 4096 but normal exit erases initialized critical-section state before PROCESS_DETACH callbacks | No for this bootstrap group; blocks complete compiler entry/exit acceptance. Preserve the failed outcome, not a fabricated successful startup |
| High | ARM64 ordinary main/wmain at slice 1 reach a 30 s watchdog; the user CPU adapter clears its exclusive monitor at every budget yield, so LDAXR/STLXR startup acquisition never succeeds | No for fixed bootstrap witnesses; separate slice-sensitive adapter contract. Existing tests explicitly encode that run-boundary policy, so correction must distinguish a pure budget yield from actual interruption/context switch |
| Medium | Workspace all-target builds report the pre-existing engine/C API `librax.rlib` output-name collision | No; all-target compilation passes. No unrelated package or ABI rename is authorized |

## Implemented contracts and instruction boundaries

Application type is a retained 32-bit cell initialized to 0. Values 0/1/2
denote unknown/console/GUI in the selected SDK header, but the setter does not
validate or clamp arbitrary scalar bit patterns. Queries zero-extend the cell.
Math registration retains the pointer-width callback identity, including NULL
and non-executable addresses, without a PTD allocation, validation or eager
callback. Opaque publisher cookie encoding is not a public guest object here.
Reporting/NLS/math delivery consumers are not manufactured from these stores.
These conclusions depend on the selected source/body profile [B1, B4].

Locale query 0, enable 1 and disable 2 return the **previous** mode (1 enabled,
2 disabled). Enable/disable changes only own-locale bit `0x2`, retaining global
bit `0x1`. Source-version input -1 writes global policy `0xFFFFFFFF` without
changing the caller's bit. Invalid values commit errno=22 before the selected
five-argument guest invalid handler; callback errno/locale mutations survive
the signed -1 result. No handler invokes existing noncatchable fail-fast.
The x86 publisher establishes PTD before reading its stack formal; Win64
bodies capture the register formal before PTD setup. Fault tests distinguish
these orders and keep a decoded request after errno-write repair [B1, B3, B5].

Synthetic private guest cells have size `8 bytes + pointer_size`:

- x86: two 4-byte error cells + 4-byte pointer = 12 bytes.
- x64/ARM64: two 4-byte error cells + 8-byte pointer = 16 bytes.

The accessor returns `cells+8`, not the pointer value. Zeroed allocation makes
the exposed cell initially NULL; it is stable for a thread, independent across
threads/runtime namespaces, and retired with the existing PTD allocation.
This layout does not assert native private PTD offsets or native FLS identity
[B3]. Establishment OOM reaches actual SIGABRT/abort policy, including a real
registered callback and its selected forced versus normal terminal flow.
x64/ARM64 `_fpreset` neither allocates PTD nor reads this cell [B1].

The x86 reset preserves physical binary80 R0-R7 bytes, clears x87 environment,
then installs actual converter operand `0x023F = 0x003F | 0x0200 | 0x0000`
(six exception masks, 53-bit precision, nearest rounding). Intel revision 086
Vol. 1 Figure 8-6/Section 1.3.2 excludes reserved readback from an oracle;
the PE compares operative fields with mask `0x0F3F` and excludes FLDCW's
undefined C0-C3 status bits using `FSW & (0xFFFF XOR 0x4700)`:
`0xFFFF XOR 0x4700 = 0xB8FF` (16 bits). Native reserved bit 6
readback is unknown. The public helper's raw-u16 assignment is an explicit
embedder API, not a claim about all 65,536 words on physical hardware.
The selected SSE2 profile also sets MXCSR=`0x1F80` [B1, B2].

Only x86 snapshots the exposed exception pointer before reset. For non-NULL
`info`, it reads a 4-byte context pointer at `info+0x4`. A nonzero intersection
`ContextFlags & 0x00010008` selects a 4-byte status AND at context+`0x20`
followed by a 4-byte tag MOV=`0x0000FFFF` at context+`0x24`. This is ANY-bit
selection, not equality or an all-bits test. Pointer/status/tag offsets are
4/32/36 bytes, respectively. Effective addresses are
`zero_extend_u64((base_u32 + offset_u32) mod 2^32)`; accesses remain checked.
The saved control word and remaining context bytes are unchanged [B1].

Retry state follows **instructions**, not subaccesses: an unretired status AND
repeats its read and write, retaining earlier pointer/flag loads and FP reset.
After AND completes, a tag-store fault retries only that MOV. Tests invalidate
earlier pointers/flags, re-poison live FP state and change completed status
storage during repair. None of those completed effects is replayed. This
uses Intel Vol. 3A Sections 7.5-7.6 and checked AddressSpace writes that commit
no byte on a fault. Embedder-only write-without-read permissions and a low-page
mapping are explicitly test instrumentation, not native PAGE_* claims [B5].

x64 changes only MXCSR. ARM64 changes only FPCR/FPSR, retaining all V0-V31,
NZCV and integer/PC/SP state. The cross-ABI public-state tests and compiled
post-reset scalar arithmetic witnesses observe the actual resumed CPU.
Windows x86 runs precise interpreter steps; AArch64 user execution also
explicitly bypasses native JIT. Feature compilation does not imply guest
native execution coverage.

Reset/policy transitions and their retained continuation require O(1) time
and auxiliary space for fixed architectural widths. Thread-map lookup is
expected O(1), worst-case O(T) for T thread contexts. Guest private cell
storage is `(8+p)T bytes` before heap alignment/metadata, p in {4,8}; host
metadata is O(T). PTD establishment inherits existing heap/address-space
costs; no constant-time allocator or total-host-OOM guarantee is claimed.

## Primary provenance and strategic verification

The [primary index](../../specifications/windows/crt-bootstrap/sources.json)
SHA-256 is `85649f1c09783cdf8f65e7210f3beb754f5c33ec817e838922b3326f6e6eaadc`.
It has 65 records: 44 retained/reused path-and-hash inputs plus 21 metadata-only
SDK inputs. Root independently replayed 44 hash/size checks, 21 SDK receipts,
19 installed inputs, 5 exact copies, 10 observer commands and 5 tool identities;
network replay verified 36 source acquisitions and 7 publisher observations,
with zero unavailable inputs/tools. Raw proprietary SDK bytes remain excluded.
NuGet signature verification and native Windows execution remain unknown/not
performed. The [archive audit](../../specifications/windows/crt-bootstrap/README.md)
retains exact source/public-prose conflicts, aliases and all acquisition commands.

The new fixture manifest SHA-256 is
`00bed39a51a6bd864d77637ebea9a3fdfc57eedf21273e661e6e36b15f3f669f`.
Six independently compiled custom-entry PEs total 39,936 bytes, with proper
UCRTBASE versus runtime/locale/math API-set IATs. Eleven modes yield
`3 ABIs × 2 bindings × 11 modes = 66 cells`; two slices yield 132 actual guest
executions per runner pass. Two complete producer builds reproduce all 30
source/artifact hashes byte-identically. Fresh root replay of the preserved
CLI gives 108 missing-export rejections, 12 successful raw-exit controls and
12 successful private ISA-reset instrumentation controls, zero watchdogs.
Controls are not counted as genuine `_fpreset` or ordinary compiler startup.

Targeted gates: 23 new policy/FP/fault tests pass, four OS-neutral x87 helper
tests pass, and all 67 new registered integration tests pass (66 semantic cells
plus integrity), with nonzero test counts. Helper coverage includes all eight
TOP values in both x86 modes, arbitrary/special binary80 payloads, all raw-u16
control words, unrelated state preservation and direct FNINIT/FLDCW parity.
The [registered runner](../../../tests/suites/user/windows/crt_bootstrap.rs)
checks independent literal results, exact PE imports/machines/hashes, complete
baseline classifications, immutable inputs and repeatability receipts.

## Genuine ordinary-startup observations

The six existing [main/wmain sources](../../../tests/fixtures/user/windows/crt_stdio/src/ordinary.c)
and compiler-selected entry/startup objects are unchanged. At slice 4096,
new feature CLI SHA-256
`a9bfba30c9f02a6053c88772124192c722f916b3a41bf107dfe2c741f60c7b24`
advances all six past `_set_app_type`, reaches `exit(0)`, then stops with shell
status 125 and `invalid synchronization operation: uninitialized/deleted
critical section`. Independent strace shows InitializeCriticalSection had
already admitted the exact eventual failing address. Normal process exit
calls `sync::on_process_exit`, which clears SyncState before live
PROCESS_DETACH callbacks. This is a separate source-localized lifecycle defect,
not lack of a producer initialization call or a successful program completion.
At slice 1, x86/x64 reproduce that diagnostic; ARM64 main/wmain reach a 30 s
watchdog after initial critical-section setup. Source and produced instructions
localize the failure: A64UserCpu::run clears its exclusive monitor after every
budget yield, while compiler startup uses LDAXR/CBNZ/STLXR/CBNZ acquisition.
At one instruction per run, every reservation is cleared before the store
exclusive. Existing adapter tests encode that policy; this is a separate
execution-boundary contract correction, not a reason to fake lock admission.
No custom entry, fake import, forced unlock or replacement startup is used.

## Baseline and validation

Preserved pre-feature CLI: `/tmp/rax-crt-bootstrap-baseline.oolsWp/rax-user`,
SHA-256 `7823ddd8837f729dc62f2f3af02fe4bc31d65c571e0140a04cdb7c5606179612`.
It was built before this group's edits with stable, locked dependency state,
`--no-default-features --features x86_64-suite,smir-jit --bin rax-user`.
The 108 expected missing-export failures are baseline evidence, not passing
postcondition tests. The 24 successful cases are explicitly raw-exit/private
ISA instrumentation controls, not substitutes for the six genuine exports.

All completed gates below used `cargo +stable --locked`; test counts were
read from the runner summaries rather than inferred from process exit status.

| Gate | Actual result |
|---|---|
| Focused bootstrap units | 23 passed, 0 ignored |
| Public x87 helper units | 4 passed, 0 ignored |
| New compiled-PE runner | 67 passed: 66 cells plus integrity |
| Portable library (`--no-default-features`) | 6,802 passed, 2 ignored |
| Portable Windows/CI integrations | 516 and 10 passed; the final 516 were repeated after the last fixture assertion correction |
| Feature library (`x86_64-suite,smir-jit`) | 8,974 passed, 2 ignored |
| Feature Windows/CI integrations | 516 and 10 passed |
| Release-equivalent Windows units/CI integrations | 526, 516 and 10 passed with debug assertions and overflow checks disabled |
| Portable and feature workspace all-target builds | Both passed; pre-existing `librax.rlib` collision warnings are bounded above |
| Feature workspace all-target Clippy | Passed; repository lints allow warnings |
| Formatting, tracked diff check, doctests | `cargo fmt --all --check` and tracked `git diff --check` passed; doc result 0 passed, 5 explicitly ignored |

The staged diff's ordinary whitespace check identifies one trailing source
space in the retained verbatim Microsoft `_matherr` example at
`docs/specifications/windows/crt-bootstrap/microsoft/matherr.md:83`.
It is preserved to maintain the acquired primary-source byte hash; it is
not Rust code or an unreviewed formatting change. No other staged path has
a whitespace error. A check with only end-of-line blank detection disabled
passes.

The two ignored library tests are
`smir::lower::validation::tests::test_lift_lower_full_microkernel` and
`smir::lower::validation::tests::test_roundtrip_exact_bytes_microkernel`.
They were not counted as executed. Runtime cross-ABI public-state checks,
fault repair, all 132 actual PE baseline executions, byte-identical fixture
rebuilds and offline/network provenance replays passed. macOS ARM64 feature
compilation is not evidence of native KVM/HVF or x86-64-host JIT execution;
those were not claimed.

## Final self-red-team and quality gates

QG1: no normative judgment is required. QG2: B1-B5 remain explicit above;
native UCRT equivalence, alternate global-state isolation, downlevel x86 and
native PTD/FLS mapping remain bounded unknowns, not inferred pass results.
QG3: criteria 1-7 have direct source, cross-ABI test and receipt evidence;
criterion 8 is a post-artifact Git delivery operation and is not asserted by
this precommit document. QG4: scalar widths, 4/32/36-byte offsets, masks,
16-bit raw control-word handling and modulo-2^32 address arithmetic are
covered by independent boundary witnesses. QG5: the x87 undefined C0-C3
condition bits, AND read-modify-write restart and absolute-address fixture
pitfall were checked explicitly; genuine ordinary-startup failures remain
separate known defects rather than contradictory success claims. QG6:
primary Microsoft/Intel evidence, retained hashes, publisher observations
and source-version limits are recorded in the linked archive. QG7: bounded
high/medium findings above are classified without modifying adjacent
subsystems. The exact-path commit, forbidden-metadata check and origin-ref
verification must be performed after this artifact is staged.
