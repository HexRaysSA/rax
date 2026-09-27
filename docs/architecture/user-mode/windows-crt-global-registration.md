# Windows CRT runtime-global registration

Semantically grouped dependency against baseline
`06e90d4bb41e0390a877819ed41ed98e369558a3` on `user-win`. The tracked baseline
and index were clean; unrelated untracked inputs remain user-owned. The Windows
userland objective remains active and incomplete. This group implements genuine
UCRT/runtime API-set registration, not CRT termination/TLS admission.

## Acceptance criteria

1. Admit `_crt_atexit` and `_crt_at_quick_exit` with their genuine cdecl,
   pointer-argument, 32-bit C int contract across x86, x64 and ARM64. Preserve
   the distinction between actual DLL export names and producer-local wrappers.
2. Own separate ordinary/quick global queues on the CRT private guest heap,
   outside ordinary malloc ownership and explicit DLL-local tables. Implement
   NULL slots, duplicates, SDK capacity increments, allocation fallback, and
   failure-preserving publication.
3. Share recursive per-runtime exit serialization between global registration
   and explicit-table registration/execution, leaving the SDK's unlocked table
   initializer unlocked. Same-thread callbacks can register recursively;
   another thread parks until the outermost operation releases ownership.
4. Retain captured target/runtime across checked faults and blocking. Release
   typed abandoned guards without fabricated callback execution or API success.
   Raw OS exit discards global storage without reading or invoking its slots.
5. Validate source/binary/IAT receipts, independently compiled all-ABI probes,
   both scheduling slices, baseline failures, and the broad relevant gates.
6. Stage exact owned paths, run `red -m --staged --run` with those same paths,
   and immediately push the unamended commit to origin without prohibited
   authorship/session metadata.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| G1 | SDK 10.0.26100.0 application-global registry behavior is the selected UCRT comparison version | Verified publisher package and exact source receipts; real three-ABI exports | Queue algorithms and named bindings | NULL, duplicates, registration during scan, capacities over 1024 | Run identical witnesses under a pinned native UCRT | Retained version profile; native equivalence unknown |
| G2 | Application-default registrar and explicit-table registration/execution select the same recursive exit lock; initialization is unlocked | SDK calls the same selector; retained lock code uses critical sections; initializer has no lock acquisition | Cross-thread wait and same-thread recursion | Nested independent table drains, independent initialization while worker registration parks | Native multi-thread witness or genuine MSVC internal_shared.h selector inspection | Retained; selector body/application-system isolation unknown |
| G3 | Personality-controlled memory changes cannot interleave one host operation without a guest callback | Single-threaded scheduler/address-space contract | Checked copy/store publication | Read-only/guard slots, source-copy faults, formal clobber | Concurrent retained AddressSpace mutation would falsify this contract | Confirmed for admitted serialized execution |
| G4 | Callers do not raw-free or destroy CRT-private callback buffers | Global registry is private, not caller malloc storage | Allocation identity and cleanup | Raw HeapFree, HeapDestroy, equal-address reuse | Allocator allocation-generation probe | Retained ownership precondition; non-ABA violations detected, exact address/size ABA unknown |
| G5 | Native SEH recovery from private registry faults and nested reset arithmetic are not established | SDK uses encoded private pointers and raw pointer arithmetic; no native recording | Checked recovery/reset profiles, not native status claims | Queue mutation after selected-slot fault, nested cleanup/reset | Pinned native private-fault/nested-reset probe | Retained explicit fail-closed/ownership-safe profiles |

Dependent claims are restricted by these registers. C int success is zero and
failure is `0xFFFFFFFF` in the 32-bit return field. This group does not claim
native errno values for allocation failures; existing error cells and LastError
are preserved by successful registration. Native Windows oracle coverage is
unknown, not inferred from a successful emulator test.

## Storage and algorithms

For guest pointer width P = 4 bytes (x86) or 8 bytes (x64/ARM64), callback
capacity C occupies C × P bytes. Preferred initial allocation is 32 × P =
128 or 256 bytes. Growth is C + min(C,512) slots, checked before multiplication;
expected allocation failure retries C + 4 slots. For 1024 occupied slots,
preferred new capacity is 1536: 6144 bytes on x86 or 12288 bytes on Win64.
All size/address arithmetic is checked against guest width; no wrapping size
or truncated pointer is accepted. Copy/zero initialization uses at most 256
bytes of host scratch. A failing candidate is freed before returning; old
logical queue, entries and live block ownership remain intact. Heap commitment
or probe residency is not promised to roll back.

Registration is O(1) within capacity, O(C) on moving growth, excluding allocator
and memory residency costs. Capped +512 growth has O(N²) worst-case aggregate
copy work for N registrations, rather than perpetual amortized O(1). Queue
storage is O(N), host scratch O(256 bytes). The internal reverse scanner marks
a selected slot NULL before returning its callback value; insertion endpoint
and storage identity changes restart traversal, with consumed holes preventing
replay. Without mutation it is O(N); adversarial callback registration/restarts
can exceed O(N). Internal scanner tests do not establish guest execution via an
unadmitted termination export.

Exit-lock state holds thread identity and a checked recursion count. A guard
survives guest callbacks, callback-stack repair, operation repair and waits,
without an outstanding RefCell borrow. Other threads use a reserved 128-bit
wait-key namespace (bit 127), disjoint from guest address and condition-variable
keys. Outermost release wakes contenders, which recheck ownership before
entering; no FIFO or starvation bound is claimed. Guard Drop records a typed
pre-reserved receipt, without guest access or allocation. Scheduler retirement
releases terminal owners; a nonterminal escape remains an explicit diagnostic.
These retirement rules are personality profiles, not native recovery from a
thread exiting while owning a CRT critical section.

## Change-surface map

| Plane | Assessment |
|---|---|
| Direct decode | Unaffected: no ISA encoding changes |
| Direct execute | Unaffected: existing software cores run compiler output |
| CPU architectural state | Unaffected: existing Cdecl/scalar marshalling |
| Memory/MMU | Affected checked private heap buffers and publication; translation unchanged |
| SMIR lift | Unaffected: no new guest instruction |
| SMIR IR | Unaffected: no new operation |
| SMIR interpreter | Unaffected: Windows personality uses existing ISA execution |
| Optimizer | Unaffected: no new transformation |
| Native lowering | Unaffected: no native Windows admission |
| JIT runtime | Unaffected: witnesses explicitly set RAX_NO_JIT=1 |
| Backend | Unaffected: no KVM/HVF state or exit changes |
| Machine/device | Unaffected: process-level personality only |
| Oracle/analysis | Unaffected: no decode/effect changes |
| C ABI/public Rust | C ABI and published Rust field paths unchanged; repr(Rust) CRT state grows, with no stable-layout claim |
| CRT/HLE/scheduler | Global queues, genuine names, shared lock, receipt retirement/discard |
| Tests/docs | Reachable all-ABI units, custom-entry integration, source/fixture receipts and this audit |

## Bounded discoveries

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | SDK dynamic CRT skips static preterminators in common_exit; dynamic DLL detach flushes stdio even for minimal/quick CRT cleanup, unlike unqualified public wording | No; blocks broad termination/stdio equivalence until link/version-specific contract is selected and verified |
| High | Duplicate executable TLS registration calls terminate; default abort can fast-fail and may call a registered handler | No; do not fabricate a universal exit status or admit a TLS stub |
| High | Legacy MSVCRT atexit binding and DLL-local ownership are distinct from UCRT global names | No; legacy registration and full CRT termination remain whole-goal dependencies |
| High | Existing explicit-table detached-generation profile differs from SDK mutable live-table traversal | No for documented profile; blocks native explicit-table reentrancy equivalence |
| High | SDK source redistribution grant is unknown | Raw proprietary members/licenses are excluded from staging; only hash receipts, retrieval code and our derived observations are committed |
| Medium | MSVC exit-lock selector body and application/system isolation are absent from SDK | No; G2 scope is explicit |
| Medium | Exact address/requested-size ABA after caller raw-free is not detectable by current heap metadata | No for valid private ownership; G4 scope is explicit |
| Medium | Root/C API all-target builds emit an existing librax.rlib filename-collision warning | No; compilation is not C API runtime coverage |

## Provenance and ownership

The [reference receipts](../../specifications/windows/crt-termination/README.md)
identify exact source members, hashes, prototypes, genuine DLL exports, producer
wrappers and owning license evidence. The entire 155613545-byte publisher SDK
package was streamed through SHA-512 and matched the publisher CDN digest;
CRC32 is only member integrity, not whole-package authentication. NuGet
author/repository signature verification is not claimed. Raw SDK inputs remain
local or temporary inspection material and are explicitly excluded from this
feature's exact staging list.

The [fixture bundle](../../../tests/fixtures/user/windows/crt_termination/README.md)
contains 30 custom-entry PEs, not ordinary compiler CRT startup. Its manifest
pins source, compiler/linker tools, parsed IATs, artifacts and literal expected
results. Baseline CLI SHA-256 is
`690e076e084a3590005fe0aec2d8723e9095954afee2531a227e0bb9e4eaf924`;
all 60 baseline runs (30 images × slices 1 and 4096) fail at the missing genuine
`ucrtbase.dll!_crt_atexit` export with shell status 125. They are observations
under the prior emulator, not native Windows recordings.

Ownership is confined to the five new termination Rust files, CRT runtime/export
wiring and shared test helper, explicit-table wrapper/binding test, scheduler
hooks, reachable integration registration/runner, this audit and its linked
overview/registry updates, plus the new reference and fixture bundles. No
dependency, Cargo feature/default, toolchain, workflow, ISA implementation,
previous generated corpus or unrelated untracked path is changed. The final
expanded exact ownership list is audited against index and commit paths.

## Executed validation and quality gates

Validation receipts are collected in `/tmp/rax-crt-global-gates.HiaJfI/`.
Final source validation used stable Rust 1.98.1
(`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8) and Cargo 1.98.1
on `aarch64-apple-darwin`. All following final commands completed with status
zero. Earlier development/nightly receipts are not substituted for this final
stable cycle.

Portable selection is `--no-default-features`; feature selection is
`--no-default-features --features x86_64-suite,smir-jit`. Each selection ran:

```sh
cargo +stable test --locked <selection> --lib -- --test-threads=1 --nocapture
cargo +stable test --locked <selection> --test user_windows --test ci_actions_pinned -- --include-ignored --test-threads=1 --nocapture
cargo +stable build --locked --workspace --all-targets <selection>
cargo +stable test --locked <selection> --doc
```

| Gate | Portable | Feature selection | Execution limits |
|---|---|---|---|
| Unfiltered library | 6731 passed, 0 failed, 2 ignored, 0 filtered | 8903 passed, 0 failed, 2 ignored, 0 filtered | Two existing microkernel validation tests remain ignored |
| Complete user_windows binary | 322 passed, 0 failed/ignored/filtered | 322 passed, 0 failed/ignored/filtered | Guest x86/x64/ARM64; interpreter witnesses, not a native Windows oracle |
| Complete ci_actions_pinned binary | 10 passed, 0 failed/ignored/filtered | 10 passed, 0 failed/ignored/filtered | Repository/source registration checks |
| Workspace all-target build | passed | passed | Existing root/C API librax.rlib collision warning; build-only C API evidence |
| Doctests | 0 executed, 5 ignored | 0 executed, 5 ignored | No runtime doctest coverage claimed |

The final cycle also completed:

```sh
cargo +stable fmt --all --check
cargo +stable clippy --locked --workspace --all-targets --features x86_64-suite
```

Clippy's default feature selection does not exercise KVM on this host. The
repository's warning/Clippy allow tables remain unchanged; quiet output is not
used as a substitute for semantic review.

An explicit overflow-enabled portable Windows library run passed all 459
selected tests, with 6274 unrelated tests filtered and none ignored:

```sh
CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true cargo +stable test --locked --no-default-features --lib user::windows -- --test-threads=1 --nocapture
```

Local ordinary dev/test settings have overflow checks and debug assertions
enabled. To cover CI execution semantics, the feature-selection Windows
library and complete Windows/CI-pinning binaries also ran with all four
`CARGO_PROFILE_{DEV,TEST}_{OVERFLOW_CHECKS,DEBUG_ASSERTIONS}=false` environment
settings. The library passed 459 tests, none failed/ignored, with 8446 unrelated
tests filtered. The complete integration binaries passed 322 and 10 tests,
respectively, with none failed/ignored/filtered.

New reachable coverage is 36 library tests (20 storage, 13 facade, 3 lock),
each exercising all three guest ABIs, plus 31 integration tests. Thirty
integration tests execute the 30 custom-entry PEs at both prescribed scheduling
slices; the remaining test checks the complete source/PE/IAT/baseline graph.
The regression that leaves independent initialization unlocked is included in
the final stable library runs, not only an earlier filtered check.

Source/fixture validation independently confirms 58 retained hash/size checks,
20 publisher source receipts, 18 installed-input hashes, four extraction
replays and 12 offline command replays, with no unavailable inputs. Two retained
network replays each verify 19 SDK member extractions, 15 command replays and
the complete publisher package SHA-512. Both fixture builds produce identical
30-PE/IAT bundles (77824 PE bytes); 60 preserved baseline failures and reciprocal
manifest/baseline references match. Ruby syntax checks pass for all three
producer/retrieval scripts. Twenty authored local documentation targets resolve.

Development review corrected the facade visibility, a transient baseline
manifest mismatch during fixture assembly, and the extra initializer lock.
Final receipts include all corrected source and fixture bytes; failed or
pre-correction runs are not counted as final validation.

Native Windows execution, complete compiler CRT startup, legacy MSVCRT
registration, termination/TLS admission and exact private-fault recovery remain
unknown or unimplemented as identified above. C API runtime, KVM/HVF runtime,
and unrelated ISA integration binaries were not run: no such behavior was
changed. Both all-target build selections cover their compile-time coupling.

## Acceptance audit and self-red-team

| Criterion | Direct evidence |
|---|---|
| 1 | Genuine-name/prototype binding tests; genuine publisher three-ABI export sets; independently parsed fixture IAT matrix |
| 2 | Separate private heap queues; 20 all-ABI storage tests including holes, duplicates, growth/fallback, repair and ownership violations |
| 3 | Lock facade and explicit registration/execution wrapper; nested, blocked-worker and unlocked-independent-initialization regressions; compiled concurrent witnesses |
| 4 | Captured-input fault/wait regressions, allocation-free guard Drop receipts, terminal/nonterminal retirement and NOACCESS host-only discard tests |
| 5 | Completed final stable/CI-profile gates and verified source/fixture/baseline receipts above |
| 6 | Exact 114-path inventory; staged/tree/blob and commit-metadata checks before immediate origin push; final Git result belongs to the delivery receipt |

The final pre-staging inventory contains exactly 114 owned paths and excludes
every proprietary `microsoft-sdk/` input. All new hand-maintained Rust files
are below the hard size trigger; the touched scheduler is 1517 lines and remains
below that trigger. No new unsafe block, instruction encoding, SMIR operation,
native admission gate, dependency, feature or public C ABI is introduced.
There is no normative judgment required by this technical task.

| Repository quality gate | Evidence |
|---|---|
| QG1 Assumptions | G1–G5 include dependent results, stress tests, probes and reconciled limits; native unknowns remain explicit |
| QG2 Coverage | Criteria 1–6 and the complete affected-plane map are enumerated; Git verification is part of the delivery workflow |
| QG3 Reproducibility | Exact source/tool/input receipts, pointer-width calculations, bounded scratch and complexity, seeds/slices and executed feature/profile settings |
| QG4 Edges/conflicts | OOM/fault/capture/reentrancy/abandonment/width/generation boundaries tested; SDK initialization and explicit-table profile distinctions reconciled |
| QG5 Provenance | Verified publisher/source/export/producer evidence; raw SDK exclusion, unsigned-package limit and native-oracle unknowns recorded |
| QG6 Bounded scope | Impact-labeled adjacent termination/TLS/stdio/legacy/isolation/ABA findings retained without incidental implementation |
| QG7 Worktree integrity | Exact owned inventory and byte snapshots; unrelated tracked/untracked content preserved; no broad staging or amendment |
| QG8 Behavior | All 36 new library and 31 integration tests are reachable and executed; complete affected binary counts and ignored/filter limitations reported |
| QG9 Consistency | Runtime export wiring, module reachability, test registry, source/fixture graph and linked architecture documentation agree |
