# Sparse guest execution and typed fault recovery

## Contract and evidence

ABI 1.4 adds `rax_emu_last_fault` without changing existing C structures or
callback signatures. Physical backing faults carry access direction and the
first inaccessible byte. Guest page-table faults remain distinct: a virtual
fault address is not authority to allocate physical backing. Invalid-instruction
exceptions whose delivery fails remain invalid-instruction diagnostics, with the
original delivery diagnosis retained.

Instruction-window reads are speculative. The decoder propagates a deferred
fault only when it consumes an unavailable byte. Thus a one-byte NOP at
`0x1fff` executes with `[0x1000, 0x2000)` mapped, whereas a five-byte `JMP rel32`
at `0x1ffd` requires backing beginning at `0x2000`. Mapping that continuation
permits retry at `0x1ffd` without retiring the failed attempt.

The governing instruction semantics are the vendored Intel instruction entries
`docs/specifications/x86_64/jmp.txt`, `push.txt`, and
`movs_movsb_movsw_movsd_movsq.txt`, and the Intel SDM in that directory.
The executable embedding contract is `capi/src/tests/x86_faultin.rs` and
`capi/src/tests/arm64_faultin.rs`. C ABI offsets are pinned by
`capi/tests/fault_abi.c`; the installed shared/static C++ consumer is
`capi/examples/cpp_fault_recovery.cpp`.

A faulting ordinary crossing store is preflighted before publishing bytes.
REP string operations preserve completed elements on a later fault; retry uses
that partial architectural state. A failed attempt contributes zero retired
instructions. Pre-execution hooks can observe attempts; embedders must not
present those notifications as completed instruction traces.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| A1 | Physical sparse memory can be supplied without changing existing guest bytes. | Existing C API sparse mapping and state-preserving rebuild. | Map-and-retry contract. | Crossing fetch/read/write tests compare PC, flags, registers, bytes and cumulative counts before and after mapping. | Confirmed for tested x86 and AArch64 paths. |
| A2 | Failed instruction attempts must not consume the caller's retirement limit; partial REP elements remain committed. | Intel MOVS/REP exception semantics and existing string engine. | Counter correction and retry behavior. | Failed PUSH, crossing store, partial REP and repeated halted-step tests. | Confirmed for tested paths. |
| A3 | AArch64's current fault information does not retain an access width. | `MemoryFaultInfo` and emulator adapter. | ABI reports width 0, explicitly unknown. | Inspect adapter and assert access kind/address; introducing a width field would permit replacing 0. | Retained. |
| A4 | Existing C API consumers accept an additive minor-version API. | Existing layouts and numeric constants retained. | ABI 1.4 query. | Strict C offsets, unknown-version/short-buffer/tail tests, installed shared/static C++ execution on native CI. | Validation required on each native lane. |

## Change-surface map

| Plane | Effect |
|---|---|
| Guest CPU / decoder / MMU | x86 deferred fetch errors and retirement; AArch64 typed physical faults and store preflight. |
| C/C++ SDK | Additive record/query; preserve fault diagnostics across host memory/register APIs; reset on run/reset/context restore. |
| State / persistence | No serialized layout change. Mapping preserves cumulative counts; context restore keeps its existing zero-count reset semantics. |
| Host kernels | No new OS calls. vm-memory remains the existing host allocation adapter. |
| CLI / VM | Typed Rust errors preserve diagnosis; normal delivered guest exceptions continue through their existing handlers. |
| Packaging / platforms | Existing installed headers and libraries carry the additive API. Required native Linux x86-64, macOS ARM64 and Windows x86-64 jobs run C API tests plus strict C and shared/static C++ consumers. Existing core matrix also compiles Linux ARM64 and macOS Intel. |
| Assist plugin / UI / MCP / permissions | No implementation in this repository; consumers must use typed faults and provide authoritative page contents. Updating the parent pin is gated on the exact RAX commit passing CI. |

## Bounds and self-review

The instruction window has a fixed maximum of 15 bytes. Descending reads make
at most 15 memory calls and inspect at most `15 + ... + 1 = 120` bytes per
boundary fetch: O(1) time and O(1) space with respect to guest memory size.
Ordinary AArch64 store preflight is O(r) for r intersected backing regions,
with O(1) auxiliary storage. The ABI v1 record is 48 bytes, with 64-bit PC,
address and retirement fields at byte offsets 16, 24 and 40 respectively.
The fixed-width fields introduce no host-pointer-size dependency.

Bounded findings:

* High, parent integration requirement: an allocated zero-filled page is not
  evidence that IDB bytes were loaded. The parent must provide complete known
  backing and must not overwrite guest changes during recovery.
* High, parent integration requirement: code/block callbacks precede execution;
  traces require retirement reconciliation after faults and retries.
* Medium, nonblocking limitation: unknown AArch64 fault width is represented by
  zero; callers must use the address and backing-page granularity.
* Medium, nonblocking limitation: retirement queries on backends that do not
  implement `VCpu::instruction_count` remain zero; this change targets the
  stepping emulator backends used for sparse instruction embedding.

Quality gates: normative content is unnecessary; assumptions and falsification
probes are above; the ABI and source contracts have explicit executable tests;
address ranges are half-open and widths are bytes. Local and native CI results
must be checked before publishing the parent dependency update. No local test
result substitutes for a native platform job.

Local validation on macOS ARM64 (rustc 1.100.0-nightly, f248f4038): 5,556 library tests, 28,515
x86 integration tests (both with `--include-ignored`), 71 C API tests,
15 packaging-helper tests and 8 installed shared/static C++ consumer tests
passed. `cargo fmt --all --check`, C API all-target Clippy, strict C ABI
compilation and `make -C capi test` passed. Native CI remains the publication
gate for the other operating systems. Baseline sparse-fetch and failed-PUSH
regressions failed before the implementation changes.
