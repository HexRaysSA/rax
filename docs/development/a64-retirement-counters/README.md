# AArch64 private retirement counters across restoration

The private instruction and cycle counters advance independently modulo 2^64
after one successful A64, ARM, or Thumb instruction. A counter at `u64::MAX`
therefore becomes zero after successful retirement. A failed instruction fetch
changes neither counter. The number of instruction bytes does not change the
retirement unit: both 16-bit and 32-bit Thumb instructions retire once.

These are existing execution metadata fields. They are not new architectural
registers, and this change does not alter instruction arithmetic, FP state,
the C ABI, or the `RAXA6403` private-record layout. The production repair makes
the two interpreter paths use the same explicit wrapping policy as native
execution and the existing retirement-budget interface.

## Restored-state and observation contract

`CoreCheckpoint` already captures, admits, and restores unrestricted `u64`
instruction and cycle counts. Resumption must therefore work at their maximum
values. Rejecting previously valid counter values would change this contract.

The adapter observation count is a separately saved field. Its phase is
preserved by adding the private retirement delta, as described in
[public system entry](../a64-system-entry/README.md). A budget of one after
restoration must report one retirement and publish one retirement-clock unit,
even when a private counter or the observation counter wraps. A zero budget
must leave those counts unchanged; a fetch fault must retire zero units.

Direct CPU stepping retains its existing timer behavior. For these non-waiting
fixtures, system stepping advances the modeled physical counter by 16 ticks
per attempt. The regression
also crosses that counter's wrap boundary without changing its tick policy.

## Reproducible fixtures and gates

The execution receipts, baseline source archive, exact environment, and source
manifests are retained under
`/Users/int/dev/rax-audit-work/four-findings-aarch64-cluster/a64-retirement-counters`.
The core tests serialize, strictly decode, and install actual private state.
The adapter tests encode a complete tagged record, pass normal admission,
restore it through the public adapter operation, and execute a real budget.
The counter fixture constructor is compiled only into tests.

The instruction bytes are independently checked by the retained LLVM MC run:

| Execution state | Instruction | Little-endian instruction bytes |
| --- | --- | --- |
| A64 | `ADD X0,X0,#1` | `00 04 00 91` |
| ARM | `ADD R0,R0,#1` | `01 00 80 e2` |
| Thumb, 16-bit | `ADDS R0,#1` | `01 30` |
| Thumb, 32-bit | `ADD.W R0,R0,#1` | `00 f1 01 00` |

LLVM verifies encodings; it is not a retirement-counter runtime oracle. Counter
expectations follow the existing wrapping budget contract and arithmetic
modulo 2^64. No new architectural instruction behavior is introduced. Existing
ISA and native comparison suites remain part of full owning validation.

The matrix covers independent instruction/cycle maxima, all nine combinations
of zero, maximum minus one and maximum counts, three operand partitions, three
entry modes, both adapter policies, preserved observation offsets, zero budgets,
faults, and actual native A64 entry. Native-entry assertions cannot be satisfied
by interpreter fallback. The core boundary matrix contains 324 cases:
4 execution forms * 3 entry modes * 3 instruction counts * 3 cycle counts *
3 operands. Smaller control, fault, adapter, and native matrices are additional.

From the repository root, after selecting one explicit disposable Cargo target
directory and an existing scratch directory, the focused command is:

```sh
cargo +stable test --locked --offline --lib --no-default-features \
  --features x86_64-suite,smir-jit,hvf retirement_counters:: \
  -- --test-threads=1 --nocapture
```

On the recorded AArch64 host with JIT enabled, 15 tests must execute. The
overflow-enabled and overflow-disabled test configurations are qualified
separately; the latter uses `CARGO_PROFILE_TEST_OVERFLOW_CHECKS=false`. This is
an arithmetic-profile check, not a claim that a complete optimized release or
physical Intel binary was executed.

Final acceptance also requires an observed parent failure, full owning library
and integration binaries, C API coverage, workspace format/Clippy/build checks,
interpreter-only and x86-64 compilation, source verification, an exact-path
commit, and cleanup of idle build output. Focused passing tests alone do not
establish completion.

## Assumption register and remaining scope

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| RC1 | Existing private `u64` counters admit every value and advance modulo 2^64; restored execution must preserve that policy. | Independent maxima, nine count partitions, all instruction widths and entry modes, faults, and native execution. A panic or incorrect retirement delta falsifies it. | Confirmed within the recorded width, count, entry, fault and native matrix. |
| RC2 | The two counters are existing private metadata, with no new wire field. | Restore complete tagged contexts and compare public/private counts and the retirement clock. A changed tag or rejected previously valid record falsifies it. | Confirmed by complete tagged-record restoration and unchanged serialized fields. |

High impact: complete backend/private/in-flight state, coordinated external
writers and late host-failure rollback, hardware and other-ISA native entry,
additional ARM/wait/event profiles, and physical Intel HVF remain separate
requirements. The four full audit findings remain incomplete.
Medium impact: this group does not qualify every implementation counter in
other CPU backends or alter instruction throughput. Retirement increments use
O(1) time and O(1) additional space.

Observed parent baseline: 15 tests executed, four passed and 11 failed with
overflow panics. The final 15-test matrix passed with overflow checks enabled
and explicitly disabled. The complete library passed 11,278 tests with
two ignored; all 47,694 integration tests across 22 complete binaries and all
223 C API tests passed. Workspace format/Clippy/build, interpreter-only and
x86-64 compile checks, and source verification passed. Doctests executed zero
cases with five ignored. Physical Intel and complete optimized-release runtime
validation did not run.
