# A32 VFP block operand admission

VLDM/VSTM and VPUSH/VPOP now check scalar register lists during decode, before
FP access controls. The shared ARM decoder validates single/double list spans,
zero counts, the double-list limit of16 registers and PC with writeback. The
Thumb wrapper additionally excludes every PC base. ARM PC bases without
writeback remain available. Execution handlers retain defensive checks.

RAX selects Undefined for these unpredictable operands. The overflowing-list
outcome was already selected by its handlers; the fix applies that policy
before permission checks and selects the same permitted outcome for the other
represented constraints. It does not require other hardware to make that choice.
Unallocated half block forms no longer decode as VFP blocks, and unsupported
odd double FLDMX/FSTMX forms retain their existing execution boundary. No CPU
state, checkpoint wire or C ABI layout changes are introduced.

| Operand | Decode requirement |
|---|---|
| Single list | count = imm8; count >0 and first + count <=32 |
| Even double list | count = imm8 /2; 1 <=count <=16 and first + count <=32 |
| PC base in ARM | No writeback |
| PC base in Thumb | Excluded |

Indices/counts are dimensionless. The encoded byte extent is4 * imm8, at most
1020 bytes; an admitted list spans at most128 bytes. The largest classification
sum is31 +255 =286, within `u32`. Classification uses O(1) time/space.

The original complete library probe passes one valid control and fails two
list/access-priority cases. The six new owning cases initially pass one and
fail five, including a mixed-width EC7 trap and an invalid PC-base store which
changes RAM. The changed complete production library passes all90 FP-control,
5 pair and487 VFP cases:582 passed,0 failed,0 ignored,0 filtered.

Those six cases contain294912 pure decode combinations,1008 boundary
executions,72 PC-base executions,252 failed-IT executions and28 mixed-width
faults. Generated data points are distinct from harness test counts. Rejected
and denied operations preserve register/status/RAM state; mixed failures retain
PC and retire zero instructions. `qualification.json` records the actual
baseline/green receipts, assumptions, falsification probes and remaining checks.

`provenance.json` pins the existing Arm DDI0597 ID032025 PDF, exact section pages
and ASL bytes. Both put list/base constraints in decode and CheckVFPEnabled in
execution. The ASL revision is unknown; the retained PDF is2025-03.

All eight canonical workspace/feature/Clippy/doc/unit/owning gates passed. The
complete Cargo owning binaries pass90 +5 +487 =582 cases, with no failures,
ignores or filters. Decoder and executor module selections pass165 and54 cases.
Two compile-fail doctests pass; five pre-existing examples remain ignored. The
frozen source excludes subsequent native firmware work and independent newer
upstream Darwin/Windows changes. Physical A32/Intel HVF execution,
broader profile controls and complete backend/private/clock/replay requirements
remain open. These software executor results do not close the original findings.
