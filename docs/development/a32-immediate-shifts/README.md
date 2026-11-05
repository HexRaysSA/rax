# AArch32 immediate shift width, count and selector admission

The immediate-shift decoder and executors previously ignored `L` in `L:imm6`.
Legal 64-bit forms could be rejected or executed as narrower lanes. Left shifts
also rejected the legal zero count. Reserved VSRI and VQSHL/VQSHLU selectors
could execute a shift or fall through into modified-immediate decoding.

Decode and execution now share the field interpretation. VSRI with its fixed
selector cleared and the reserved VQSHL/VQSHLU selector return Undefined before
FP access. The related modified-immediate, narrowing and widening classes keep
their separate field rules. No native vector admission or state layout changes.

The primary reference is [Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf),
one-based PDF pages 1244-1245 (VQSHL/VQSHLU immediate), 1337-1338 (VSHL
immediate), 1346-1347 (VSHR), 1355-1356 (VSLI), and 1365-1366 (VSRI).
[Provenance](provenance.json) records the exact manual and tool hashes.

| Field | Element width in bits | Left count | Right count |
|---|---|---|---|
| L:imm6 = 0001xxx | 8 | imm6 - 8 | 16 - imm6 |
| L:imm6 = 001xxxx | 16 | imm6 - 16 | 32 - imm6 |
| L:imm6 = 01xxxxx | 32 | imm6 - 32 | 64 - imm6 |
| L:imm6 = 1xxxxxx | 64 | imm6 | 64 - imm6 |

The shared helper returns `encoded = 64*L + imm6` and the element width.
Thus left counts range from zero through width minus one; right counts range
from one through width. `0000xxx` retains related-encoding dispatch. The helper
takes constant time and space; execution keeps the existing lane-wise cost.

The mask is `u64::MAX >> (64 - width)`, so mask construction never shifts by
64. Full-width VSRI preserves its destination without evaluating a 64-bit
host shift. Saturating calculations use `i128`: the largest unsigned shifted
operand is `(2^64 - 1)*2^63 = 2^127 - 2^63`, within `i128`; the most negative
signed case is `-2^63*2^63 = -2^126`. Zero-count VQSHLU still saturates negative
inputs to zero and sets sticky QC.

The complete pre-fix control target passed 107 tests and failed seven. The
corrected target contains 114 tests, including all 6,881,280 legal-family
D/M/Q/ISA/count decoding combinations, 60,480 direct execution cases with
independent integer formulas, legal FP denial/failed-IT controls, mixed-width
fault priority, and 946,176 related-encoding allocation controls.

An existing VFP test expected `f2880511` (VSHL.I8 D0,D1,#0) to be Undefined.
That contradicts the primary count formula and independent QEMU execution.
Its corrected assertion checks a legal copy and preservation of the other
vector registers. The initial complete VFP failure is retained in
[qualification](qualification.json), rather than counted as a passing run.

The independent QEMU guest executes 6,728 cases: all 6,720 combinations of
14 legal operations, every count, both ISAs and both vector widths, plus eight
reserved selector controls. It checks exact D0/D1/FPSCR values with signed,
unsigned, rounded, accumulating, insert and saturating operations. Inputs vary
aliases, sign/carry patterns and initial sticky QC deterministically. The
selected named-instruction LLVM bytes are in [assembly.json](assembly.json).

```sh
python3 docs/development/a32-immediate-shifts/qemu-controls.py --out /tmp/rax-shift-qemu-results
```

The output directory must not exist. The harness retains text observations
and reproducibility metadata there, and removes temporary objects/executables.
It does not establish physical AArch32 execution.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| S1 | L selects the 64-bit immediate domain | Primary encoding; all 120 counts per operation/ISA/Q; cross-word carry and saturation results | Confirmed within this domain |
| S2 | Zero left shifts are legal and retain operation-specific QC | Zero counts at every width, negative VQSHLU and repeated non-saturating input with QC already set | Confirmed |
| S3 | The two rejected selector classes are reserved | Primary fixed encoding/explicit Undefined condition and eight actual QEMU exceptions; related modified immediates remain allocated | Confirmed |
| S4 | These NEON forms remain outside scalar SMIR/native admission | Existing A32/Thumb lifters reject these mnemonics; complete native scalar and no-JIT gates remain separate checks | Qualification records the actual runs |

High-impact remaining profile and instruction-admission work, complete native
state/checkpoint/interrupt/replay behavior and the streaming-FPSR SDK
counterexample remain separate requirements. This group does not close the
four original findings.

The canonical neighbor checks above do not prove all reserved neighbor fields.
A subsequent independent control found 72 narrowing/widening records with a
reserved high field bit that QEMU rejects while the current RAX decoder admits
and executes them. Their complete witnesses are retained for the next semantic
group. The ordinary-shift fix does not change those decoders.
