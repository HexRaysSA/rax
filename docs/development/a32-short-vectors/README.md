# Optional AArch32 VFP short vectors

This component implements the explicit `MVFR0.ShortVectors=1` software profile:
`VMSR`/`VMRS` preserve `FPSCR.Len[18:16]` and `FPSCR.Stride[21:20]`, and the
fourteen forms below execute every selected register-bank element in ARM and
Thumb. The default `ShortVectors=0` profile retains its existing masked controls.
This is a synthetic non-trapping profile, not a claim of a physical processor's
complete feature set. All four original audit findings remain partial.

| Forms | Operands |
|---|---|
| VADD, VSUB, VMUL, VDIV, VNMUL | Binary |
| VMLA, VMLS, VNMLA, VNMLS | Binary with destination accumulation |
| VABS, VNEG, VSQRT, VMOV (register) | Unary |
| VMOV (immediate) | Immediate |

The authority is [Arm DDI0406C.d](../../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf),
D11.1-4, Tables D11-1/2, FPSCR B4.1.58 and MVFR0 B4.1.108; its acquisition and
SHA-256 are recorded beside the PDF. See `qualification.json` for verified
sections, assumptions, execution planes, exact validation commands and results.
The `VFMA`/`VFMS`/`VFNMA`/`VFNMS` instruction descriptions separately require
scalar controls. These forms are denied with nonzero short-vector controls.

## Selection and bounds

| Control or bank | Behavior |
|---|---|
| Len=0, Stride=0 | Scalar mode |
| Len=1..7, Stride=0 | Length=Len+1, stride=1 |
| Len=1..3, Stride=3 | Length=Len+1, stride=2 |
| Other controls | RAX selects Undefined before FP access or effects |
| S0-S7 | Scalar destination or broadcast second/unary source |
| Other S banks, each 8 registers | Vector; wrap within the selected bank |
| D0-D3, D16-D19 | Scalar destination or broadcast second/unary source |
| Other D banks, each 4 registers | Vector; wrap within the selected bank |
| Double vector length>4 or stride=2 and length>2 | RAX selects Undefined |
| Double scalar destination | Accept every globally permitted control pair |
| ShortVectors=2..15 | Deny affected forms; ID reads remain independent |

The first binary source advances even when its starting register belongs to a
scalar bank. A scalar destination executes once. Element reads and writes use
encoded-element order; overlapping operands are not snapshotted. The appendix
does not explicitly specify overlap read timing. This selected processing-element
choice is tested and agrees with QEMU's observed binary and single-precision
unary paths; physical overlap conformance is unknown.

The loop calls the existing scalar arithmetic handlers, accumulating their
status flags. Admission happens before iteration. Existing restricted scalar
rounding/NaN/subnormal support-code boundaries remain before all effects. An
unexpected scalar-handler rejection restores the initial VFP image. These forms
have no guest-memory or device access. One admitted instruction retires once,
regardless of element count; a rejected instruction does not retire.

Time is O(L), with L<=8; storage is O(1) because VFP state has fixed size. In the
register advance expression, r<=31, i<=7, s<=2, so r+i*s<=45<256; this fits `u8`
before bank masking. FPSCR control mask `0x00370000` excludes FZ16 bit19. No
serialized field, wire format, public ABI, native lowerer or dependency changes.
The ARM/Thumb SMIR frontier remains Unsupported for every affected base form.

## Scalar FP16 admission

Scalar FP16 arithmetic, fused arithmetic, move immediate, VMOVX and VINS
require zero FPSCR.Len and FPSCR.Stride. The shared admission check rejects
these encodings before an FP access trap or architectural effects. The
configured legacy short-vector profile exposes both controls. On RAX profiles
that read them as zero, raw bits in a saved context do not affect admission.
FP16 comparison, core transfers and conversions follow their own encodings.
[Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm DDI0601, FPCR Len and Stride](https://support.arm.com/documentation/ddi0601/2023-12/AArch64-Registers/FPCR--Floating-point-Control-Register)

| ID | Assumption and dependent behavior | Falsification probe | Result |
| --- | --- | --- | --- |
| A1 | Only visible Len and Stride participate in admission. This determines the default profile's behavior after restoring raw state. | Vary all 32 pairs across 19 forms, both instruction sets and profiles with and without the controls. Check unchanged GPRs, VFP state and FPSCR on rejection. | The parent took a Hyp FP trap for `VADD.F16` with Stride=1. The new admission check tests the control fields before the trap. |
| A2 | The controls are decode restrictions for these FP16 forms and take priority over an FP access check. | Program and read back each pair on QEMU 11.1.2 `max`. Compare Undefined delivery and the destination register. Use Cortex-A15 as a negative control for absent FP16. | The `max` model rejected all 1,178 nonzero cases and executed all 38 zero cases. Cortex-A15 rejected all cases. Both QEMU models retained the written fields even with MVFR0.ShortVectors=0. RAX selects read-as-zero for its default profile. |

The mask `0x0037_0000` combines Len[18:16] and Stride[21:20] and excludes
FZ16[19]. Admission uses constant time and auxiliary space. Tests also cover
software-backend fault retirement, context round-trip and the unsupported
SMIR frontier in both instruction sets. The five complete integration suites
and the two short-vector backend tests passed 47,722 tests with no failures
or ignored tests. Clippy passed with warnings denied on macOS Arm64. The QEMU
test guest, exact commands, tool versions and raw results are in
`/Users/int/dev/rax-audit-work/four-findings-a32-half-short-controls-2026-11-26/`.
Physical AArch32 execution and the broader A32-FP finding remain open.

## Evidence and reproduction

Four observed failures on the parent engine covered discarded FPSCR controls,
a single-element VADD, accepted reserved capability and accepted invalid shape.
The repaired owning VFP suite checks 1,064 independent primary-derived cases in
both instruction sets, every register and FPSCR bit, D16 admission, predicates,
invalid controls and access priority, flag union, overlap, restricted-mode
bounces and closed SMIR admission. Standalone backend tests check private
pre/post boundaries and one-instruction retirement. Actual checkpoint files
exercise 1, 2 and 4 prepared online CPU contexts at pre-control, pre-vector and
completed-vector boundaries. Prepared contexts do not establish architectural
secondary startup.

`cases.json` is generated by a Python model derived from the primary bank and
stride tables, using finite powers-of-four operands with exactly representable
results. LLVM supplies encodings only. The model does not invoke RAX arithmetic
helpers. Positive regeneration is byte-identical; separate corrupted-word and
corrupted-expected-register checks must fail verification.

```sh
python3 tools/execution/a32_short_vector_cases.py --llvm-mc /path/to/llvm-mc
# Expected: 1064 semantic cases, 125 distinct encodings per instruction set; fixture verified
cargo test --locked --no-default-features --features x86_64-suite,smir-jit --test arm_vfp_a32
# Use a dedicated CARGO_TARGET_DIR and TMPDIR, then remove only those owned roots.
python3 tools/execution/a32_short_vector_qemu.py \
  --cases docs/development/a32-short-vectors/cases.json \
  --out-dir /absolute/empty/owned/output \
  --llvm-mc /path/to/llvm-mc --ld-lld /path/to/ld.lld \
  --qemu /path/to/qemu-system-arm
```

The independent Cortex-A8 QEMU 11.1.2 guest completed 2,138 records: 2,128 base
records plus 10 overlap records. Full 32-D-register images and FPSCR were
compared without masks: 1,938 matched; 200 records had register differences; every
FPSCR comparison matched. `qemu-reference.json` retains all 200 differences,
input/tool hashes and calibration. The retained source explains two observed
model discrepancies:

| Difference | Records | Observation |
|---|---:|---|
| Single precision, encoded stride=3 | 164 | QEMU advances four S registers; Table D11-1 specifies two |
| Double unary vector | 36 | QEMU derives the next destination from the source and does not advance the source |

The primary rules determine RAX expectations where QEMU differs. No discrepant
record is silently discarded. The QEMU binary version/hash and retained tagged
source have separate provenance; exact build-source identity is unknown. The
first QEMU fixture's incorrect Thumb entry addition is excluded and retained as
a fixture error: Thumb function symbols already carry bit0, so the corrected
fixture uses OR, not addition. Compiler-only fixture errors are also excluded
from behavioral regression evidence.

Remaining original scope includes optional FP exception trapping, broader
profile/security/debug controls, complete other backend/private/in-flight
state, native interrupt/scheduling/clock/replay requirements and physical Intel
validation. Physical AArch32 short-vector execution is unverified. Existing
native ARM streaming-FPSR reentry remains separately open. See the audit ledger
and the bounded-scope register in `qualification.json`.
