# AArch32 widening and narrowing admission

The widening and narrowing decoders ignored fixed encoding bits. Reserved
records could modify vectors or select FP-access traps instead of Undefined.
The widening decoder also rejected legal nonzero VSHLL forms and consumed
related modified-immediate encodings that the specification routes elsewhere.

The decoder now rejects narrowing bit7=1 and ordinary widening bits7:6!=00
before FP access. Widening supports both VSHLL encodings, preserves the VMOVL
zero-shift alias, and routes imm6=000xxx to modified-immediate decoding.
The maximum-count encoding rejects size=3 and odd Q-destination D indices.
VSHLL joins the existing FP/AdvSIMD access classification and remains outside
scalar SMIR/native admission. Existing mnemonic variant positions are retained
by appending the new variant.

| Encoding | Source width in bits | Shift count | Destination |
|---|---|---|---|
| A1/T1, zero count | 8, 16, 32 | 0, decoded as VMOVL | Twice the element width in Qd |
| A1/T1, nonzero count | 8, 16, 32 | 1 through width minus one | Twice the element width in Qd |
| A2/T2 | 8, 16, 32 | Exactly the source width | Twice the element width in Qd |

The primary reference is [Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf),
one-based PDF pages 1343-1345 for VSHLL and 1351-1352 for VSHRN. The
instruction-specific fixed fields for the rounding and saturating narrowing
forms are also retained in `docs/architecture/arm/asl/arm_instrs.asl`.
[Provenance](provenance.json) records the primary and tool hashes.

Widening snapshots its complete D source before publishing either destination
half. This preserves aliases including a source in the high half of Qd.
Signed and unsigned shifts use `i128` and truncate to twice the source width.
The largest source width and count are 32 bits, so the largest unsigned result
is `(2^32 - 1)*2^32 = 2^64 - 2^32`, within `i128`. Integer widening leaves
FPSCR unchanged. Decode takes constant time/space; execution takes time and
temporary space proportional to the source lane count, at most eight lanes.

The pre-fix complete control target passed 115 tests and failed seven.
The correction is covered by the complete 122-test control target, including
all D/M register fields, ordinary counts, maximum-count sizes, fixed bits,
signedness, source aliases, related modified immediates, FP denial and trap
priority, failed Thumb IT, mixed-width zero retirement, and precise native
rejection. The unfiltered library run passed 12,479 tests, failed zero and
ignored 36; the qualification lists each ignored case.
[Qualification](qualification.json) records the exact tested source and broad
gates, with upstream integration checks recorded separately.

LLVM assembled 30 named boundary controls in [ARM](arm.S) and [Thumb](thumb.S).
The independent QEMU control runs all 230 legal count/ISA/signedness records
and 86 reserved records. It checks exact D0/D1/FPSCR results, including VMOVL
aliases, maximum-count VSHLL and unchanged state for Undefined instructions.

```sh
python3 docs/development/a32-widen-narrow/qemu-controls.py --out /tmp/rax-widen-narrow-results
```

The output directory must not exist. This harness reuses the text guest
transport in `a32-immediate-shifts/qemu-controls.py`, whose hash is recorded.
It retains observations and metadata, and removes temporary objects and
executables. QEMU evidence does not establish physical AArch32 execution.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| W1 | Fixed widening/narrowing fields require Undefined before FP access | Primary encoding; 86 QEMU exceptions; register/immediate matrices and denied controls | Confirmed within scope |
| W2 | Both VSHLL encodings and VMOVL aliases are base AdvSIMD forms | All legal counts, both ISAs/signedness, maximum shift and source aliases; 230 QEMU controls | Confirmed |
| W3 | Zero high immediate bits select related modified immediates | Instruction-specific SEE rule and all legal cmode/op partitions in the owning target | Confirmed |
| W4 | Vector widening remains outside scalar native admission | Exact Unsupported frontier checks and complete scalar native targets | Qualification records the actual gates |

High-impact remaining instruction/profile, complete backend/private/in-flight
state, interrupt/clock/replay and native streaming-FPSR requirements remain
open. This component does not close the original four findings.
