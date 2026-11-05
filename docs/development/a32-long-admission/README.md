# AArch32 long-multiply selector admission

Reserved P8 VMULL encodings such as A32 `f3800e00` and T32 `ff800e00`
previously executed polynomial multiplication. The vector VQDMLAL, VQDMLSL,
and VQDMULL forms also ignored their fixed-zero selector. These encodings
could modify vectors with FP enabled, or select an FP-access exception when
Undefined was required.

The decoder now rejects those selectors before FP-access checks. Execution
shape checks retain the same restriction. Ordinary signed and unsigned
VMLAL/VMLSL/VMULL retain their existing allocation and semantics. Each new
selector check uses constant time and auxiliary space.

The primary reference is [Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf),
one-based PDF pages 1146-1147 (VMULL integer/polynomial), 1202-1203
(VQDMLAL), 1205-1206 (VQDMLSL), and 1212-1213 (VQDMULL). These are mandatory
encoding constraints. P64 PMULL feature admission and constrained
unpredictability are outside this correction. [Provenance](provenance.json)
records the local manual and tool hashes.

The baseline census observed 229376 mismatches among 917504 combinations:
seven instruction/width forms, two instruction sets, both selector values,
and all 32 values of each D/N/M register field. The baseline complete control
target passed 103 tests and failed three. The new controls also cover legal
results, unsigned integer neighbors, denied FP access, Hyp and mixed-width
execution, unchanged architectural state, and failed Thumb IT conditions.

The independent Cortex-A15 QEMU runs execute 28 cases: 14 legal controls and
14 reserved controls. Reproduce them with:

```sh
python3 docs/development/a32-long-admission/qemu-controls.py --out /tmp/rax-long-qemu-results
```

The output directory must not exist. The harness removes its temporary
object/executable directory on exit. Its JSON records instruction words,
observed Undefined/completion markers, exact D0/D1 values, tool commands,
and executable hashes. This is emulation evidence; physical AArch32
execution remains unqualified.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| L1 | The selected P8 and vector doubling-long forms require a zero selector; decode must reject before FP access | Instruction-specific primary encoding; both selector values, both ISAs, all D/N/M fields, and independent QEMU allocation | Confirmed within this scope |
| L2 | Unsigned integer long neighbors remain legal | Independent wrapping-integer formulas at all three element widths, both signedness values, and both ISAs | Covered by owning controls |
| L3 | Unsupported NEON remains outside SMIR native admission | Scalar A32/Thumb lifters reject these mnemonics; JIT and no-JIT complete control targets exercise the interpreter boundary | Qualification records the actual runs |

[Qualification](qualification.json) records complete-target results and source
hashes. The complete control target passes 106 tests with JIT enabled and
with `RAX_NO_JIT=1`; the five-pair, 524-VFP, 46850-ARM, 26-A32-native,
25-Thumb-native, and 246-C-API targets also pass. Formatting, all-target build,
and Clippy succeed. The doctest command executes zero examples and ignores
five. The full library test binary was not rerun for this narrow group.

High-impact remaining A32 profile/admission defects and complete
backend/private/checkpoint/interrupt/replay requirements remain open. This
component does not close the four original findings.
