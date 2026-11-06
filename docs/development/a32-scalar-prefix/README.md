# AArch32 scalar FP prefix and coprocessor allocation

Ordinary scalar FP data decoding previously ignored mandatory coprocessor and
prefix bits. For example, `ee020d44` and `ee810e02` selected VMLS and VDIV for
coprocessors 13 and 14; `feb10b42` selected scalar VNEG in the unconditional
encoding space. These words could select FP execution or an FP-access trap.

The shared scalar decoder now requires `(raw & 0x0f000c10) == 0x0e000800`.
This checks major bits 27:24 = `1110`, coprocessor bits 11:10 = `10`, and
bit 4 = 0. Within this class, size bits 9:8 = `00` and condition bits
31:28 = `1111` select Undefined. Other coprocessors retain their existing
generic decode path. The earlier unconditional VSEL, VMAXNM/VMINNM, rounding,
conversion, VMOVX and VINS decoders retain priority. The guard takes constant
time and space and introduces no state or public API changes.

The authoritative references are the archived
[Arm ASL](../../architecture/arm/asl/arm_instrs.asl), entries
`aarch32_VDIV_A1_A`, `aarch32_VDIV_T1_A`, `aarch32_VNEG_A2_A`,
`aarch32_VNEG_T2_A`, and the scalar VMLA/VMLS entries; and
[Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf),
one-based PDF pages 917–918 (VDIV), 1070–1072 (floating-point VMLA),
and 1154–1157 (VNEG).

An LLVM disagreement for `ee120954` was excluded from the defect set:
`aarch32_VMOV_h_A1_A` and its T32 counterpart mark six omitted fields as
`x`. Those fields are preserved. The corresponding PDF pages are 1097–1098.
[Provenance](provenance.json) pins both primary sources and oracle tools.

The complete pre-fix `a32_fp_controls` target ran 135 tests: 131 passed and
four failed. The failures cover generic coprocessor aliasing, unconditional
scalar prefixes, FP exception priority/state preservation, and mixed-width
fault/retirement behavior. The two preservation controls already passed.
The corrected complete target passed all 135 tests with no ignored or filtered
cases. The final [qualification](qualification.json) records complete affected targets,
commands, source identity, and any ignored or unrun checks.

The six added tests cover all 16 coprocessor numbers for three arithmetic
families and A32 conditions 0–14, both instruction sets, all 32 D/M register
fields in selected invalid prefixes and valid unconditional extensions,
CPACR/Hyp/FPEXC denial controls, unchanged registers/status on rejection,
SMIR unsupported frontiers, and AArch64/AArch32 bridge non-retirement.
VMOV_h controls exercise all 64 ignored-field combinations, both directions,
all 16 core and 32 scalar register fields, and both instruction sets.

The independent QEMU Cortex-A15 guest rejected all 12 invalid A32/T32 cases
and completed all eight legal VMOV/VNEG controls. It checks exact D0, D1
and FPSCR values, including preserved sticky flags. It does not establish
physical AArch32 execution, every profile, or every scalar encoding.

```sh
python3 docs/development/a32-scalar-prefix/qemu-controls.py --out /tmp/rax-scalar-prefix-results
```

The output directory must not exist. LLVM MC, LLD and QEMU must be available;
missing tools fail the harness. Temporary objects and executable are removed.
[Oracle observations](qemu-observations.json) retain the actual case results.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| P1 | Ordinary scalar data requires the fixed major/coprocessor/conditional prefix | Primary encodings; all coprocessors, conditions, both ISAs, high register fields and earlier extensions; falsified by a primary-defined legal ordinary encoding failing the predicate | Primary confirmed; complete target results in qualification |
| P2 | VMOV_h ignored fields retain their current allocation | All 64 values, directions and register fields; falsified by a primary mandatory-bit/decode restriction | Primary confirmed; baseline preservation control passed |
| P3 | Non-FP coprocessor neighbors acquire no FP side effects or FP-access traps | Enabled/denied FP, Hyp TCP10, FPEXC disabled, SMIR and mixed-width frontiers; falsified by an FP dispatch or changed state | Final regression results in qualification |

High-impact remaining profile controls, complete backend/private/in-flight
checkpoint state, configured SMP execution, interrupts, clocks and replay
remain open under A32-FP, C-STATE, C-SMP and C-HVF. The native ARM streaming
FPSR SDK counterexample remains separate. Medium-impact generic CDP2 and
LDC2/STC2 mnemonic classification is outside this scalar FP correction.

A separate diagnostic found unconditional core/system-transfer words
`fc410b10`, `fe000a10` and `fef10a10` still selecting VMOV or VMRS,
and `fd900b00` selecting SVC. QEMU rejects all eight A32/T32 cases; eight
legal controls pass. These earlier/other decode paths require a separate
correction. This scalar data group does not claim those cases are repaired.

The first complete C API run passed 245 tests and failed the installed-runtime
functional check at its 30 s host deadline. That result remains a failure;
qualification records its diagnosis and any separate test-budget followup.

The incoming Windows-only commit `95d9c3f8b` was integrated by fast-forward.
It changes none of the validated ISA, SMIR, backend, VM, C API, feature/lock
or owning-test paths. Complete C API and compiler/build/format gates are
refreshed on that integrated state. The C API deadline followup has its own
[qualification](../capi-runtime-work-budget/qualification.json).
