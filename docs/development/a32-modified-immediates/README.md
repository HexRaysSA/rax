# AArch32 modified-immediate allocation

The modified-immediate decoder omitted fixed bits 21:19. Unallocated
shift-space records could fall through as VORR or VBIC, modify vectors, or
select FP-access traps. The execution dispatcher duplicated the same broad
predicate.

Decode and execution dispatch now share the primary-defined allocation
predicate. Bits 21:19 must be zero. Valid higher-priority shift, narrowing,
widening and fixed-conversion encodings retain their own decoders. Canonical
VMOV, VMVN, VORR and VBIC literal expansion and architectural state storage
remain unchanged.

The primary source is [Arm instruction ASL](../../architecture/arm/asl/arm_instrs.asl),
entries `aarch32_VMOV_i_A`, `aarch32_VMVN_i_A`, `aarch32_VORR_i_A` and
`aarch32_VBIC_i_A`. Their A32 pattern begins `1111001x 1x000xxx`; the T32
equivalent begins `111x1111 1x000xxx`. [Provenance](provenance.json) retains
the exact masks, source checksum and tool identities.

The complete pre-fix FP-control target passed 126 tests and failed three.
The failures independently expose invalid decode admission, standalone FP
access priority and mixed-width trap selection. The registered 129-test target
covers these regressions, all 256 canonical literal values and 31 mode/opcode
combinations, D/Q alignment, high D indices, exact expansion/data effects,
failed Thumb IT suppression, preserved integer/vector/FPSCR state, zero
retirement and precise native rejection. [Qualification](qualification.json)
records actual commands, source identities and results.

The allocation test checks
`256 * 31 * 2 lengths * 32 D indices * 2 ISAs = 1,015,808` canonical records.
The independent data test executes 111,104 legal records. Decode and literal
execution use constant time and space: at most two D registers are written.

The independent [QEMU harness](qemu-controls.py) executes 33,912 records:

| Partition | Records | Compared fields |
|---|---:|---|
| All legal literal/mode/opcode/D-or-Q/ISA combinations at D0 | 31,744 | Completion class, D0, D1, FPSCR |
| Nonzero fixed prefix in the unallocated neighboring opcode | 896 | Undefined completion, unchanged D0/D1/FPSCR |
| Canonical reserved mode/opcode combination | 1,024 | Undefined completion, unchanged D0/D1/FPSCR |
| Odd Q-destination D1/D31 boundaries | 248 | Undefined completion, unchanged D0/D1/FPSCR |

All observations match. The [receipt](qemu-result.json) records ordered-output,
source and executable hashes. The repository retains the compact receipt and
reproducer; full observations and case descriptions remain in the local audit
directory identified by provenance. Generated guest assembly, objects and the
executable are removed after execution.

```sh
python3 docs/development/a32-modified-immediates/qemu-controls.py --out /tmp/rax-modified-immediate-results
```

The output directory must not exist. The harness requires LLVM MC, LLD and
QEMU system ARM, and reuses the checked-in text transport in
`a32-immediate-shifts/qemu-controls.py`. It bounds each child by 45 s. QEMU
Cortex-A15 execution establishes this reference profile; physical AArch32
execution remains unqualified.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| M1 | Fixed bits 21:19 distinguish modified immediates from neighboring classes | Four primary instruction entries; all 896 neighboring QEMU exceptions; complete reserved field matrix | Confirmed within this domain |
| M2 | Every canonical literal expansion retains its architectural result | All 256 literals and 31 legal mode/opcode combinations, both ISAs and lengths; exact QEMU and direct integer equations | Confirmed by independent QEMU; qualification records RAX gates |
| M3 | Restricting fallback preserves earlier valid shift/conversion allocation | Complete owning, ARM and VFP targets, including existing shift/widen/narrow matrices | Qualification records actual gates |
| M4 | These vector operations retain their scalar-native frontier | Exact Unsupported-address controls and complete scalar native targets | Qualification records actual gates |

The prior full-root library result remains pinned to the source recorded by
[widening/narrowing qualification](../a32-widen-narrow/qualification.json).
This component runs its complete unfiltered owning target and affected semantic
and workspace gates; it does not claim a fresh unfiltered root-library run.

High-impact remaining profile/security/debug, complete backend/private/in-flight
restoration, IRQ/clock/replay and native streaming-FPSR requirements remain
open. This component does not close the four original audit findings.
