# VMRS/VMSR should-be-zero fields

The A32 ISA v2025-03 VMRS/VMSR diagrams mark opcode bits [7:5] and [3:0]
as `(0)`, or should-be-zero (SBZ), rather than obligatory zero. The archived
ASL patterns accordingly use `xxx1xxxx` for the low opcode byte. Arm's generic
A-profile constraint permits several outcomes when SBZ bits are nonzero,
including execution with the should-be value. The accompanying source excerpt
is the architectural specification in Appendix C.1, not a claim that RAX models
the Cortex-R82 processor.

A retained bare-metal QEMU Cortex-A15 control executes canonical `0xeef10a10`
and takes Undefined Instruction for `0xeef10a11`, `0xeef10a30`, `0xeee10a11`,
and `0xeee10a30`. Current RAX executes the latter four as canonical VMRS/VMSR.
These observed outcomes establish a profile difference. They do not establish
an architecture defect: executing the canonical operation is permitted here.
The access-control and condition checks still apply to that operation.

The preliminary hypothesis that these four encodings must be rejected is
withdrawn. No production encoding mask was changed on that basis. Other
reserved, unallocated and obligatory-bit cases require separate admission
checks; this disposition does not close A32-FP.

Primary sources are `docs/specifications/arm/aarch32-isa-2025-03.pdf`, printed
pages 1124-1129 (PDF pages 1127-1132), its VMRS/VMSR encoding diagrams;
`docs/architecture/arm/asl/arm_instrs.asl`, `aarch32_VMRS_AS` and
`aarch32_VMSR_AS`; and the generic specification in the attached Arm TRM
excerpt. `provenance.json` records its issuing organization/title/revision,
source URL, original digest and exact excerpt page/digest.

Assumption: the generic SBZ rule applies to these non-exclusive instructions.
Falsification probe: a specific VMRS/VMSR rule excluding canonical execution
for these bits, or an obligatory-zero diagram rather than an SBZ diagram.
The reviewed instruction diagrams and ASL do not contain that restriction.
Virtualization-specific interception configurations require separate controls.

Raw guest inputs, commands, QEMU outputs and the actual RAX adapter result are
retained under `four-findings-aarch64-private-state/a32-system-alias-probe-v2`
and `a32-system-alias-rax-v1` in the audit evidence. The first QEMU attempt
failed at ELF/DTB loading; the corrected explicit-PHDR guest is the behavioral
control. No failed setup attempt is counted as an instruction result.
