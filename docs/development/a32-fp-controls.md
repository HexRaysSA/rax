# AArch32 FP access controls

The standalone AArch32 executor and the AArch32 view of an AArch64 PE share
`src/isa/arm/aarch32/fp_controls.rs`. Classification and permission checks occur
after the instruction predicate passes and before register or memory effects.
The enclosing PE supplies exception-level presence, security state, execution
widths, and its actual controls. Standalone reset state is not substituted for
mixed-width guest state.

The policy implements the represented controls below. This component does not
close the broader A32-FP finding.

| Control | Represented behavior |
| --- | --- |
| CPACR.cp10 | Denied, privileged-only, and full-access values; ignored in Hyp mode |
| CPACR.ASEDIS | AdvSIMD denial outside Hyp mode |
| FPEXC.EN | Ordinary data-access gating; system-register exceptions; effective EN=1 at A32 EL0 under A64 EL1 |
| NSACR | Non-secure CPACR/HCPTR read/write clamps and effective access restrictions |
| HCPTR.TCP10/TASE | Lower-EL Hyp trap or same-Hyp Undefined Instruction entry, with EC=7 syndrome |
| HCPTR/CPTR_EL2.TCPAC | Valid EL1 CPACR access traps to EL2, with EC=3 syndrome |
| CPTR_EL2.TFP/FPEN | Ordinary and VHE higher-EL FP controls |
| CPTR_EL3.TFP/TCPAC | FP, CPACR and represented HCPTR traps to EL3 |
| HCR.TID0/TID3 | VMRS FPSID/MVFR group traps after ordinary FP permission checks, with EC=8 syndrome |

Hyp control registers are available in Hyp mode, or in Monitor mode with
SCR.NS=1, when the EL is implemented. Non-secure EL1 cannot rewrite the
represented Secure/Hyp controls. CPACR is shared between Secure and Non-secure
states. The selected modern 32-D-register profile implements ASEDIS; D32DIS is
RES0. CP11 does not independently gate FP execution; software should program it
consistently with CP10.

Mixed-width CPACR, HCPTR and HCR guest transfers project and commit the enclosing
PE's storage. Derived effective FPEXC.EN does not overwrite stored FPEXC32_EL2.EN.
Both direct arithmetic handlers and shared admission use the same effective
permission value.

The installed QEMU 11.1.2 reference does not implement the optional
AdvSIMD-specific access traps in its version-tagged `neon_access_check` path.
The retained NSACR.NSASEDIS witness and an additional HCPTR.TASE witness complete
the AdvSIMD instruction, while the same instruction under HCPTR.TCP10 traps.
Readback retains the programmed NSASEDIS/TASE bits. These results remain
explicit reference differences; they do not replace the selected RAX profile's
Arm-defined access checks. The pinned QEMU source and provenance are under
`a32-fp-controls/references/qemu-11.1.2`; release commit
`4fc49f46dc95d4a27de2509e7fceb2931e91faeb`. The release source explains the
observed distinction; the installed binary has a matching version string but
has not been reproduced from that source. Raw witnesses remain under
`four-findings-a32-profile/reference-hyp-v4` and `reference-hyp-v5-tase`.

Unallocated FP coprocessor transfers and represented invalid VMRS/VMSR register,
opcode or Rt forms raise Undefined Instruction instead of reaching the generic
unmodelled-coprocessor no-op/read-zero fallback. Instruction-specific reserved
encoding checks remain a separate inventory; this statement does not cover every
AdvSIMD encoding.

Hyp exception entry saves the instruction address in ELR_hyp, preserves the
banked SPSR and syndrome, clears IT/IL, and selects HVBAR+0x04 for an Undefined
Instruction taken in Hyp or HVBAR+0x14 for a lower-EL trap. An A32 Undefined
Instruction taken to ordinary Undefined mode uses LR=PC+4; T32 uses LR=PC+2,
including a 32-bit T32 instruction. EL0 Undefined Instruction is routed to Hyp
when HCR.TGE requires it. Fault entry does not retire the faulting instruction.

## Register-pair admission and data routing

`VMOV_ss` encodes the first single register as `Vm:M`; odd starts S1 through
S29 are legal. `VMOV_d` uses `M:Vm`, including D16 through D31. The decoder and
executor preserve this distinction. Invalid PC operands, a single pair starting
at S31, and equal GPR destinations for a transfer to core registers select the
Undefined outcome for the specified unpredictable operands. These decode
constraints precede FP control checks. Failed ARM conditions and Thumb IT
conditions suppress execution and effects.

`a32_fp_pairs` covers 54,810 legal GPR/FP register-field combinations, all other
registers and flags, invalid-operand priority, failed predicates, and 252
mixed-width projections. Independent QEMU guests complete 124 single-pair and
128 double-pair data-projection cases across ARM and Thumb; their inputs and
outputs remain under `four-findings-a32-pair-admission`. The first Thumb harness
used the M-profile semihosting BKPT and timed out after printing correct data;
it is excluded from completed-run counts. Corrected A-profile T32 SVC runs
complete normally. See the [Arm semihosting ABI](https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst).

Invalid or privileged FP system-register accesses retain the existing
`ExecResult::Undefined` diagnostic API. A valid instruction denied by FP access
controls returns the architectural Undefined Instruction exception instead.
The complete existing VFP binary verifies the distinction.

## Primary provenance

The pinned Arm XML 2025-12 pseudocode is
`docs/specifications/arm/pauth/shared_pseudocode-2025-12.xml`, SHA-256
`84c3572ef27cb9a7b12cba314d62d1b8afd71c770ee92d818cbdb4dc6ac37d6b`.
Relevant functions are `AArch32_CheckAdvSIMDOrFPEnabled`,
`AArch32_CheckFPAdvSIMDTrap`, `AArch32_CheckAdvSIMDOrFPRegisterTraps`,
`AArch64_CheckFPAdvSIMDTrap`, `AArch32_SystemAccessTrapSyndrome`,
`ConditionSyndrome`, `AArch32_EnterHypMode`,
`AArch32_TakeUndefInstrException`, and `AArch32_TakeHypTrapException`.
VMRS/VMSR instruction pseudocode also appears in the pinned
`docs/architecture/arm/asl/arm_instrs.asl`.

Register access and profile details are cross-checked against manufacturer
manuals, without treating a named processor as the complete identity of this PE:

- [Arm ARMv7-A/R Architecture Reference Manual, HCPTR and PL2 access](https://documentation-service.arm.com/static/5f8daeb7f86e16515cdb8c4e).
- [Arm Cortex-A15 TRM, HCPTR and NSACR clamps](https://documentation-service.arm.com/static/5f042143dbdee951c1cd7f8c).
- [Arm Cortex-R52+ TRM, HCPTR fields](https://documentation-service.arm.com/static/66548bde4072745e25d841c5).
- Local Cortex-A9 DDI0388G, CPACR shared storage and NSACR access permissions.

## Assumption register

| ID | Assumption/selected policy | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| A1 | Newer pinned Arm XML defines access ordering when older local ASL differs | Compare complete access-check functions and probe competing denial controls | Retained; revision pinned |
| A2 | Reserved CPACR.cp10=2 selects the permitted deny outcome | Exercise the reserved value at EL0/EL1 and verify no FP effects | Explicit constrained-unpredictable policy |
| A3 | For EL0 under A64 EL2 with {TGE,RW}={1,0}, effective EN=1 is selected | Execute with stored EN=0 and verify execution leaves stored EN unchanged | Explicit implementation-defined policy |
| A4 | T32 trap syndromes report CV=1 and the instruction's current IT condition | Trap a passing IT NE instruction and inspect ISS[24:20] without advancing IT | Explicit implementation-defined policy |
| A5 | The represented PE does not implement optional EL3 SDD Undefined priority | Inventory advertised feature flags and the EL3 control surface | No SDD feature advertised; must revisit if added |

## Evidence and limits

The owning `a32_fp_controls` test target executes in both backend/storage CI
selections. Its contracts include guest control-register writes, full syndrome
fields, denied-effect preservation, A32/T32 predicates, Hyp frames, and actual
software-backend zero-retirement transitions. Full validation results and exact
frozen inputs are retained separately; the existence of this document is not a
claim that those gates passed.

Independent QEMU inputs under
`/Users/int/dev/rax-audit-work/four-findings-a32-profile/` retain tool versions,
encodings, linked guest binaries, stdout/stderr, commands and SHA-256 manifests.
`reference-mixed-v2` executes actual ERET transitions and confirms six FP access
traps to EL2/EL3, including Secure A32 EL1 configured with SCR.RW=0.
`reference-hyp-v4` confirms CPACR bypass and TCP10 denial in Hyp; its NSASEDIS
case remains a mismatch: NSACR reads 0x00008c00 but the AdvSIMD instruction
executes. The RAZ/WI hypothesis is falsified by guest readback. The underlying
reference-model cause is unknown; the mismatch is retained rather than removed
from the expected architectural domain. QEMU is not physical Arm validation.

| Impact | Remaining boundary | Blocks full A32-FP closure |
| --- | --- | --- |
| High | Complete reserved encoding/feature admission across ARM, Thumb and all FP instruction groups | Yes |
| High | CPU capability/profile consistency and all direct/lifted/native representations | Yes |
| High | Complete checkpoint preservation of new and pre-existing private/security/exception state | Also tracked under C-STATE |
| Medium | Reference-model NSASEDIS discrepancy and physical A32 validation | Validation scope remains qualified |

The component adds FP control handling; it does not establish A32 MMU/LPAE,
full virtualization, secondary startup, complete checkpoint restoration, or
physical native execution.

## Restricted scalar operating modes

MVFR0.FPRound and MVFR1.FPDNaN/FPFtZ now participate in scalar instruction
admission under the explicitly selected synchronous support-code subarchitecture.
Access permission traps retain priority over an unsupported runtime mode; reserved
capability values reject dependent encodings first. Defined restricted profiles
identify the private FPSID support-code interface. FPSCR read/write semantics
and raw identity storage remain unchanged. See [restricted scalar VFP modes](a32-restricted-fp/README.md)
for primary sources, complete owning validation, checkpoint continuation and limits.
