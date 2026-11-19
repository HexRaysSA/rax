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

## Banked register in a cross-width trap syndrome

An AArch32 CPACR or HCPTR system-access trap to AArch64 reports the X-register
view of the transferred register in `ESR_ELx.ISS[9:5]`. The same rule applies to
VMRS ID-group traps to AArch64 EL2. For example, FIQ R8 is X24 and supervisor
R14 is X18. The flag-setting MRC form with encoded Rt=15 reports 31. An
AArch32 Hyp trap reports the encoded R-register number in HSR.

The implementation reuses the register mapping used by mixed-width execution.
Syndrome construction takes O(1) work and storage. The RAX tests cover ARM and
Thumb, CPACR reads and writes routed to EL2 and EL3, HCPTR reads and writes
routed to EL3, FPSID and all three MVFR reads, and unchanged guest registers
and retirement counts at the trap.

QEMU 11.1.2 independently agreed on the ten CPACR and four HCPTR cases. In four VMRS cases it
reported the encoded AArch32 register number. Both the pinned Arm 2025-12
syndrome pseudocode and DDI 0487B.a specify the AArch64 view for those traps.
[Pinned Arm pseudocode](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L12926)
[Arm DDI 0487B.a, D7.2, page D7-2263](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)
[Qualification and observations](a32-fp-controls/banked-register-traps.json)

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

## Integer VPADD selector

Integer VPADD requires bit 24 clear in A32 and bit 28 clear in T32. The
set-bit vector encoding belongs to VQRDMLAH on FEAT_RDM implementations.
VPMIN and VPMAX accept either selector for signed and unsigned elements.
These checks take constant time and storage.
[Arm DDI0597 ID032025, PDF pages 1182 and 1220](../specifications/arm/aarch32-isa-2025-03.pdf)

The owning tests vary all D, N and M register fields, sizes, selectors and Q
values in both execution states. They also check failed Thumb IT predicates,
competing access denials and mixed-width zero retirement. An independent
QEMU Cortex-A15 run matched 32 controls, including the six legal VPADD
results and preserved data on Undefined. LLVM's Armv8.1-A disassembler
independently identifies the corresponding VQRDMLAH encoding in A32 and T32.
The complete `a32_fp_controls`, `arm_vfp_a32`, and `arm` targets passed
151, 524, and 46,850 tests on Apple Silicon. Workspace all-target Clippy and
format checks passed.

## AArch32 FEAT_RDM

VQRDMLAH and VQRDMLSH execute in A32 and T32 when `ID_ISAR5.RDM` is 1 and
the profile has a D32 register bank and `MVFR1.SIMDInt` is 1. Guest
readback applies the same capability checks. The standalone default reports
RDM 0. Mixed-width CPUs derive the field from `ID_AA64ISAR0_EL1.RDM`
and report it through both AArch32 MRC and AArch64 MRS of the AArch32 ID
register. Raw saved capability values are preserved. A missing, incompatible,
or reserved capability selects Undefined before FP permission traps.
Executed Thumb IT slots select the architecturally permitted Undefined outcome.
[Arm DDI0597 ID032025, VQRDMLAH and VQRDMLSH, PDF pages 1220–1227](../specifications/arm/aarch32-isa-2025-03.pdf)
· [Arm DDI0487B.a, G6.2.107–108](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

For signed input lanes `a`, `b`, and accumulator `d`, with lane width `w` of
16 or 32 bits, the unsaturated result is
`d + ((s * 2 * a * b + 2^(w-1)) >> w)` using an arithmetic shift. The sign
`s` is +1 for VQRDMLAH and -1 for VQRDMLSH. Signed saturation to width `w`
then sets sticky FPSCR.QC if any lane clips. Intermediate arithmetic fits
signed 128 bits. Execution uses time and storage linear in lane count, bounded
by eight lanes. A scalar source is sampled before the destination is changed.

An independent QEMU 11.1.2 run matched 64 cases across A32, T32, both initial
QC values, D and Q forms, indexed and vector operands, and the `max` and
`cortex-a15` CPU models. The RAX controls also check minimum-times-minimum
without premature saturation, reserved capability fields, mixed-width readback,
and TID3 traps. The full A32 FP controls, VFP A32, and ARM targets passed 155,
524, and 46,850 tests. The A32/T32 SMIR lifters report these operations as
unsupported. Physical AArch32 execution and the broader profile audit remain
open.

The readback regression reproduced a D16 guest reporting RDM=1 while a
legal RDM word returned Undefined. It now checks D16, missing and reserved
SIMDInt, and reserved RDM levels. The mixed-width cases also retire a
legal RDM word with SIMD floating-point arithmetic disabled. The 64 QEMU
cases were replayed against the enabled and absent standard profiles.
All 47,661 tests across `a32_fp_controls`, `arm`, `arm_vfp_a32`, and
`isa_oracle` passed on Apple Silicon.

## AArch32 BF16 allocation

The current AArch32 profiles omit FEAT_AA32BF16. The A32 and T32
allocations for BF16 conversion, dot product, matrix multiply-accumulate,
and widening multiply-add decode as Undefined. Scalar conversions
preserve A32 conditions and Thumb IT predication. An executed undefined
word takes precedence over FP access traps on the mixed-width software
CPU. Decode uses a fixed number of masks and constant storage.
[Arm DDI0597 ID032025, pages 875–876, 888–889, 912–913, 916–919, 936–938, and 1092–1093](../specifications/arm/aarch32-isa-2025-03.pdf)

LLVM MC identified the instruction forms and the affected p13 encoding
`0xfe020d44` as indexed `VDOT.BF16`. QEMU 11.1.2 (Cortex-A15) matched 38
guest cases across A32 and T32, including 32 undefined instructions, four
predicate skips, and two legal FP move controls. The oracle checked D0, D1,
and FPSCR. The RAX regressions also checked all general and FP data registers
in the standalone executor, higher-EL FP access trap priority in the
mixed-width CPU, and neighboring FP16 and coprocessor decodes.
The `arm`, `arm_vfp_a32`, `a32_fp_controls`, and `a32_fp_pairs` targets
passed 46,850, 526, 169, and 5 tests on Apple Silicon.

## AArch32 dot product, integer matrix, and complex SIMD allocations

The earlier allocation fix covered profiles without FEAT_DotProd, FEAT_AA32I8MM,
or FEAT_FCMA. It routed those allocations to Undefined before coprocessor
dispatch. The predecessor decoded `0xfc220d04`
(`VSDOT.S8`) as `STC`. The masks cover the vector and indexed dot products,
the integer matrix operations, and the vector and indexed complex operations.
Decode takes constant time and storage.
[Arm DDI0597 ID032025, VCADD, VCMLA, VSDOT, VUDOT, VSMMLA, VUMMLA, VUSMMLA, VSUDOT, and VUSDOT](../specifications/arm/aarch32-isa-2025-03.pdf)

LLVM MC supplied words for 16 forms in each execution state. A QEMU 11.1.2
Cortex-A15 guest reported 32 undefined instructions and completed both legal
FP move controls with the expected D0, D1, and FPSCR values. RAX checked
register preservation, mixed-width fault priority, SMIR rejection, and
neighboring FP16 and `CDP2` encodings. All 47,551 tests across the four owning
targets passed on Apple Silicon. Physical AArch32 execution remains unverified.

Standalone CP15 reads report absent `ID_ISAR6.{I8MM[27:24],BF16[23:20]}`
even if a host override or a saved state supplies those bits. AArch64 MRS
and mixed-width MRC report the same AArch32 view. Raw saved fields remain
round-trippable.
[Arm ASL definitions](../architecture/arm/asl/arm_regs.asl),
[Linux arm64 sysreg field table](../specifications/arm/native-context-feature-registers/linux-sysreg.txt)

## AArch32 FEAT_FCMA

VCADD and both forms of VCMLA now execute in A32 and T32. Standalone
AArch32 takes the feature from the saved or configured `ID_ISAR5.VCMA`.
Mixed-width PEs derive it from `ID_AA64ISAR1_EL1.FCMA` for both AArch64 MRS
and AArch32 MRC. Effective VCMA requires value 1, the D32 bank, SIMDInt,
and SIMDSP. FP16 operands separately require SIMDHP=2. The standalone
reset profile reports VCMA=0. The guest readback and instruction gate use
the same dependencies and retain the raw state representation.

Invalid Q register pairs and absent features report Undefined before FP
access traps. Thumb skips a failed IT predicate and selects Undefined for
an executed IT slot. Each pair uses the Advanced SIMD standard FP controls.
VCMLA fuses the multiply and add with a single rounding, and the indexed
form samples its complex source before writing any destination register.
Results update FPSCR cumulative flags. Execution takes O(p) time and
constant extra storage, with at most four complex pairs.
[Arm DDI0597 ID032025, VCADD pages 799–801 and VCMLA pages 839–844](../specifications/arm/aarch32-isa-2025-03.pdf)

LLVM MC verified identical architectural words for the A1 and T1 forms.
QEMU 11.1.2 executed 88 legal `max` cases and 88 Cortex-A15 Undefined
controls. The 44 distinct legal result vectors are replayed in both states
with full D-register and FPSCR comparisons. They cover both element and
vector widths, all rotations, indexed aliasing, fused rounding, and NaN
and subnormal handling. The A32/T32 SMIR lifters report these operations as
unsupported for interpreter fallback. Physical AArch32 execution and
the remaining FP profile audit remain open.
[QEMU replay vectors](../../tests/suites/backend/a32_fp_controls/complex-qemu.tsv)

## AArch32 FEAT_DotProd

The previous executor returned Undefined for `VSDOT` even with the DP
feature bit set. Vector and indexed `VSDOT` and `VUDOT` now execute in A32
and T32. Standalone AArch32 takes DP from its saved or configured
`ID_ISAR6.DP`. Mixed-width PEs derive it from `ID_AA64ISAR0_EL1.DP` and
expose the same effective field through AArch64 MRS and AArch32 MRC.
Readback and execution require DP=1, a D32 register bank, and SIMDInt.
The standalone reset profile reports DP=0. The saved field uses the
existing format.
[Arm ID_ISAR6](https://developer.arm.com/documentation/111107/2026-03/AArch32-Registers/ID-ISAR6--Instruction-Set-Attribute-Register-6)

Absent features and invalid Q register pairs select Undefined before FP
access traps. A failed Thumb IT predicate skips the instruction. An executed
IT slot selects Undefined. Each result lane adds four byte products to the
32-bit accumulator modulo 2^32 and preserves FPSCR. A signed byte product
ranges from -16,256 to 16,384 and an unsigned product ranges from 0 to 65,025.
Both four-product sums fit in a signed 32-bit temporary. The indexed form
reads its source before either half of the destination is written.
Execution takes O(lanes) time and constant extra storage for at most four lanes.
[Arm DDI0597 ID032025, VSDOT pages 1325–1328 and VUDOT pages 1446–1449](../specifications/arm/aarch32-isa-2025-03.pdf)

LLVM MC verified 18 A1/T1 encoding pairs. QEMU 11.1.2 completed 36
enabled cases with `max` and reported Undefined with unchanged registers
and FPSCR for all 36 Cortex-A15 controls. The replay covers both
signednesses, both vector widths, both indexed lanes, high registers,
aliasing, and 32-bit wrap. RAX also exercises reserved feature levels,
the D16 and SIMDInt prerequisites, invalid register pairs, and HCPTR trap
priority. All 47,660 tests across `a32_fp_controls`, `arm`, `arm_vfp_a32`,
and `isa_oracle` passed on Apple Silicon. The SMIR lifters use interpreter
fallback for this instruction family. Physical AArch32 execution and the
remaining FP audit stay open.
[QEMU replay vectors](../../tests/suites/backend/a32_fp_controls/dot-product-qemu.tsv)

## Original ARM audit replay

The audit author's `audit_arm/repro_full_cpu.rs` ran unchanged against the
published software CPU implementation at
`dacaae9ab251703aedeab104b6a5f3f332ebe770`. The source SHA-256 is
`d4d06f509b2df4d2c34dc8d723ca8aa80ffdead7e04ecada5a7b1bf0befa1285`.
All six A32 scalar FP cases now agree with the expected S0 and FPSCR values in
section 5.3. The six A64 FP controls reproduced their original output
byte-for-byte. The seven A64 memory cases returned the expected values or
public fault classes and addresses. The harness does not expose walk levels.
[Original audit](audit-2026-10-source/audit_root_en.md#53-distinguishing-a32-fp-failures-from-passing-a64-controls)

The isolated source projection copied the original file into `examples/`
and used `cargo +stable run --locked --no-default-features --features
x86_64-suite,smir-jit,hvf,debug --example audit_arm_replay`. The comparison
checked the original case order and all printed result bits, status bits,
and public memory fault fields. Replay stdout SHA-256 is
`fad241e33c6369474152d55111d72d2a2baab8baa7cb3d1a3f711526e99d9716`.
Optional profiles, security and debug controls, and physical A32 execution
remain open.
