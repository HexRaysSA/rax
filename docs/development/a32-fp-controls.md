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
| NSACR | Non-secure CPACR/HCPTR clamps, mixed-width defaults and privilege traps |
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

## Mixed-width NSACR access

An AArch32 Non-secure read at EL1 or EL2 returns `0x00000c00` when the
enclosing PE has no EL3 or implements EL3 in AArch64. A write takes Undefined
Instruction. In Secure EL1, an access traps to an enabled AArch64 Secure
EL2, or to AArch64 EL3 when Secure EL2 is absent. The trap reports EC
`0x03`, the transfer direction and the mapped register number. The access
check takes O(1) time and space.
[Arm NSACR access pseudocode](https://df.lth.se/~getz/ARM/SysReg/AArch32-nsacr.html)

The software-vCPU test enters AArch32 with ERET and checks 16 read/write
cases across ARM and Thumb. The partitions are Non-secure EL1 with EL3
absent, Non-secure EL1 under AArch64 EL3, Secure EL1 trapping to AArch64 EL3,
and Non-secure EL2. The test checks execution state, handler PC, retirement,
destination register preservation and, for the Secure trap, ELR and ESR.
On the parent revision the mixed-width executor returned an unsupported
coprocessor-transfer error.

The seven owning ARM integration targets passed 47,632 tests. The full
library suite passed 13,215 with five ignored. Both runs were unfiltered
and reported zero failures.

| Assumption or boundary | Impact | Falsification probe |
| --- | --- | --- |
| The enclosing PE implements EL3 in AArch64 or omits EL3. | High | Run both configurations and verify identical Non-secure read and write outcomes. |
| Selecting the fallback does not change the standalone Armv7 NSACR bank. | High | Compare the standalone bank behavior and the complete owning A32 targets. |
| HSTR.T1 interception precedes these defaults on profiles that implement it. | High | Set HSTR.T1 and require an EL2 trap. See the mixed-width HSTR qualification below. |
| Secure EL2 routing follows the represented security controls. | Medium | Toggle SCR_EL3.EEL2 with FEAT_SEL2 enabled. The public-vCPU and QEMU probes observed the corresponding EL3 and EL2 vectors. |

QEMU 11.1.2 independently reproduced the Non-secure read value, the
Undefined write, and the Secure EL3 syndromes `0x0fe40403` (read) and
`0x0fe40402` (write). Its no-security Armv7 Cortex-A15 returned Undefined
for both operations. Eight further public-vCPU cases switch the Secure
trap between EL2 and EL3 in ARM and Thumb. QEMU independently confirms
both destinations and ESR values for ARM. Physical Arm remains untested.

## Mixed-width HSTR interception

The AArch64 HSTR_EL2 register and its AArch32 Hyp alias share the enclosing
PE's system register bank. The CPU checkpoint already includes that bank.
The new trap control uses a reserved checkpoint slot. A generic value
from a pre-HSTR checkpoint leaves the control at RAX's reset value of zero.
Bits 63:16, T14, and T4 read as zero and ignore writes. An EL3 read exposes zero when the profile omits AArch32 or EL2. The stored trap selection applies
only when EL2 is enabled in the current security state and the effective
VHE host combination is clear.
[Arm HSTR_EL2](https://df.lth.se/~getz/ARM/SysReg/AArch64-hstr_el2.html)
[Arm AArch32 HSTR](https://df.lth.se/~getz/ARM/SysReg/AArch32-hstr.html)
[Arm A64 shared pseudocode, AArch64_CheckCP15InstrCoarseTraps](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L13037)

For scalar MRC and MCR transfers, the CRn selector is checked
after the instruction predicate and the EL0 privilege gate, then before
register-specific traps and effects. Trap delivery preserves the source
register and reports EC 0x03 through ESR_EL2 or the AArch32 Hyp HSR.
Each transfer performs one constant-time selector check with no allocation.
A selected EL1 transfer can take this trap even when RAX lacks its
ordinary register effects. With the selector clear, the existing execution
boundary still applies.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| HSTR_EL2.T1 intercepts the NSACR access before its ordinary read or write rule. | High | Toggle T1 for ARM and Thumb NSACR reads and writes. Require zero retirement and the original operand on a trap. |
| The AArch32 Hyp alias uses the enclosing EL2 bank. | High | Write and read the alias in Hyp, enter AArch32 EL1 and check the resulting exception syndrome. |
| Saved generic values cannot arm the new control. | High | Restore a legacy-format generic value at the exact architectural encoding, then read HSTR_EL2 from EL2 and require zero. Check that AArch64 reads and writes below EL2 take Undefined Instruction. |
| The trap-only path cannot perform the ordinary operation. | High | Set T1 for a SCTLR read and T7 for the legacy CP15 wait and CP15DMB. Check ARM and Thumb syndrome, unchanged R0, handler PC, and zero retirement. Clear the selectors and require the same unsupported-state result as the parent. |
| The selector respects register class, privilege and condition execution. | High | Toggle C0, C1 and C13 selectors for ID_ISAR5, CPACR and TPIDRURW. Require EL0 NSACR denial and a false ARM condition to keep their existing result. |

QEMU 11.1.2 matched eight ARM/Thumb NSACR cases for AArch64 EL2 and eight
for AArch32 Hyp, including enabled and disabled controls. The independent
18-case public step probe covered CPACR, ID_ISAR5, TPIDRURW, denied EL0
NSACR, and a false ARM condition. The owning regressions also exercise
restore into a fresh core with the original trap selector. A separate
QEMU Cortex-A53 run reproduced the T1 and T7 cases with ESR values
`0x0fe00401`, `0x0fe81c00`, and `0x0fea1c14`, with six enabled and six
disabled cases. The RAX parent stopped with an unsupported execution state
for an enabled legacy CP15 wait. With the trap selected, the candidate
delivered all six ARM and Thumb exceptions. The candidate's six disabled
controls preserved the parent boundary. Other CP15 forms and physical Arm qualification remain open.

The seven complete owning integration targets passed 47,598 tests. The full
library passed 14,145 with 5 ignored. Both runs reported zero failures
and zero filtered cases.

### HSTR traps paired CP15 accesses

An AArch32 `MCRR p15` or `MRRC p15` uses the `CRm` field to select
the `HSTR_EL2.T<n>` bit. Scalar coprocessor transfers select the bit from
`CRn`. The mixed-width AArch64 backend checks the paired trap after the
instruction predicate and operand admission. This applies to A32 and T32
encodings. It leaves each underlying CP15 register's existing behavior in
place when the HSTR trap does not apply.

The paired exception class is 0x04. Its syndrome preserves the transfer
direction, option, CRm and both register numbers. AArch64 EL2 observes the
enclosing register numbers for banked AArch32 operands. The product probe
checks SVC and FIQ banks. An admitted trap retires zero instructions and
preserves the source pair. The selector and syndrome checks take constant
time and require no additional checkpoint state.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Paired transfers use CRm. | High | Select an MRRC/MCRR with CRm=2 and compare T2, T1 and no trap bit in both encodings. |
| Both register identifiers survive entry to AArch64 EL2. | High | Use banked R8/R9 in FIQ and require X24/X25 in the syndrome. |
| An intercepted write does not change the underlying register. | High | Use a paired write which reports an unsupported operation with T2 clear and require an architectural trap with T2 armed. |

The scalar-only baseline returned unsupported on the first intercepted
paired operation. The paired candidate passed the focused regression's
48 combinations. Separate QEMU 11.1.2 probes produced 24 AArch64 EL2
observations, 48 AArch32 Hyp observations across two QEMU targets, and
eight additional banked-register observations. Other CP15 encodings and the full A32-FP finding remain open.

## Standalone AArch32 HSTR and checkpoint ownership

The standalone adapter retains guest HSTR writes when AArch32 Hyp is
implemented. Hyp can read and write the register. Monitor access follows
SCR.NS and reads zero when EL2 is absent. Eligible Non-secure lower modes
use the HSTR selector for scalar and paired CP15 traps. A trapped transfer
preserves its operand and retirement frontier.

An active value is stored in the standalone `RAXA3203` context, whose
four-byte extension follows the previous CPU record. A reset value retains
the `RAXA3202` representation. Both older record versions import with the
control cleared. Restore rejects reserved bits before publishing any CPU
state. The enclosing AArch64 PE continues to own the mixed-width register.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The stopped CPU owns its trap control. | High | Write HSTR in Hyp, restore into a separately constructed VM, and require a precise trap at the next lower-mode CP15 instruction. |
| A malformed control cannot change an admitted CPU. | High | Import an image with a reserved bit set and compare the destination's checkpoint before and after rejection. |
| Older records cannot inherit the target's active control. | High | Restore a version-2 idle record onto an armed target and read HSTR through the guest ABI. |
| HSTR reserved bits are RES0 in the represented profile. | Medium | Write all ones and require 0xbfef. Compare trap delivery separately from QEMU readback. |

The pre-fix guest read back zero after writing T7. The candidate passed all
three focused tests, 47,632 tests across seven owning
integration targets, and 13,230 tests with 5 ignored in the full
macOS library. The QEMU guest executed the Hyp-to-SVC transition and agreed
with all 24 trap outcomes. In eight runs QEMU read back bits 4 or 14 that
the Arm register specification marks RES0. The RAX control follows the
specified mask. Physical Arm and remaining privilege and instruction
profiles stay open.

[Arm Architecture Reference Manual, EL2 configurable controls](https://support.arm.com/documentation/ddi0487/md/-Part-G-The-AArch32-System-Level-Architecture/-Chapter-G1-The-AArch32-System-Level-Programmers--Model/-G1-22-Configurable-instruction-controls/-G1-22-5-EL2-configurable-controls?lang=en)
[Arm AArch32 HSTR register description](https://df.lth.se/~getz/ARM/SysReg/AArch32-hstr.html)

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

## Legacy VFP double-register block transfers

The odd-count FLDMX and FSTMX encodings transfer one to sixteen consecutive
registers in D0 through D15. Invalid lists and bases are rejected before
checking access permissions. For N registers, the encoded word count is
2N + 1, so the encoded address span is 8N + 4 bytes, at most 132 bytes.
Only 8N bytes are accessed. The trailing word contributes to the
decrement-before start address and writeback. Both legacy and ordinary
scalar double-register transfers use CPSR.E to order the two words.
The standalone backend applies data byte order to word and halfword
accesses and fetches according to BE8 instruction order. A transfer takes
O(N) time and O(1) auxiliary space.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The odd count selects a legacy D-register block. | High | Enumerate ARM and Thumb list fields. A zero count, D16, or a list crossing D15 must take the decode fault before an access trap. |
| The trailing word contributes to the address span alone. | High | Place the final transferred word at the mapping boundary. Verify the base update and both transferred words. |
| Both CPU adapters use the same data byte order. | High | Compare the eight guest bytes and the D15 value in both byte orders through standalone and mixed-width backends. |

The parent returned Undefined for `0xec80fb03`. The composed revision
passed 47,634 tests across seven owning integration binaries.
The Cortex-A15 QEMU guest
independently matched all 24 tested ARM and Thumb encodings across transfer
direction, addressing mode, and byte order. Physical Arm execution remains
unverified.

[Armv7-A/R former VFP mnemonics](https://support.arm.com/documentation/ddi0406/c/Application-Level-Architecture/Instruction-Details/Alphabetical-list-of-instructions/F---former-Floating-point-instruction-mnemonics)

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

## AArch32 FEAT_AA32BF16

The standalone software CPU enables BF16 with host-configured
`ID_ISAR6.BF16=1`. The mixed-width software CPU takes the same explicit
selection from the saved `ID_ISAR6_EL1` entry and requires the supported
A64 BF16 level and AArch32 execution state support. Both default to BF16
absent and require D32, FPSP, SIMDInt, and SIMDSP before reporting the
feature. Guest ID reads and instruction admission use the same projection.
The test varies each prerequisite, including reserved field values, and
checks for Undefined before an enabled FP access trap.
[Arm Feature Names, pp. 81–82](../specifications/arm/audit-reference-inputs/feature_names_109697_2025_09_en.pdf)

Scalar narrowing preserves the other destination halfword, honors FPSCR
rounding, DN and FZ, and takes enabled exceptions before writing its
destination. Vector narrowing and widening fused multiply-add use
StandardFPCR and accumulate exception status. Dot products and matrix
multiply-accumulate use the fixed BF16 operation. The decoder enforces Q
register alignment, preserves A32 scalar conditions, and applies the T32
IT restrictions by instruction. These instructions use bounded time
and storage per word.
[Arm DDI0597 ID032025, pp. 875–876, 888–889, 912–913, 916–919, 936–938, 1092–1093 and 2229–2230](../specifications/arm/aarch32-isa-2025-03.pdf)

The baseline rejected all 14 opt-in probes. With BF16 enabled, the
software interpreter matched QEMU 11.1.2 `max` on 896 legal cases and
eight malformed Q operands across A32 and T32. The disabled profile
matched all 904 Cortex-A15 cases. Comparisons covered the instruction
outcome, every D register, and FPSCR, including high register numbers,
source and destination overlap, exceptional operands, and all scalar
rounding modes. Regressions cover mixed-width state import, access
priority, scalar exception enables, and SMIR rejection. Physical
AArch32 execution remains unverified.

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

The earlier profile suppressed `ID_ISAR6.I8MM[27:24]` while preserving
the raw saved field. The I8MM implementation below supplies the effective
view for standalone CP15, AArch64 MRS and mixed-width MRC.
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

## AArch32 FEAT_AA32I8MM

`VSMMLA`, `VUMMLA`, `VUSMMLA`, `VUSDOT` and `VSUDOT` now execute in
A32 and T32. The standalone CPU selects the feature with
`ID_ISAR6.I8MM=1`. A mixed-width CPU requires the saved
`ID_ISAR6_EL1.I8MM=1` selection, `ID_AA64ISAR1_EL1.I8MM=1`, and
AArch32 EL0 support. Both use the effective D32 and SIMDInt checks for
ID readback and instruction admission. The default AArch32 selection
is absent. The existing saved ID field carries the selection.
[Arm Feature Names, page 41](../specifications/arm/audit-reference-inputs/feature_names_109697_2025_09_en.pdf)

The matrix forms reuse the A64 `MatMulAdd` arithmetic. Each result
lane accumulates eight products of bytes into a 32-bit lane. The dot
forms accumulate four products and select the signedness of each
source separately. Each intermediate product has magnitude at most
65,025, so the largest sum of products has magnitude at most 520,200
and fits in `i32`. The destination addition wraps modulo 2^32.
Execution uses bounded time and constant auxiliary storage per
instruction. The result leaves FPSCR and condition flags unchanged.
[Arm DDI0597 ID032025, pages 1355–1356, 1434–1435 and 1450–1457](../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm MatMulAdd pseudocode](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L48286)

| Assumption | Falsification probe |
| --- | --- |
| The decoded operands select the prescribed widths, register pairs and indexed lane. | LLVM MC agrees on all 32 A1/T1 word pairs. Tests vary odd Q fields and the reserved matrix selector. |
| ID readback and operation admission share a profile. | Test reserved I8MM levels, D16, absent SIMDInt, absent FP16/FP32 SIMD, and competing HCPTR traps. Reimport a mixed-width profile and verify guest ID and execution. |
| T32 checks the predicate before rejecting a restricted IT slot. | A failed predicate skips the operation. A passing predicate reports Undefined ahead of the access trap, with unchanged vector registers. |
| Source operands survive destination aliasing. | Replay mixed signs, vector and indexed overlap, all three matrix operand layouts, high registers and 32-bit wrap with QEMU 11.1.2. |

The baseline returned Undefined for a valid enabled `VSMMLA`. The
candidate matched 64 enabled QEMU `max` cases and 64 Cortex-A15
Undefined controls. All 47,677 tests passed across the five owning
targets on Apple Silicon with `smir-jit`. Unsupported SMIR operations
continue through interpreter fallback. Physical AArch32 execution and
the wider profile and security/debug audit remain open.
[QEMU replay vectors](../../tests/suites/backend/a32_fp_controls/i8mm-qemu.tsv)

## AArch32 JSCVT capability readback

`VJCVT.S32.F64` consumes a binary64 operand. The software AArch32 profile
advertises `ID_ISAR6.JSCVT=1` only when the selected JSCVT field is 1 and
`MVFR0.FPDP` selects VFPv2 or VFPv3 double-precision arithmetic, and
`MVFR0.SIMDReg` selects a D16 or D32 register bank. Guest
CP15 MRC and the mixed-width `ID_ISAR6_EL1` MRS use the same projection as
instruction admission. The selection stored in the CPU context stays intact.
The projection takes constant time and constant auxiliary storage.
[Arm Feature Names, pages 57–58](../specifications/arm/audit-reference-inputs/feature_names_109697_2025_09_en.pdf)
[Arm DDI 0487B.a, G6.2.107](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe |
| --- | --- |
| An enabled conversion requires an implemented binary64 arithmetic profile. | A32 and T32 MRC advertise the feature when FPDP is absent or reserved, or the enabled conversion fails with a defined FPDP value. |
| The selected profile supplies an implemented FP register bank. | Keep FPDP enabled and compare ID readback and execution with SIMDReg=0, 1, 2, 3 and 15. The denied path must preserve FP state. |
| A mixed-width CPU uses the imported AArch32 profile for both guest ID aliases. | A64 MRS, A32 MRC and A32/T32 execution disagree after importing the MVFR0 value. |

The first correction covered `FPDP`. At `9f583c746`, both extended
regressions still advertised JSCVT with `FPDP=2, SIMDReg=0`. The
register-bank correction passed 640 standalone and 40 mixed-width
configurations, including both ARM and Thumb encodings. All 47,683 tests
passed across the five owning targets on Apple Silicon with `smir-jit`.
Physical AArch32 qualification remains open.

### CP15 feature ID group interception

`HCR.TID3` intercepts EL1 reads of the base CP15 feature ID group when
EL2 is enabled in the current Security state. In the mixed-width model,
Secure EL2 also requires `FEAT_SEL2` and `SCR_EL3.EEL2=1`.
Mixed-width Armv8-A execution also intercepts `ID_MMFR4` and the
additional defined CP15 identification encodings. The selected
`ID_ISAR6` trap applies even when the register reports zero. The same
check admits the trap through mixed-width preflight and selects its
execution outcome before reading the register. The classification uses
constant time and auxiliary space.
[Arm DDI 0487B.a, D7.2 and G6.2, HCR_EL2 and HCR](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)
[Arm ID_ISAR5 register access pseudocode](https://arm.jonpalmisc.com/latest_sysreg/AArch32-id_isar5#access-instructions)

| Assumption | Falsification probe |
| --- | --- |
| An intercepted MRC has no destination or retirement effect. | Run every selected encoding in ARM and Thumb. Require EC `0x03` at EL2, the exact ISS, unchanged R2 and PC, and zero retirements. |
| The feature ID group excludes MIDR, CTR and MPIDR. | Enable TID3 and issue those otherwise adjacent reads. Require the normal access outcome. |
| A hypervisor can intercept a read whose value the mixed-width CPU does not supply. | Compare the same MRC with TID3 set and clear. The clear case preserves the existing mixed-width availability check. |
| Secure EL1 uses TID3 when EL2 is enabled for Secure state. | Read `ID_ISAR5` in ARM and Thumb with Secure EL2 enabled, with `SCR_EL3.EEL2` clear, and with `FEAT_SEL2` absent. Also clear TID3 as a control. Check the EL2 trap, syndrome, PC, R2 and retirement count. |

The parent continued after a Non-secure EL1 `ID_PFR0` read with TID3
set. QEMU 11.1.2 trapped all 28 base-group ARM and Thumb reads on each
of its Cortex-A15 and Cortex-A53 models. The Cortex-A53 model trapped
all 30 additional and optional cases with AArch32 EL2. With AArch64 EL2
it matched all 128 syndrome and control probes, including 58 TID3
traps. The Cortex-A15 model did not implement the later encoding traps.
The five owning RAX test targets passed all 47,728 tests. Physical
AArch32 execution remains unverified. The raw results and guest sources are in
`/Users/int/dev/rax-audit-work/four-findings-a32-tid3-2026-11-26/`.

Parent `3913a2180` let the Secure EL1 `ID_ISAR5` read retire with TID3
set and Secure EL2 enabled. QEMU 11.1.2 `max` entered Secure EL1 with
EL3 `ERET` and trapped both the ARM and Thumb instructions to EL2 with
ESR `0x0fea0045`. It reached the follow-up HVC with TID3 clear and the
follow-up SMC with Secure EL2 disabled. All eight reports completed.
The five owning RAX suites passed 47,729 tests. Physical AArch32
qualification remains open.
The guest program and raw results are in
`/Users/int/dev/rax-audit-work/four-findings-a32-secure-tid3-2026-11-26/`.

### VMRS ID trap priority

For normal AArch32 EL1 execution, `VMRS FPSID` and `VMRS MVFR0–2`
check local coprocessor permission and EL2 FP access before the EL2 ID
trap. The ID trap takes precedence over `CPTR_EL3.TFP`. FPSID uses
`HCR_EL2.TID0`, and the three MVFRs use `HCR_EL2.TID3`. The checks use
constant time and auxiliary space.
[Arm FPSID access pseudocode](https://arm.jonpalmisc.com/latest_sysreg/AArch32-fpsid#access-instructions),
[Arm MVFR0 access pseudocode](https://arm.jonpalmisc.com/latest_sysreg/AArch32-mvfr0#access-instructions),
[Arm MVFR1 access pseudocode](https://arm.jonpalmisc.com/latest_sysreg/AArch32-mvfr1#access-instructions),
[Arm MVFR2 access pseudocode](https://arm.jonpalmisc.com/latest_sysreg/AArch32-mvfr2#access-instructions)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Normal EL1 execution takes the ID trap before the EL3 FP trap. | High | Set the applicable TID bit and `CPTR_EL3.TFP`. For each register in ARM and Thumb, require EL2 EC `0x08`, the exact ISS, unchanged R2 and PC, and zero retirements. |
| Each control retains its own priority. | High | Clear the TID bit to observe EL3 EC `0x07`. Set `CPTR_EL2.TFP` to observe EL2 EC `0x07`. Clear CPACR permission to observe Undefined ahead of both traps. |
| The guest executes outside halted Debug state. | Medium | The Arm register pseudocode has a separate `EL3SDDUndefPriority()` path for `EDSCR.SDD` in halted Debug state. The regression checks ordinary guest instruction execution. |

Parent `b59e6eaf7` reported EL3 EC `0x07` for the first combined FPSID
case. In 48 QEMU 11.1.2 `max` guests, the eight combined TID and EL3 TFP
cases also selected EL3. QEMU's VMRS translator checks general FP access
before calling its HCR ID trap helper. The remaining 40 cases exercised
each individual trap, EL2 TFP priority, local Undefined, and ordinary
read completion. RAX implements the priority in Arm's per-register
access pseudocode. All 47,730 tests across the five owning suites passed.
Physical AArch32 qualification and halted Debug state remain open.
[QEMU 11.1.2 VMRS translator](https://github.com/qemu/qemu/blob/v11.1.2/target/arm/tcg/translate-vfp.c#L722-L798)

The guest code and raw results are in
`/Users/int/dev/rax-audit-work/four-findings-a32-vmrs-id-priority-2026-11-26/`.

## AArch32 execution below EL2 without EL3

On the represented Non-secure PE without EL3, `HCR_EL2.RW` selects the
EL1 execution width. With `RW=0`, guest `ERET` can enter AArch32 EL1 or
EL0. The saved `SCR_EL3` slot has no effect on either decision. The FP
access path uses this same EL1 width when interpreting `FPEXC.EN`. With
EL1 in AArch32, arithmetic first checks `FPEXC.EN`, then checks
`CPTR_EL2.TFP`. The width check uses constant time and space.
[Arm ELStateUsingAArch32K](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L45817),
[Arm IsSecureBelowEL3](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L46678),
[Arm AArch32 FP access ordering](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L2086)

| Assumption | Falsification probe |
| --- | --- |
| The no-EL3 PE implements Non-secure EL2. | Confirm that ID_AA64PFR0_EL1 reports absent EL3 and that ERET enters A32 and T32 at both lower levels with HCR_EL2.RW=0. |
| FPEXC.EN has priority over the higher FP trap when EL1 uses AArch32. | Arm CPTR_EL2.TFP, vary FPEXC.EN, and check the exception class, destination EL, original PC, FP state, and retirement count. |

On the parent, ERET loaded the expected PC but remained in AArch64 EL2h
when the saved SCR_EL3 slot held zero. The corrected software backend
passed all eight combinations of ARM or Thumb, EL0 or EL1, and FPEXC.EN
clear or set. The denied FP instruction retains its PC, state, and
retirement count in every case. The complete `a32_fp_controls`,
`a32_fp_pairs`, `arm`, `arm_vfp_a32`, and `isa_oracle` binaries passed
47,682 tests on Apple Silicon.
[Owning regression](../../tests/suites/backend/a32_fp_controls.rs)

QEMU 11.1.2 confirmed entry in both encodings and modes. Twelve of
sixteen probes matched the pinned access order or its controls. QEMU
selected the EL2 FP trap in the four combined cases with FPEXC.EN clear
and CPTR_EL2.TFP set. With CPTR_EL2.TFP clear, QEMU distinguished local
Undefined Instruction from a completed FP operation in all eight cases.
The pinned QEMU translator tests the exception target before the enable
bit, which accounts for the observed priority. The pinned Arm access order
governs the priority case. Physical AArch32 qualification remains open.
[QEMU v11.1.2 VFP access check](a32-fp-controls/references/qemu-11.1.2/target/arm/tcg/translate-vfp.c#L219)

The unfiltered Apple Silicon library run passed 13,277 tests with zero
failures and five ignored. It tested these source files over
`b8e1c9b8e0a3d0023187594616c06a0756210f42` with the PC virtual-wire and
software-disable LVT masking changes also applied.

## Effective SCR_EL3.RW and AArch32 below EL2

On the modeled PE with EL3, a Non-secure EL2 that supports only
AArch64 makes `SCR_EL3.RW` effectively 1. EL1 still follows
`HCR_EL2.RW`. If both privileged lower levels are AArch64-only,
`SCR_EL3.RW` is also effectively 1. These width decisions leave the
stored register intact. When EL1 is AArch64, AArch32 EL0 ignores the
stored `FPEXC.EN` value. Selection takes constant time and space.
[Arm EffectiveSCR_EL3_RW](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L46017),
[Arm ELStateUsingAArch32K](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L45817),
[Arm AArch32 FP access ordering](../specifications/arm/pauth/shared_pseudocode-2025-12.xml#L2086)

| Assumption | Falsification probe |
| --- | --- |
| Non-secure EL1 follows HCR_EL2.RW when the stored SCR_EL3.RW bit is clear and EL2 supports only AArch64. | Attempt ERET to ARM and Thumb Supervisor mode. With HCR_EL2.RW set, require IL and the original EL3h. With it clear, require AArch32 EL1. |
| AArch32 EL0 under an AArch64 EL1 treats FPEXC.EN as enabled. | Execute VADD after guest ERET with FPEXC.EN clear. Require its binary32 result, advanced PC and one retirement. Repeat with AArch32 EL1 and require the denied instruction to preserve registers, PC and retirement. |
| Secure EL1 without Secure EL2 follows the stored SCR_EL3.RW selection when AArch32 EL1 is present. | Repeat the guest transitions with SCR_EL3.NS clear and both HCR_EL2.RW values. |

The parent entered AArch32 Supervisor mode where ERET should have set IL.
The corrected CPU passed all 16 mixed-width and FP-access configurations.
The five complete A32 and ISA oracle test binaries passed 47,683 tests on
Apple Silicon. QEMU 11.1.2 separately ran six A64, ARM and Thumb EL0
controls on Cortex-A76 and Neoverse-N1 models with AArch64-only EL1 and EL2.
Each model retired the FP instruction before the following Undefined.
Those model controls cover the all-AArch64 privileged profile. The mixed
EL1 profile uses the pinned Arm pseudocode and the RAX regression.

The unfiltered native Intel Linux KVM library passed 14,231 tests with zero
failures and 99 ignored. It tested these source files over
`e0c83ee4e6ae82f046638028e2e4e40f8650d741` with the other
checkpoint and exception-return changes applied. The raw log SHA-256 is
`f48aed218dd82309d1c21e32172419db29f73e214e282f9b31a2e1890a619e04`.

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

## AArch32 differential CPU state

The `arm_diff32` target now installs D0–D31 and FPSCR in an AArch32 user CPU
and executes the instruction through the ordinary fetch, decode, and step
path. It then reads those registers, FPSCR, the successor PC relative to the
instruction, NZCVQ/GE/T, the integer registers, and the scratch window. Every
successful comparison checks those fields. Before this change the audit replay's
division-by-zero case reported its input value `0x3f800000` and FPSCR `0`.

The reference guest uses the Linux AArch32 signal ABI. It checks that execution
reaches the trailing breakpoint, bounds the VFP frame walk to `uc_regspace`,
and reports whether it captured D0–D31 and FPSCR. The driver rejects incomplete
or invalid records. The ARM differential job installs the cross compiler and
sysroot and requires a working oracle. The oracle binary is built inside
Cargo's temporary target directory. [Linux AArch32 signal frame](https://github.com/torvalds/linux/blob/master/arch/arm/include/asm/ucontext.h)

The six audit inputs cover infinity, quiet NaN, division by zero, invalid
division, upward rounding, and flush-to-zero. Linux QEMU 5.2.0 with `-cpu
cortex-a15` matched the raw results and flags in both ARM and Thumb. Enabling
the integer sweeps exposed host arithmetic overflow in `SMMLA`/`SMMLS` and
`SSAT #32`. Rotated T32 `SXTB`, `SXTH`, `UXTB`, and `UXTH` also lost the
decoded source register and rotation. The arithmetic corrections keep the
architecture's result bits at their signed boundaries. The T32 extensions
now use the encoding's source and rotation fields, with separate A32 and T16
controls.
[Arm instruction pseudocode](../architecture/arm/asl/arm_instrs.asl)

All 46,332 Cortex-A15 cases matched across seven oracle batches, including
the 12 VFP replays. Four complete integration binaries passed 47,394 tests
with no ignored cases on Linux AArch64. All 57 AArch32 executor unit tests
also passed. Forcing a nonexistent cross compiler failed the required mode
and produced an explicit skip in optional mode.
The qualification receipt and logs are under
`/Users/int/dev/rax-audit-work/four-findings-a32-differential-state-2026-11-24`.

| Assumption | Falsification probe |
| --- | --- |
| The driver compares post-instruction FP and execution state. | Replay the six audit inputs in both execution states. Independently corrupt D31, FPSCR, PC and T and require all four differences to appear. |
| The reference record belongs to the instruction that reached the sentinel. | Compare normalized PC across ARM, T16 and T32. A missing VFP frame, wrong wire version, failed process or incorrect record count must fail the test. |
| Integer arithmetic stays within architectural result widths. | Exercise signed accumulation and round-only overflow, shifted `SSAT #32` with Q clear and set, and all four legal rotation amounts with byte and halfword extension. |

Run locally on Linux with `qemu-arm`, `arm-linux-gnueabihf-gcc`, and the
armhf C sysroot installed.

```sh
A32DIFF_REQUIRE=1 cargo test --locked --no-default-features --test arm_diff32 -- --nocapture
```

High-impact coverage stays open for the remaining optional FP profiles,
security/debug controls, and physical AArch32 execution.

## A32 and T32 CP10 transfer allocation

The decoder returns Undefined for opcodes 1 through 6 in the conditional
CP10 core-transfer space. Opcode 0 selects the single-register VMOV
encoding. Opcode 7 selects the floating-point system-register transfer.
The check takes constant time and storage.
[Arm DDI 0597 ID032025, pages 1492 and 1525](../specifications/arm/aarch32-isa-2025-03.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Opcodes 1 through 6 are unallocated for both transfer directions. | Vary all extension and core register fields in both ARM and Thumb. Require the Undefined decode for all 6,144 combinations. |
| The allocation decision precedes higher-level FP permission checks. | Attempt both transfer directions in a mixed-width PE with CPTR_EL2.TFP armed. Require the Undefined diagnostic, unchanged register state and PC, and zero retirement. |
| The allocated transfers still reach their intended decode. | Compare both single-register VMOV directions and VMRS/VMSR against LLVM MC and a Cortex-A15 QEMU guest in both instruction sets. |

The parent classified `0xee200a10` as a generic MCR. The independent
LLVM MC and QEMU 11.1.2 controls each matched 32 cases, including the
24 rejected encodings and eight allocated transfers. In QEMU the
rejected cases entered the guest Undefined vector with the expected
ARM or Thumb state.

On macOS arm64, the five complete Cargo targets passed with no ignored
or filtered cases. The results were 198 in `a32_fp_controls`, 5 in
`a32_fp_pairs`, 46,850 in `arm`, 529 in `arm_vfp_a32`, and 102 in
`isa_oracle`. The complete run log has SHA-256
`1f60cb5ef4a2fa844f37642b5b0307797883acd6a39f073a9f65b7b41f477ab7`.
The independent 64-result oracle log has SHA-256
`fb85f24e1f7418943cc3ee90cbfff7f1aacda6dc0b94a0d3e1ad74e5cb50806c`.

## CP10 and CP11 pair and memory allocation

Reserved encodings in the conditional CP10/CP11 64-bit transfer and
load/store space select Undefined Instruction after the allocated VFP
decoder paths. The shared decoder applies the same allocation rules to
T32. The selected check takes constant time and storage.
[Arm DDI 0597 ID032025, pages 1490–1491 and 1523–1524](../specifications/arm/aarch32-isa-2025-03.pdf)

| Assumption | Falsification probe |
| --- | --- |
| A reserved FP prefix cannot execute a generic coprocessor operation. | Vary the reserved D, o3, opc2 and P/U/W partitions across ARM, Thumb, CP10 and CP11. The rejected encoding must preserve CPU state and retirement even with an FP trap armed. |
| Allocated neighboring transfers retain their decode. | Compare two-core-register VMOV, scalar VLDR and VSTR, and CP15 MCRR/MRRC in both instruction sets. |

The parent decoded `0xec400a00` as MCRR. The regression exercises
14,336 reserved decode combinations, 56 mixed-width executions and 12
neighboring decode controls. LLVM MC and QEMU 11.1.2 agreed on all 64
independent cases. QEMU ran 56 guest Undefined Instruction cases and eight
allocated transfer controls on Cortex-A15. Its data-address controls used
mapped, aligned RAM. The independent log SHA-256 is
`ead7065e7f4638fbb9c4e0b297b141832c88fa0cc45c1b63c44aed48a7f8dd97`.

The five unfiltered owning targets passed 47,651 tests on native Intel
Linux with `smir-jit`. The runs reported zero failures, ignored cases,
and filters. The complete Cargo test log SHA-256 is
`760df3090fd5fb1689726e04baae1fd0132c474e60e531bf06d43d66b70e28eb`.

## CP8 and CP9 pair and memory allocation

The conditional A32 and corresponding T32 decoder selects Undefined for the
unallocated size-00 and size-01 pairs and for unallocated scalar memory forms.
Size 01 (`CP9`) retains the immediate FP16 `VLDR` and `VSTR` forms. The check
takes constant time and storage.
[Arm DDI 0597 ID032025, pages 1490–1491 and 1523–1524](../specifications/arm/aarch32-isa-2025-03.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Conditional allocation depends on size and the P/U/W partition. | Vary the A32 condition, direction, D bit and low-field samples. Check every P/U/W partition in A32 and T32, and keep both address signs as positive FP16 controls. |
| A reserved prefix selects Undefined before higher-EL FP access. | Arm CPTR_EL2.TFP and check the diagnostic, retirement, PC, and register state for CP8 and CP9 pair and memory words. |
| Unconditional complex SIMD is a separate allocation. | Decode `VCMLA.F16` and `VCADD.F32` in both instruction sets and compare with LLVM's disassembly. |

The parent decoded `0x0c010800` as `STC` and failed the mixed-width Undefined
check for `0xec410810`. QEMU 11.1.2 `max` took the Undefined vector in all 56
reserved cases and completed all ten allocated controls. The witness compares
D0, D1, FPSCR and an aligned 32-bit RAM location after each instruction. The
FP16 store controls also check preservation of the adjacent halfword. The
observation SHA-256 is
`56eedc100e578aa819c6ac46a5a7a32dc4630d11290f3e0447885d7487b876d7`.

The seven unfiltered integration targets passed 47,762 tests on macOS arm64,
including ARM and Thumb SMIR JIT, with zero ignored cases. The mixed-width
regression passed eight reserved transfer probes with CPTR_EL2.TFP enabled.

## AArch32 crypto capability readback

The AArch32 ID_ISAR5 projection clears the AES, SHA1 and SHA2 fields.
The AES field also governs the 64-bit polynomial multiply form. The
software AArch32 decoder has no execution support for these encodings.
The projection preserves other represented AArch32 capabilities and
the raw checkpoint fields. AArch64 ID_AA64ISAR0 crypto reporting uses
its own feature view. The mask takes constant time and storage.
[Arm DDI0487B.a, ID_ISAR5_EL1 field descriptions](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Disabled AArch32 crypto forms stay Undefined even with nonzero saved ID fields. | Assemble the raw instruction families with LLVM. Execute each A32/T32 encoding with the raw ID values enabled and require Undefined and unchanged SIMD data. |
| Readback masks the same fields through CP15 and AArch64's AArch32 alias. | Import feature images with both defined and reserved values. Read from ARM and Thumb, then compare the AArch64 alias and unchanged AArch64 crypto controls. |
| Narrow polynomial multiplication has a separate allocation. | Execute VMULL.P8 in ARM and Thumb under the same setup and require completion. |

The unchanged decoder rejected 30 encodings for AArch32 AES, SHA and
VMULL.P64 across the two instruction sets, and executed both VMULL.P8
controls. Its output SHA-256 is
`c0a04cf7442941ba28aa0a89ec44c8aa872440254755cc24c4fb4712fd7c62a0`.
QEMU 11.1.2 Cortex-A15 rejected the same 30 inputs and ran both P8
controls with AArch32 ID_ISAR5=0. The QEMU max model reported nonzero
fields and ran all 32 inputs. These runs exercise decoded allocation
and the feature contrast on an independent model. The Cortex-A15 and
max output SHA-256 digests are
`0ad4da6178bbdcff3b5ab5d6f54e2fc7194d5a4873fb70cc183c18cb29eecbd4`
and `a38f6623d1ebc218a93fb38ba2b38d11f172c3dfcf6ccdf208ec6aa3d29cbba9`.

Before the fix, both restored-profile readback tests failed on physical
Intel Linux. The standalone test read `0x01001120` instead of
`0x01000000`. The mixed-width test read `0x1100fff1` instead of
`0x11000001`. Both passed with the projection in place. The five
unfiltered owners passed all 47,651 tests across `a32_fp_controls`,
`a32_fp_pairs`, `arm`, `arm_vfp_a32`, and `isa_oracle`. The combined
passing log SHA-256 is
`022553e1317fdde2e83e2ac3c1f46fdd53623cfa41a12367eb7b97a6b11adda5`.

## Retirement after restoring the maximum instruction counter

A standalone AArch32 checkpoint accepts every unsigned 64-bit retirement
counter value. Successful ARM and Thumb retirement now increments it modulo
2^64. The shared budget runner measures the delta with wrapping subtraction.
Exception entry leaves the counter unchanged.

| Assumption | Falsification probe |
| --- | --- |
| A decoded FP instruction can retire across the counter boundary. | Start at `u64::MAX` in each instruction set, directly and after loading the same saved state into a fresh vCPU. Require one retired unit, counter zero, PC advanced by four bytes and the exact destination bits. |
| FP access denial remains nonretiring at the boundary. | Repeat with FPEXC.EN clear. Require the Undefined Instruction vector, the original destination bits and the maximum counter value. |

A public-API probe restored a `RAXA3202` record containing `u64::MAX`
and triggered the old debug overflow while retiring `VADD`. The baseline
log SHA-256 is `9ac45392dd8e5d404e2a0e821b298f8a99f7dd279d6f91d6b462d19627f92481`.
The direct and restored ARM and Thumb regression passed on Intel Linux.
The unfiltered library and ten integration targets passed 61,985 tests,
with 100 opt-in tests ignored. The combined log SHA-256 is
`7d26dd5fd5e3b583e9f725f1ccc9219b78bff2a5a9c9ab4abbe5ef477dacc7c8`.

## Short-vector reporting on Armv8-A

The Armv8-A software PE returns zero in MVFR0.FPShVec[27:24] through
both AArch64 `MRS MVFR0_EL1` and AArch32 `VMRS MVFR0`. Scalar execution
uses that same effective value. The profile uses read-as-zero and
write-ignored behavior for FPSCR.Len and Stride. In the trapping profile,
FPEXC32_EL2.TFV consequently reads as one and ignores writes. The
projection is a constant-time mask and preserves the raw imported
MVFR0 record. The standalone legacy AArch32 executor still supports its
optional ARMv7 short-vector profile.
[Arm DDI0487B.a D7.2.32, D7.2.75 and G6.2.107](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Both register views use the Armv8-A field and preserve unrelated capabilities. | Import all 16 field values. Read the complete word in AArch64 and AArch32, then export and compare the original raw value. |
| The execution profile uses read-as-zero short-vector controls. | With a reserved raw FPShVec value, write Len, Stride and DN in ARM and Thumb. Verify FPSCR retains only DN and that scalar VADD produces the expected result and retires. |

On parent `99187938a`, the first regression exposed FPShVec=1 through
the AArch64 alias and the second raised Undefined on scalar VADD with a
reserved raw field. The baseline log SHA-256 is
`afb58b1548200b3e6971de3c8c8d69da2be362b4c214bf8ae8ec24326cd75a93`.
Two pre-existing FPEXC tests expected TFV to read zero when an imported
FPShVec field was nonzero. Their updated assertions exercise imported
and default IDs, write-ignored TFV, the VHE permission matrix, and
EL1 rejection. The old expectations failed with a readback of
`0x6400079f` and a comparison value of `0x6000079f`.

QEMU 11.1.2 Cortex-A53 and Cortex-A57 controls reported the same
`0x10110222` through both MVFR0 views in all four ARM and Thumb cases.
Those models retained the written Len and Stride fields in FPSCR.
After clearing those fields, both models retired VADD with the expected
binary32 result. The model log SHA-256 is
`17bb24230c79bc429bb5e7e0594ce0b662f3bb2b07b1e32d038f3f837d7e0f6b`.
Physical AArch32 behavior remains unverified.

The unfiltered macOS Arm64 integration targets passed 47,687 tests with no
failures or ignored cases. This includes 201 `a32_fp_controls`, 5
`a32_fp_pairs`, 46,850 `arm`, 529 `arm_vfp_a32` and 102 `isa_oracle` tests.
Two macOS library runs received SIGKILL before their result summaries. The
second used test optimization level 1, SHA-256 optimization level 3 and
three test threads. Both logged successful execution of the two changed
FPEXC unit tests. The interrupted log SHA-256 digests are
`e4bdbc457ffc36ac0c7182f87c80af23d05c4d6a98749d61c8a6671167bcc8ee`
and `97689566360df5c38b854dbc75b61c662140bd395b51a05d0b07eff71695ed60`.

The physical Intel Linux run hit its 6,800 s command limit while running
the library's detached PC interrupt checkpoint tests. It recorded no
failures before interruption. The partial log SHA-256 is
`b956027273c3390ab2f2709416188be768c1f461896b3e4ef58f91d4c15c6884`.

The macOS Arm64 library run with the same four FP input files and the
parallel HVF candidate passed 11,078 tests, with five ignored and no
filters or failures. Two stopped RISC-V GSC test subprocesses completed
after receiving SIGCONT. The source of the stops is unknown. The passing
log SHA-256 is
`cc9d98fb75058880c735dd16772d033543445daf976a3c282e37d3fc6274a349`.

## Reserved scalar data-processing and core transfers

After matching the scalar floating-point data-processing prefix, ARM and
Thumb now decode unallocated opcode and precision combinations as Undefined.
After the allocated FP16 transfer has been selected, CP8 and CP9 core-transfer
words also decode as Undefined. These allocation checks use constant time and
space and run before FP permission checks and architectural effects.
[Arm DDI0597 ID032025, printed pages 1492–1496 and 1526–1530](../specifications/arm/aarch32-isa-2025-03.pdf)

The parent decoded `0x0e800a40` as CDP and successfully executed reserved word
`0xee000810` through the generic coprocessor path. The regression checks
predicate-independent allocation across the conditional ARM space, rejection
with CPACR, HCPTR and FPEXC denial states, unchanged mixed-width register
state and retirement, and rejection by both SMIR lifters.

| Assumption | Falsification probe | Result |
| --- | --- | --- |
| The reserved encodings take Undefined Instruction with FP enabled. | Run a bare-metal guest with an Undefined vector and a separate completion marker. Include the adjacent allocated instruction in each case and check that it reaches completion. | QEMU 11.1.2 `max` took Undefined for all 10 reserved ARM/Thumb cases and completed all 12 allocated controls, including the unconditional VFMAL adjacent to the CP8 word. |

The QEMU receipt SHA-256 is
`b9bd55d650a09c6571550236b134a61ab98035667b2ed04fad32b3e4200c7612`.
The five complete RAX integration targets passed 47,690 tests with zero
failures or ignored tests. The initial ARM run received SIGKILL. Its complete
46,850-case rerun used two test threads. Physical AArch32 execution remains
unverified.

## Single-register VMOV reserved fields

A32 A1 and T32 T1 mark bits 6:5 and 3:0 of the CP9 `VMOV.F16` and
CP10 `VMOV` single-register core transfers as `(0)`. RAX selects
Undefined Instruction for nonzero values at decode, before dispatch to
FP access checks. Undefined is one of the permitted Armv8-A outcomes
for these fields. The archived ASL represents them as `x` in its opcode
matcher. That representation identifies the instruction class, while
the encoding diagrams and SBZ rules govern the permitted outcomes.
Canonical transfers retain the existing core and single-register
operands. The check takes constant time and storage.
[Arm DDI 0597 ID032025, pp. 1094–1096](../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm DDI 0487B.a, § K1.1.9](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe | Result |
| --- | --- | --- |
| Both instructions have the same SBZ positions. | Exercise all 64 combinations, all 16 core and 32 scalar register selectors, both directions, and both instruction sets in RAX. Run all 64 combinations at S3 with FP enabled on QEMU. | The CP10 and CP9 baselines classified `0xee002a11` as MCR and `0xee002911` as VMOV.F16, respectively. The QEMU matrix returned Undefined on 756 nonzero cases and the expected copied value on all 12 canonical cases. |
| The selected Undefined outcome preserves state and the ARM predicate. | Compare all GPRs, D registers, FPSCR and CPSR on the standalone path. Use an Armv8.2-A mixed-width profile with CPTR_EL2.TFP enabled and canonical transfers as trap controls. | The baseline already rejected the tested CP10 words in standalone execution. The corresponding nonzero CP9 fields selected the FP16 transfer. |

The independent reference was QEMU 11.1.2. Its Cortex-A15 and `max`
512-case single-precision guest log SHA-256 is
`82bedb295362ef4e60e01ed6c027dbbc0228864f6e598d98163947ff0d9dca9c`.
Its FP16-capable `max` 256-case guest log SHA-256 is
`7266d44a12e635aaad37f28b2cc0db4ac95b0157fa86c532529e61a99ad7aa88`.

The final macOS Arm64 run passed all 47,695 tests across five complete
targets. The totals were 203 `a32_fp_controls`, five `a32_fp_pairs`,
46,850 `arm`, 535 `arm_vfp_a32`, and 102 `isa_oracle`. The mixed-width
control uses Armv8.2-A so canonical `VMOV.F16` reaches the FP access trap.
The first mixed-width control used the default Armv8.0-A profile, which
rejected canonical `VMOV.F16` at feature admission.

Physical AArch32 qualification and the remaining optional profile, security
and debug controls stay open.

## VMRS and VMSR reserved fields

The shared A32 and T32 decoder selects Undefined Instruction for `VMRS` and
`VMSR` when any bit in [7:5] or [3:0] is set. Bit 4 remains the register-transfer
selector. The encoding diagrams mark the checked bits `(0)`, and Armv8-A
permits selecting Undefined for those values. The decoder checks the fields
with a constant-time mask before FP access checks can read or write state or
select an FP access trap. The existing conditional execution rules still
apply. [Arm DDI 0597 ID032025, pp. 1124–1125 and 1127–1128](../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm DDI 0487B.a, § K1.1.9](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe | Result |
| --- | --- | --- |
| The two transfer directions share the same seven SBZ bits in A32 and T32. | For each encoding, vary all 127 nonzero field patterns over the tested GPR and special-register selectors. Check the corresponding zero-field decode. | The parent decoded `0xeef00a11` as `VMRS`. The candidate classified all 34,290 nonzero combinations as Undefined and retained all 272 canonical decodes, including `VMRS APSR_nzcv, FPSCR`. |
| Reserved forms select Undefined before a competing FP access trap when the predicate passes. | Compare GPRs, FPSCR, FPEXC and CPSR on the standalone path for passing and failing predicates. Compare canonical controls with CPTR_EL2.TFP set on the mixed-width path. | The parent executed `0xeef12aff` and returned `Continue`. The candidate preserved state and retirement on rejection and preserved state when the predicate failed. Canonical controls retained the EL2 FP access trap. |
| The guest Undefined marker distinguishes rejection from a retired instruction. | Reset R2 and FPSCR before each word, set the marker only in the Undefined vector, and verify both values after resuming. Include the zero-field read and write as positive controls. | On QEMU 11.1.2, `cortex-a15` and `max` agreed in A32 and T32. All 1,016 nonzero FPSCR transfers took Undefined and preserved R2 and FPSCR. All eight canonical transfers retired with the expected register effects. |

The pre-fix regression log SHA-256 is
`d1deef0a137eb1c6aca8395d012798f56b46bb2365535b4c0e9172ce28086462`.
The independent QEMU receipt SHA-256 is
`cba3049e0b9605bc35e3ca1ae959c592c1e9bd3811de6eb3df729d4d2eee95b3`.
On macOS Arm64, five unfiltered targets passed 47,697 tests with no failures
or ignored cases. The targets were `a32_fp_controls` (205), `a32_fp_pairs` (5),
`arm` (46,850), `arm_vfp_a32` (535), and `isa_oracle` (102). The combined
log SHA-256 is
`ba5748685ede5bed8b562427ce69f74dcddd4ef471f05c198247d8bd7e4fe39b`.
Formatting, whitespace and scoped Clippy checks passed. The unfiltered
library run reproduced the existing Darwin code-signing failure. The isolated
rerun returned `EINVAL` where the test expects `EPERM`. Its log SHA-256 is
`2c07b7fc49ab9a8ef95a4e4ef6866ac87f034f2957d3678eacddea4a886d2a30`.
[Prior PC checkpoint qualification](pc-machine-checkpoint/README.md#acpi-s5-power-off-across-restore)

The Linux-only `arm_diff32` harness requires `qemu-arm` and was omitted on
macOS. The independent controls ran system-mode guests with `qemu-system-arm`.
Physical AArch32 execution and the remaining profile, security and debug
controls stay open.

## Scalar compare with zero and move-immediate reserved fields

`VCMP` and `VCMPE` against zero mark bits 5 and 3:0 as `(0)` in the A2 and
T2 encodings. Scalar immediate `VMOV` marks bits 7 and 5 as `(0)` in A2
and T2. The shared decoder selects Undefined for nonzero reserved fields
before FP access checks. Register-source variants still use their encoded
source registers, and scalar immediate `VMOV` still uses all eight literal
bits. The decode checks take constant time and space.
[Arm DDI 0597 ID032025, pp. 845–853 and 1105–1108](../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm DDI 0487B.a, § K1.1.9](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe | Result |
| --- | --- | --- |
| The field masks are shared by A32 and T32 at all three precisions. | Vary every reserved field combination, all 32 destination selectors and all A32 condition codes in the conditional space. Include canonical encodings and adjacent register-source forms. | The parent decoded 96,768 reserved words as FP operations. |
| Reserved encodings reach Undefined before FP access checks. | Exercise A32 and T32 with FP enabled, with local denial or with a higher FP trap armed. Check unchanged FP and general registers, status and mixed-width retirement. | The parent executed `0xeeb50a41` on the standalone path and failed the mixed-width Undefined assertion. |
| The Undefined vector distinguishes rejection from execution in the independent guest. | Seed D0, D1 and FPSCR before each guest word. Check both destination effects and compare flags for canonical words. Check the vector marker and original state for reserved words. | QEMU 11.1.2 `max` rejected all 390 reserved encodings and executed all 18 canonical controls. |

QEMU observation SHA-256 is
`4133bda5c99fca4d44062a56080a5c7af1c97e05addc86779003316e02d780ab`.
The decoder matrix covers 104,448 words from 16 instruction-set and
condition combinations, three precisions, 32 destinations, and 68 field
patterns. Before the fix, 63 of the 68 patterns per combination were
misclassified. The QEMU matrix uses both instruction sets, all three
precisions and all 68 field patterns with one destination.

All five complete targets passed 47,700 tests with zero failures or ignored
cases. The targets were `a32_fp_controls` (208), `a32_fp_pairs` (5), `arm`
(46,850), `arm_vfp_a32` (535) and `isa_oracle` (102). The combined log SHA-256
is `7bcacbb8c8de8bccf826e2803740389832567fb540a93be3c6ba33c1db34f2d4`.
Physical AArch32 behavior for these fields remains unverified.

## Lane VMOV and core-register VDUP reserved fields

Both directions of lane `VMOV` and the core-register form of `VDUP` mark
bits [3:0] `(0)` in A32 A1 and T32 T1. RAX selects Undefined Instruction
for nonzero values before checking FP permissions. The shared decoder
uses a constant-time mask. The condition and Thumb IT rules still apply.
[Arm DDI 0597 ID032025, pp. 920-921, 1103-1104 and 1116-1117](../specifications/arm/aarch32-isa-2025-03.pdf)
[Arm DDI 0487B.a, § K1.1.9](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe | Result |
| --- | --- | --- |
| Both instruction sets reserve the same four bits. | Vary all 16 field values over 12 transfer forms, every D and core register selector, and both instruction sets. Include canonical and pre-existing invalid operands. | The parent decoded `0xee400b11` as `VMOV` and executed `0xee402b11`. |
| The encoding check precedes FP access and has no data effects. | Compare GPRs, vector registers, FPSCR and retirement on the software paths, with an EL2 access trap armed on the mixed-width PE. Check ARM condition and Thumb IT skips. | Canonical controls reach the intended operation or EL2 access trap. The reserved words preserve register state and do not retire on the mixed-width PE. |
| The independent guest distinguishes Undefined from canonical execution. | Reset R2, D0 and D1 before each word. Check the vector handler marker and original state on rejection. Check the result and untouched registers on canonical operations. | QEMU 11.1.2 `cortex-a15` and `max` rejected all 720 nonzero cases and executed all 48 canonical cases. |

The decode matrix covers 196,608 inputs. The independent QEMU receipt
SHA-256 is `81e00d4b61dfd3e873f57654f087df4675238e75f5655473690fc081a821fa86`.
On macOS Arm64, all 47,708 tests passed across five complete targets with no
failures or ignored tests. The targets were `a32_fp_controls` (216),
`a32_fp_pairs` (5), `arm` (46,850), `arm_vfp_a32` (535), and `isa_oracle` (102).
The combined log SHA-256 is
`a72f67d5233e1e81d22ff1afa60f2fa9d6284f536478923c472ea534e030aceb`.
Physical AArch32 execution remains unverified.

## FPSCR on scalar-only and integer Advanced SIMD profiles

The shared FP system-register transfers are available when the PE implements
scalar FP or Advanced SIMD. An integer-only Advanced SIMD PE can read and
clear cumulative saturation with VMRS and VMSR, and can read its feature
registers and control FPEXC.EN. The same CPACR, FPEXC, privilege and trap
checks apply. The register file by itself admits no system-register access.

FPSCR.QC is available with Advanced SIMD. AHP requires half-precision
conversion and FZ16 requires half-precision data processing. The integer-only
profile selects zero for the unavailable FPSCR fields. A mixed-width PE
updates the AArch64 FPCR and FPSR fields exposed by the AArch32 profile.
The FPSCR projection and commit use constant time and auxiliary space.

| Profile | FPSCR access and applicable field behavior |
| --- | --- |
| Scalar FP without Advanced SIMD or half-precision | Scalar flags and controls, with QC, AHP and FZ16 read as zero |
| Scalar FP with half conversions | AHP is writable |
| Integer-only Advanced SIMD | VMRS and VMSR expose QC |
| Advanced SIMD with floating-point operations | SIMD exceptions can accumulate in FPSCR and defined half capabilities expose AHP and FZ16 |
| Register file without either extension | FP system-register transfers are Undefined |

Arm DDI0406C.d specifies FPEXC and FPSCR in B4.1.57-58 and the shared
VMRS/VMSR encodings in A8.8.349-350 and B9.3.21-22. Arm DDI0487B.a
G6.2.50 defines the AArch64 mapping and distinguishes half conversion from
half data processing. [Armv7-A/R reference](../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf)
[Armv8-A reference](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Integer SIMD does not require scalar FP for the shared registers. | Saturate eight signed byte lanes in A32 and T32, observe and clear QC through FPSCR, and require scalar VADD to remain Undefined. Toggle FPEXC.EN and require the ID and FPEXC reads to succeed while FPSCR access is denied. |
| Half conversion and arithmetic expose different fields. | Compare all-ones VMRS/VMSR across scalar-only, conversion-only and full-half profiles. Seed unavailable bits in raw state before checking the architectural read. |
| A32 FPSCR writes update only the visible view of shared state. | On a mixed-width PE, seed additional A64 QC, AHP and FZ16 state, then check preservation through guest VMRS and VMSR in both A32 and T32. Verify that visible A64 status and control fields update. |

The parent `7c9b695c6` failed all four new regressions. QEMU 11.1.2
Cortex-A15 and Cortex-A8 returned QC with Advanced SIMD and zero with
`neon=off,vfp-d32=off`. A32 and T32 agreed. The Cortex-A15 model reported
scalar half conversion and returned the written AHP value. The Cortex-A8
model also returned the written AHP value with both half-conversion fields
clear. DDI0406C.d defines the absent field as UNK/SBZP, and RAX selects
zero for that profile. Integer-only profile qualification uses the Arm
specification and the RAX execution regressions. Physical AArch32
qualification remains open.

The complete `a32_fp_controls`, `a32_fp_pairs`, `arm`, `arm_vfp_a32`
and `isa_oracle` suites passed 47,715 tests with zero failures or ignored tests.
The Linux-only `arm_diff32` target executed zero tests on macOS. LLVM MC
23.0.0git independently assembled the tested A32 and T32 transfers and
the signed 8-bit saturating add.

On macOS Arm64, the native JIT suites passed all 26 A32 cases and all
25 T32 cases. The shared FP system-register transfers use the interpreter.

### FPSCR for pure FP16 Advanced SIMD

RAX admits pure Advanced SIMD FP16 data processing in synthetic profiles
with `SIMDHP=2` and no scalar FP or `SIMDSP`. The FPSCR view for this
configuration now exposes FZ16 and cumulative exceptions alongside QC.
AHP stays clear because FP16-to-FP32 and FP32-to-FP16 conversions require
`SIMDSP`. Arm DDI0487B.a G6.2.50 defines FZ16 for both scalar and SIMD
half data processing. G6.2.108 defines the capability fields and constrains
Armv8-A hardware profiles.
[Armv8-A reference](../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Guest FPSCR transfers expose the status and controls of admitted half operations. | Write all ones and read back QC, FZ16 and the cumulative flags. Add the smallest half subnormal to zero and add opposite infinities in a second lane. Toggle FZ16, compare the raw result and require IOC in both cases. |
| The half data path has its own admission boundary. | Require the FP32 add and half-to-FP32 conversion to report Undefined. With absent, conversion-only or reserved SIMDHP fields and SIMDSP clear, require all-ones writes to read back only QC. |
| The shared register projection retains the half controls and status. | Import the pure-half capability fields on a mixed-width PE and step VMSR, VADD.F16 and VMRS. The intermediate add must flush the subnormal and the later read must report IOC. |

The parent returned only QC for the half data-processing profile. The
corrected regressions cover standalone and mixed-width execution in ARM
and Thumb. The five owning suites passed 47,725 tests. QEMU 11.1.2 `max`,
with a full FP profile, independently matched the result and FPSCR for
the four instruction-set and FZ16 combinations. The RAX synthetic profile
cases qualify its guest view. Physical AArch32 qualification remains open.
The scripts and results are in
`/Users/int/dev/rax-audit-work/four-findings-a32-pure-simd-half-2026-11-26/`.

## FP16 multiply-long mnemonic

The decoder renders the subtract-long instruction as `vfmsl` for both
vector and indexed A32 and T32 encodings. A sweep compared 32,768 words
per instruction set in the scalar FP and adjacent coprocessor space with
LLVM 23.1.3. It found the `vfmls` spelling on 256 sampled indexed forms
per instruction set. Arm defines `VFMSL` for both forms.
[Arm DDI 0597 ID032025, pp. 950–955](../specifications/arm/aarch32-isa-2025-03.pdf)

The regression checks both instruction sets, both source forms, and the
`VFMAL` add control against the assembly mnemonics. It
failed on the parent and passed with the corrected spelling. The complete
`a32_fp_controls`, `arm` and `arm_vfp_a32` suites passed 47,614 tests.

## ARM1176-style VFPv2 selection

`aarch32_isa = "v6"` and `"v6_k"` select D16 VFPv2 on the software
S3C64xx and S5L8900 machines. VFP data execution starts with `FPEXC.EN`
clear. Privileged guest code can enable it with `VMSR`. Admission rejects
Advanced SIMD, D16–D31 operands, and VFPv3-only instructions. VFP short-vector
controls remain available under the existing standalone execution path.
Complete checkpoints carry the selected capability IDs and FP controls in
the CPU record. The checks take constant time and space per instruction.
Historical base-only files stored the ISA setting but omitted the FP
capability IDs. For such a file the restored FP capabilities come from the
configured destination.

Arm DDI 0301H Tables 20-3 through 20-5 define the VFP11 registers and
their access modes. The access table below assumes CPACR permits the
instruction. The setting uses the VFP11 allocation and RAX's synchronous
support-code ABI, identified by the FPSID subarchitecture field. Physical
VFP11 asynchronous exception state and its support code remain outside
this qualification. [ARM1176JZF-S Technical Reference Manual](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

| Register reads | Supervisor, EN=0/1 | User, EN=0 | User, EN=1 |
| --- | --- | --- | --- |
| FPSID, MVFR0, MVFR1 | Available | Undefined | Available |
| Selector 5 (MVFR2 on newer profiles) | Undefined | Undefined | Undefined |

| Assumption | Basis | Falsification probe | Impact |
| --- | --- | --- | --- |
| The VM applies the configured FP profile. | Software CPU factory and complete backend record. | Compare `v6`, `v6_k`, and `v7_a` using guest ID reads, a scalar add, a VFPv3 immediate, and an operation targeting D16. Repeat the admission checks on a fresh owner restored from the `v6_k` file. | High |
| The VFP11 ID access policy depends on privilege and enable state. | DDI 0301H Table 20-4. | Vary all four ID selectors, A32 and T32, CPACR permissions, privilege, and FPEXC.EN. On denial the destination register must retain its original value. | High |

Both regressions failed on `2cde00194`. QEMU 11.1.2 `arm1176` confirmed the
privileged register results, the reserved selector and the disabled User
MVFR denials. Its User-mode FPSID read succeeded with FPEXC.EN clear, and
its User-mode MVFR0 and MVFR1 reads faulted with FPEXC.EN set. For those
three cases the RAX setting follows Table 20-4. The observed QEMU values
and process commands are in the retained 16-case receipt, SHA-256
`0c56e5a21045dd0417f9b77e7f4a1d786fde3d3c523f3f35e621a5c3511b1b8c`.
The same QEMU model returned binary32 `0x40400000` for `1 + 2`, then
independently rejected the VFPv3 constant move and the operation targeting
D16. The arithmetic receipt has SHA-256
`de2a16ec1a6f08371ba390476f9ccc7e67d5c31aced4af81057886d97bc9f07a`.
The `a32_fp_controls`, `a32_fp_pairs`, `arm`, `arm_vfp_a32`, and `isa_oracle`
suites passed 47,730 tests. The five owning library modules passed 170
tests. Library Clippy passed with warnings denied.
The inputs and receipts are under
`/Users/int/dev/rax-audit-work/four-findings-vfpv2-id-access-2026-11-26/`.

### ARM1176 coprocessor permissions

The ARM1176-style setting starts with CP10 and CP11 access denied. The
guest initializes both fields in CPACR before using the VFP system
registers. `FPEXC.EN` separately gates FP data operations. The guest view
of CPACR exposes only CP10 and CP11. Neither CPACR nor NSACR exposes the
later Armv7 SIMD and D32 disable fields. NSACR retains the ARM1176
coprocessor, cache and TLB lockdown, and DMA permissions.
[ARM DDI 0301H, Tables 3-44, 3-45 and 3-51](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

| Assumption | Falsification probe | Impact |
| --- | --- | --- |
| No external coprocessor is attached to the modeled machine. | Write all ones to guest CPACR and read it back. Only the CP10 and CP11 fields should remain. | High |
| The ARMv6 register view applies only to the selected ARM1176-style profile. | Read CPACR at startup with `v6`, `v6_k`, and `v7_a`. Enable both fields from guest code and restore the `v6_k` checkpoint into a fresh VM. Read CPACR again and check that the restored guest sees its programmed value. | High |
| Reserved NSACR fields have zero readback in this model. | Write its reserved bits together with the CP10, CP11, CL, TL, and DMA fields. Require the defined bits to survive guest readback. | Medium |

On `992d1c92d`, guest reset readback was `0xc0f00000`. The two regression
cases exercise decoded CP15 transfers and the configured VMM. QEMU 11.1.2
on `raspi0` confirmed the CP10/11 reset permissions and the single- and
double-precision access decisions in Secure and Non-secure states. QEMU read
`0xc0000000` from reset CPACR and retained reserved NSACR bits. RAX chooses
zero readback for those reserved fields. The 11-case receipt SHA-256 is
`21777d8a37e2d6574e042756bdf23688c1822340e9016ba20ec901bdb1858384`.
The inputs, guest outputs and results are under
`/Users/int/dev/rax-audit-work/four-findings-arm11-coprocessor-controls-2026-11-26/`.
The five affected integration binaries passed all 47,730 tests, and the
VMM backend-context test module passed all 18 tests.
Unequal CP10 and CP11 permissions are outside the defined VFP domain.
Physical ARM1176 validation and asynchronous VFP11 exceptions remain open.
[Arm Architecture Reference Manual, DDI 0100I, B3-17](https://www.scs.stanford.edu/~zyedidia/docs/arm/armv6.pdf)

### ARM1176 FPSCR modes

On ARM1176, `MVFR1[7:0]` describes media extensions. The zero reset value
carries no information about the availability of `FPSCR.DN` or `FPSCR.FZ`.
The software VFPv2 profile uses its scalar arithmetic for both settings of
these controls and applies the `FPSCR.RMode` setting. This interpretation
uses the existing ARM1176 profile identity and takes constant time and
space. [ARM DDI 0301H, Tables 20-6 and 20-10](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

The VMM regression on `4c83a81d` obtained `S0=0x00000000` where the guest
addition at reset `FPSCR` should produce `S0=0x40400000`. Its revised
sequence runs on `v6`, `v6_k`, and `v7_a`, and tests retirement again
after restoring a `v6_k` checkpoint into a fresh owner. QEMU 11.1.2 with
an `arm1176` CPU matched the result and guest-visible FPSCR in all 22
binary32 and binary64 reference cases. They cover all four rounding
settings, both NaN modes, and both input flush settings. The rounding test
adds `2^-24` or `2^-53` to 1, exactly half the distance to the next
representable value in binary32 or binary64. Round toward positive infinity
selects that next value. All tested modes set `FPSCR.IXC` for the tie.
The reference receipt SHA-256 is
`3322d32d2ce1bcda07a8a57fc0bf513075470904472ebb528311fd5622d01b07`.
The five owning integration binaries passed 47,731 tests. Library Clippy
passed with warnings denied.

| Assumption | Basis | Falsification probe | Status |
| --- | --- | --- | --- |
| ARM1176 `MVFR1=0` leaves both DN and FZ settings usable for RAX's software VFP. | DDI 0301H Tables 20-6 and 20-10. | Read zero from guest MVFR1 and vary DN, FZ, and rounding through guest FPSCR writes. Compare raw binary32 and binary64 results and FPSCR against the QEMU guest. | Confirmed for the tested scalar cases. |
| Complete checkpoints retain the selected profile. | The backend CPU record carries FPSID, MVFR and FPSCR. | Restore the checkpoint into a fresh VMM, then require the reset-FPSCR VADD to retire at the next guest PC. | Checked by the VMM regression. |

Physical ARM1176 behavior, including the high-impact VFP11 asynchronous
bounce and replay path, remains open. The evaluated results describe software
execution of the arithmetic, including inputs for which ARM1176 hardware
delegates to support code.

### ARM1176 flush sign

With FPSCR.FZ set, the ARM1176 software profile replaces a subnormal
binary32 or binary64 input with positive zero and raises IDC. A nonzero
result whose exact magnitude is below the minimum normal is flushed to
positive zero before rounding and raises UFC. An actual zero operand
retains its sign. The interpreter derives the flush rule from CPU identity
and FPSCR at instruction entry and applies it on each short-vector lane. The
checkpoint representation continues to store the CPU identity and the
raw FPSCR. Each scalar evaluation uses constant time and storage with
respect to operand width and vector length.
[Arm DDI 0301H, sections 18.5.2, 22.5 and 22.9](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

The parent `7abe41862` returned `0x80000000` for multiplying the negative
binary32 subnormal `0x80000001` by +1 with FZ set. The regression also
tests division by a negative subnormal, negative tiny results, square
root, negated multiply, widening and narrowing, and two short-vector
lanes with different causes. The five owning integration binaries passed
47,733 tests. All 18 VMM backend-context tests passed, including the
negative-input control on a restored S3C64xx `v6_k` guest. Library Clippy
passed with warnings denied.

QEMU 11.1.2 `arm1176` preserved the sign in the six sign-discriminating
cases and matched the result and FPSCR in four signed-zero and
gradual-underflow controls. The positive-zero expectations follow the
VFP11 manual. The QEMU outputs and Rust logs are under
`/Users/int/dev/rax-audit-work/four-findings-arm11-flush-sign-2026-11-26/`.
The QEMU receipt SHA-256 is
`3c85e4ab802884a3d3c8a9e246ec3fda428a1d500b62e809ba185e229671ef6a`.

| Assumption | Falsification probe | Impact |
| --- | --- | --- |
| The selected ARM1176 profile uses VFP11's positive-zero rule on a flush. | Divide +1 by a negative subnormal and require +infinity with IDC and DZC. Multiply the negative minimum normal by 0.5 and require +0 with UFC. Repeat at both widths and compare the default modern profile's signed results. | High |
| A sticky UFC flag and an actual negative zero are independent of a new flush. | Write UFC alongside FZ before multiplying negative zero by +1. Require negative zero with the original UFC. Clear FZ and run a representable subnormal through the same multiply. | High |
| The flush rule applies after checkpoint restoration and throughout short-vector execution. | Restore a fresh `v6_k` owner and require positive zero and IDC. Use two vector lanes with an input flush and a result flush and require both flags. | High |

Physical VFP11 timing and asynchronous support-code behavior remain
high-impact validation boundaries.

### ARM1176 default NaN in negated multiply

VFP11 default-NaN mode returns a positive canonical NaN when arithmetic
consumes or generates a NaN. The result is `0x7fc00000` for binary32 and
`0x7ff8000000000000` for binary64. Under the selected ARM1176 profile,
`VNMUL` retains the canonical sign when FPSCR.DN is set. The multiply
supplies the FPSCR exception flags. `VNEG` edits the operand sign in every
mode. `VNMUL` negates propagated NaNs with DN clear and follows the later
Arm profile's sign rule on later CPUs. The instruction-entry profile hint
is derived from the CPU identity that checkpoints store. The result
selection takes constant time and storage per lane.
[Arm DDI 0301H, section 18.5.3 and Tables 20-1 and 20-2](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

The parent `1e58c0e68` returned `0xffc00000` for a quiet NaN multiplied
by +1 with DN set. The new regression varies quiet and signaling NaNs,
an invalid zero-times-infinity product, a finite product, and a separate
`VNEG` at both widths with DN clear, DN set, and both DN and FZ set. It
checks the legacy and later profiles. A fresh S3C64xx `v6_k` restore
executes the signaling-NaN case in RunFast mode and checks the result and
both IOC and the earlier sticky IDC. The five owning integration binaries
passed 47,734 tests. All 18 VMM backend-context tests passed, including the
S3C64xx restore regression. Library Clippy passed with warnings denied.

QEMU 11.1.2 `arm1176` returned negative canonical NaNs for all 12
DN-enabled `VNMUL` cases. It matched the other 18 results. Its FPSCR
observations matched all 30 expectations. QEMU `cortex-a15` matched all
30 later-profile expectations. The ARM1176 sign expectation follows
the VFP11 manual. The assembled guests and raw observations are under
`/Users/int/dev/rax-audit-work/four-findings-arm11-default-nan-2026-11-26/`.
The ARM1176 receipt SHA-256 is
`1f6316dc30dd8edb2fd291778813694067162cc44f2271e48dad80d1fe1bbcc8`.
The Cortex-A15 receipt SHA-256 is
`7a46e890c2a0c6773da18ccb04750ccf2fadcfca331cb10c18a9590ad6832c2d`.

| Assumption | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| The VFP11 arithmetic DN rule applies to `VNMUL`. | A positive canonical result with DN set. | Exercise both widths with a quiet NaN, a signaling NaN and zero times infinity. Read the result bits and FPSCR with DN and RunFast controls. | High |
| NaN sign selection is separate from `VNEG`, finite results and the later profile. | Scope of the result-sign change. | Clear DN, execute `VNEG` with DN set, negate a finite product, and repeat under the later profile. | High |
| The selected CPU identity is sufficient to recover the result rule after a file restore. | `v6_k` resumes the configured arithmetic. | Restore a new VMM, set RunFast in the guest, and require a positive canonical result with IOC and retained IDC. | High |

Physical ARM1176 execution and asynchronous exception replay remain open.

#### ARM1176 invalid products with DN clear

With FPSCR.IOE clear, an invalid `VNMUL` product yields the positive
Default NaN and sets FPSCR.IOC even with FPSCR.DN clear. This applies to
zero times infinity in either operand order, including a subnormal that
FPSCR.FZ flushes to zero. The result and the current operation's IOC
distinguish a generated Default NaN from a propagated canonical quiet NaN
when DN is clear. Sticky IOC alone has no effect on the sign decision.
[Arm DDI 0301H, Table 20-1 and §§22.6–22.6.2](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

The baseline `8bea42a95` returned `0xffc00000` for `VNMUL.F32` with
+0, +infinity, and FPSCR initially zero. The regression covers both
precisions and both profiles, including a canonical quiet NaN with IOC
already set. A fresh S3C64xx `v6_k` checkpoint restore also executes the
invalid product after a guest write clears DN, FZ, and cumulative status.
All 47,734 tests across the five owning binaries and all 18 backend-context
tests passed.

QEMU 11.1.2 `arm1176` matched the FPSCR field in all 16 independent
system-guest observations and produced a negative canonical NaN in the
10 cases where Table 20-1 and §22.6.2 specify a positive one. The guest
sources and receipt are in
`/Users/int/dev/rax-audit-work/four-findings-arm11-invalid-product-2026-11-26/`.
The receipt SHA-256 is
`328bad49d011e66368513343e9f3b3ae21079c9244ab54c8f74785b9f6ed00e1`.

| Assumption | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| VFP11 invalid-product default handling applies across both FZ settings with DN and IOE clear. | Positive Default NaN and newly raised IOC. | Test signed zeros in both operand positions. Multiply a subnormal by infinity with FZ clear and set and check the result bits, IOC, and IDC. | High |
| Per-operation IOC distinguishes the generated canonical NaN from a propagated canonical quiet NaN when DN is clear. | Propagated NaNs retain the existing sign operation. | Seed sticky IOC, then negate a product with a canonical quiet NaN operand. Check the result sign and retained IOC. | High |

Physical ARM1176 execution and asynchronous exception replay remain open.

#### ARM1176 invalid products in VMLS and VNMLA

The VFP11 chained operations round the product and accumulate separately.
With FPSCR.IOE clear, a product that generates a Default NaN passes its
positive canonical bits into the accumulator stage. This follows DDI 0301H
even with DN clear. The multiply stage retains its own exception flags,
and a finite accumulator then receives the positive NaN. The addend sign
operation follows the completed product stage, including any flush to zero.
The sign selection takes constant time and storage per lane.
[Arm DDI 0301H, §18.4.1, Table 20-1 and §§22.6–22.6.2](https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3)

The parent `584f79ad7` produced `0xffc00000` for `VMLS.F32` with
DN and IOE clear, a finite accumulator, and a zero-times-infinity product.
The regression checks both widths, both operand orders, input and product
flushing, and a propagated quiet NaN. The fresh S3C64xx file restore
exercises `VMLS.F32` after a guest write clears the cumulative flags.
All 47,735 tests in the five owning suites and all 18 backend-context
tests passed.

QEMU 11.1.2 matched all 28 later-profile result and FPSCR pairs, and all
28 ARM1176 FPSCR readings. On ARM1176 it returned a negative canonical NaN
in the 12 DN-clear cases where the manual specifies a positive one.
The guests and observations are in
`/Users/int/dev/rax-audit-work/four-findings-arm11-subtract-accumulate-2026-11-27/`.
The receipt SHA-256 is
`152a56b3ab486af5955e96cd52dc9e55dea198951243a91c8c42580de85a3f9e`.

| Assumption | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| The disabled invalid-operation rule applies to the chained product. | VMLS and VNMLA with a finite accumulator deliver a positive Default NaN and set IOC. | Execute both encodings and precisions with either operand order, then repeat with a subnormal flushed before multiplication. | High |
| Rounding and flushing precede the product's sign change in a chain. | The accumulator receives the sign of the completed addend and the product's status. | Multiply the smallest normal by 0.5 with FZ set. Add the negated product to negative zero and require negative zero and UFC. | High |
| The guest's profile remains authoritative after restoring the checkpoint. | The first stage produces the legacy result in the replacement owner. | Restore a fresh S3C64xx VMM, clear FPSCR in the guest, and check the VMLS destination and IOC. | High |

Physical ARM1176 execution and asynchronous support-code behavior remain open.
