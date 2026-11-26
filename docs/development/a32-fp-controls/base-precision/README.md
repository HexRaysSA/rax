# Scalar A32/T32 precision admission

The scalar admission path now checks MVFR0.FPSP and FPDP independently of
register-bank width. Values 1 and 2 describe VFPv2 and VFPv3 arithmetic; all
other values do not enable that precision. VMOV floating constants and
fixed-point conversions require value 2. Conversion between single and double
precision requires both precisions. FPDivide and FPSqrt must equal 1 for the
corresponding FP32/FP64 operations.

Core transfers, FP system-register access and raw scalar memory transfers use
the scalar FP capability. A 64-bit D-register storage operand does not imply a
double-precision arithmetic requirement. Existing FP16 feature/conversion
admission remains distinct; FP16 data operations are not inferred from FPSP.
Scalar precision fields do not govern Advanced SIMD operations.

## VFPv2 User-mode FPSID reads

The generic standalone VFPv2 profile permits `VMRS Rt,FPSID` in User mode after
the ordinary coprocessor access checks. The read is independent of
`FPEXC.EN`. Profile selection uses `FPSP=1` and `FPDP` equal to zero or one.
In this legacy profile, a T32 `VMRS` or `VMSR` with SP as the core operand
selects RAX's Undefined diagnostic for the unpredictable encoding. A32 permits
SP in either direction. The restriction applies after the instruction predicate
passes and before FP permission checks. The mixed-width Armv8-A profile permits
the SP operand even with imported VFPv2 precision IDs.
The standalone VFPv3 and mixed-width Armv8-A profiles require privileged
access to FPSID. The access check takes constant time and space.
[Arm DDI0406C.d, §§ B1.11.2, B9.3.21 and B9.3.22](../../../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf)
[Arm DDI0597 ID032025, pp. 1124–1125 and 1127–1128](../../../specifications/arm/aarch32-isa-2025-03.pdf)

The ARM1176-style VM setting has its own FPEXC.EN and User access rules.
[ARM1176-style VFPv2 selection](../../a32-fp-controls.md#arm1176-style-vfpv2-selection)

| Assumption and basis | Dependent behavior and falsification probe |
| --- | --- |
| The standalone precision pair identifies VFPv2. Arm § B1.11.2 permits reads at PL0. | Attempt the read in A32 and T32 with CPACR full, privileged-only and denied. Check the returned ID, untouched state on denial, and both values of FPEXC.EN. |
| The legacy permission is specific to the FPSID read. | At PL0, check rejection of an FPSID write, an FPSID read targeting R15, and an MVFR0 read. |
| The legacy T32 encoding constrains SP. | Read FPSID into SP and move FPSCR and FPEXC to and from SP. Use both instruction sets, both legacy FPDP selections, and a failed condition. Compare SP, FPSCR and FPEXC before and after each instruction. |
| Imported capabilities leave the enclosing PE's regime Armv8-A. | Inject VFPv2 precision IDs into the mixed-width PE and require Undefined with zero retirements and the original operand in ARM and Thumb. |
| The Armv8-A SP allocation is independent of the imported precision IDs. | Import VFPv2 precision IDs and execute all four T32 FPSCR and FPEXC transfers using SP at EL1. Each must retire once. |

On `445ca8894`, the first standalone control returned Undefined and the
mixed-width control passed. In QEMU 11.1.2, ARM1176 returned `0x410120b5`
to R2 and SP with FPEXC.EN clear and CPACR enabled. After disabling
CPACR, the same guest reached the Undefined vector with its original
destination. Cortex-A15 reached the Undefined vector with CPACR enabled.
The QEMU cases execute A32 and exercise emulated CPU models. Physical Arm
execution remains open.

On `28f612e00`, both new standalone regressions failed because RAX accepted
the first legacy T32 `VMRS` and `VMSR` using SP. QEMU 11.1.2 `max` executed
all four FP system-register transfers in both instruction sets and returned
the expected ARMv8-A register effects. The QEMU Cortex-A15 model also
executed the four raw T32 encodings. RAX selects Undefined for its legacy
VFPv2 profile under the Armv7-A `UNPREDICTABLE` rule. LLVM MC 23.0.0git
assembled all four T32 forms for Armv8-A, rejected both Thumb FPSCR forms
for Armv7-A, and assembled the Thumb FPEXC forms on both targets.
The QEMU receipt SHA-256 is
`dce847566d7c3b1a37e5a2f86e0b4b1d2e73e21a864b3c9f76d7ce266817fb1e`.

All 47,769 tests passed across seven complete macOS Arm64 targets with zero
failures or ignored cases. The targets were `a32_fp_controls` (223),
`a32_fp_pairs` (5), `arm` (46,850), `arm_vfp_a32` (538), `isa_oracle` (102),
`smir_jit_aarch32_aarch64` (26) and `smir_jit_thumb_aarch64` (25).
The combined test log SHA-256 is
`1df81fdcdbbeb906e64bb3d0bb88acaeef95fe075b0f6af8f8fd92930a75b199`.

## VFPv2 MVFR2 selector

The standalone VFPv2 profile selects Undefined for `VMRS Rt,MVFR2` in
A32 and T32 before checking HCPTR.TCP10 or HCR.TID3. Arm DDI0406C.d
Table B1-24 reserves selector 5. Section B1.14.2 includes MVFR0 and MVFR1 in
ID group 3. The current Armv8-A allocation includes MVFR2, so an Armv8-A PE
continues to expose it even if its imported precision fields report VFPv2.
See the [archived Armv7-A manual](../../../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf)
and the VMRS encoding in [Arm DDI0597 ID032025](../../../specifications/arm/aarch32-isa-2025-03.pdf).

The standalone regression varies the two VFPv2 precision pairs, A32/T32
state and competing access traps. The Armv8-A mixed-width control imports
the legacy precision fields, reads MVFR2 with FPEXC.EN clear, and checks the
exact retirement count. The baseline at `22dfee6aa` accepted `0xeef52a10`
under the VFPv2 single-precision selection.

QEMU 11.1.2 ran 20 bare-metal register reads. `arm1176` took Undefined for
selector 5 in A32. `cortex-a15` took Undefined in A32 and T32. `max` read
`0x43` in both states. All three models completed their FPSID, MVFR0 and
MVFR1 controls. The QEMU receipt SHA-256 is
`838c50b030aca9979c77ff360a8b80a522d48d93023bfa80bbb0328ef7f1476d`.

On macOS arm64 with `--no-default-features`, `a32_fp_controls`,
`a32_fp_pairs`, `arm_vfp_a32`, `isa_oracle` and `arm` passed 47,723 tests
with zero failures or skips. Physical AArch32 execution remains unverified.

## Evidence

[Provenance](provenance.json) identifies the retained Arm MVFR0 definition and
QEMU implementation. The independent Cortex-M4 Thumb control executes 12
cases using observed MVFR0=`0x10110021`, MVFR1=`0x11000011`. Double arithmetic,
register VMOV.F64 and conversions to/from double are undefined; raw 64-bit
storage, scalar FP32, its constants/fixed conversions, division and square
root execute. These are shared instruction/capability controls. They do not
establish A32-mode execution on Cortex-M4 or equivalence of M-profile and
A-profile exception controls. Physical A32 execution is unverified.

[Assembly and LLVM encodings](assembly.json) retain 16 ARM/Thumb pairs. LLVM
provides encodings, not semantic expectations. The RAX baseline passes storage
controls and fails four groups: absent/reserved precision, SP-only rejection of
double operations, missing divide/sqrt support and VFPv3-only forms under v2.
Boundary tests independently vary ID fields; these do not assert that a
processor implements every varied combination.

The correction tests architectural register/FPSCR/CPSR/memory preservation on
rejection, both ordinary and denied FP access, and permitted storage controls.
The existing registered `a32_fp_controls` target owns the tests. No new Cargo
target or CI shard is needed.

```sh
cargo test --locked --no-default-features \
  --features x86_64-suite,smir-jit,hvf --test a32_fp_controls \
  -- --test-threads=1 --nocapture
```

[Qualification](qualification.json) records 540 passing tests, formatting and scoped
Clippy, with exact commands and source hashes. Validation
uses the combined integration checkout, including unfinished native changes.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|---|
| BP1 | Precision fields constrain arithmetic and conversion admission. | Arm DDI0487B.a G6.2.107; independent SP-only QEMU controls. | Absent/invalid precision rejection. | Both conversion directions and absent/reserved precision; successful absent arithmetic falsifies it. | Baseline violation reproduced; represented corrected controls pass. |
| BP2 | Raw 64-bit storage remains available with scalar single precision alone. | QEMU trans_VMOV_64_dp and trans_VLDM_VSTM_dp; actual SP-only guest controls. | Legal D-register storage. | Core pair transfer and D-register loads/stores with FPDP=0; rejection falsifies it. | Baseline and independent controls pass. |
| BP3 | Constants/fixed conversion and divide/sqrt obey their separate feature fields. | Arm MVFR0 definitions and retained QEMU v3 guards. | Exact instruction-family admission. | v2 versus v3, field 0/1/reserved and ordinary/denied access; successful unavailable operation falsifies it. | Baseline violation reproduced; represented corrected controls pass. |
| BP4 | The selected standalone VFPv2 profile uses the legacy VMRS selector allocation. | Arm DDI0406C.d Table B1-24 and B9.3.21. | Undefined precedes both FP access traps for selector 5. | Exercise both VFPv2 precision pairs and widths. Read MVFR2 on the mixed-width Armv8-A PE after importing VFPv2 fields. | Baseline violation reproduced; corrected controls pass. |

## Boundaries

The default full scalar profile uses a constant-size fast check. Classification
has O(1) time and space for a decoded instruction. No architectural state,
serialization layout or public API signature changes. The A32/T32 SMIR lifters
continue to reject these FP families before native lowering.

High-impact remaining work includes Advanced SIMD subfields, rounding/denormal
profile controls, coherent advertised profile identity and remaining security
and debug behavior. Complete native/private state and restoration, actual SMP
execution and remaining Intel HVF source/runtime qualification remain open.
This scalar correction does not close any of the original four findings.
