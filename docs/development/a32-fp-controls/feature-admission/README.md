# FP16 capability admission references

The two Arm Technical Reference Manuals in this directory distinguish the
MVFR1 scalar field FPHP and the Advanced SIMD field SIMDHP. Cortex-A35
100238_0002_00_en, section 2.6, pages 2-22 and 2-23, describes FPHP=2
and SIMDHP=1 for a conversion-only profile. Cortex-A55 100446_0200_00_en,
section 3.6, pages 3-37 and 3-38, describes FPHP=3 and SIMDHP=2 for
half-precision conversion and data processing. These references establish field
semantics; they do not establish RAX as either processor model.

The instruction-admission requirement comes from the archived
`docs/specifications/arm/aarch32-isa-2025-03.pdf`. VMOVX A1/T1, printed
page 1122 (PDF page 1125), requires FEAT_FP16 before the operation calls
CheckVFPEnabled. The T1 instruction inside an IT block has constrained
unpredictable alternatives, including NOP. Treat that case separately from an
ordinary, feature-disabled instruction. The archived Arm ASL in
`docs/architecture/arm/asl/arm_instrs.asl` also records the HaveFP16Ext
guards for the scalar and vector instruction families.

A retained baseline campaign assembles 17 ARM and 17 Thumb streams and runs
all 34 with FEAT_FP16 disabled and enabled. Before the fix all 68 execute. The
28 feature-disabled data-processing/register/load forms contradict their
mandatory feature guard. The six feature-disabled conversion-only forms are
positive controls. The updated implementation rejects all 28 disabled forms
before register, PC or instruction-count changes, while all 40 positive
controls still retire. Another 32 ARM/Thumb controls retain integer halfword
SIMD, lane transfers, ordinary scalar loads and FP32 execution under both
FP16 settings. The campaign includes scalar
and vector addition, half-register moves, half loads, estimates, number
min/max, rounding, integer/fixed conversion, scalar-lane multiplication,
absolute value and comparisons. The assembler is an encoding tool, not the
semantic oracle. Exact sources, outputs and producer hashes reside in the
audit evidence under `a32-admission-study/admission-matrix-*`.

The shared standalone/mixed executor derives half-precision admission from
MVFR1, before its FP access trap checks. The mixed-width producer derives
FPHP/SIMDHP from the enclosing FP16 flag: (2,1) for conversions and (3,2)
for conversion and arithmetic. FPSCR.FZ16 is masked in conversion-only
profiles, including state copied from the enclosing PE. The full-half default
profile skips further family classification. Classification has bounded O(1)
time and space for each decoded instruction.

Armv8-R Supplement DDI0568A.b, Table B1-1, printed/PDF page B1-26/26,
also documents FPHP=1 for half/single conversion without double precision.
The pre-existing primary PDF is
`docs/specifications/arm/DDI0568A_b_armv8_r_supplement.pdf`.
The capability-boundary test additionally uses adversarial independently varied
fields and reserved values; these combinations are not claims of valid ARMv8-A
configurations. A35 section 3.3's FPSCR diagram (PDF page32) and A55
section3.3, FZ16 description (PDF page33), distinguish the reserved bit from
the half data-processing control.

Full A32-FP closure additionally requires profile/control consistency,
including AArch64 ID-register views and non-half capability fields, and the
remaining security/virtualization cases. SBZ encodings retain their separately
recorded permitted canonical-execution disposition.

Assumption F1 is that the enclosing configuration's FP16 flag denotes an
implemented capability, as documented by `AArch64Config.features`. Stress it
with both flag values, both execution states, all classified families, positive
conversion controls, and trap precedence. An instruction executing when its
mandatory feature is absent falsifies that contract. The baseline falsifies it; the corrected mandatory controls now pass.

High-impact remaining work is coherent profile identity and instruction
admission across the affected execution planes. Physical A32 behavior and
additional trapped profiles remain unverified. Exact red/green, native-host,
Rosetta, library, SMIR, C API and build commands/counts are retained in the
qualification receipt; Rosetta is not a physical A32 or Intel HVF oracle. Provenance, retrieval times,
checksums and original notices are retained with the unmodified PDFs.

Final qualification passed 10796 library tests (two pre-existing ignores),
47437 tests across five owning targets, 478 tests across the Rosetta owning
targets, 208 C API tests, 18 C/C++ consumers, six strict ABI objects,
formatting, workspace Clippy and the shared all-target build. The owning
target includes all nine new admission tests. Rosetta omits 34 AArch64-host
reference tests from the 484-case native-host VFP target. No native A32 or
physical Intel HVF proof is inferred. The qualification receipt records the
corrected fixture compile and rejected stale-artifact attempt as invalid
attempts, with the successful exact-artifact controls retained separately.
