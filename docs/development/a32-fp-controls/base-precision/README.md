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
