# A32/T32 D16 register-bank admission

`MVFR0.SIMDReg=1` exposes D0-D15; S0-S31 alias that bank. The
standalone executor now rejects D16-D31 operands and block transfers whose
last D register exceeds D15 before FP access traps, destination writes,
memory operations, or base writeback. Advanced SIMD requires the D32 bank.
`SIMDReg=0` and reserved field values do not enable FP instructions.

The guard distinguishes operand roles: conversion integer/S-register operands,
fixed-point fractional immediates, VMOV literals, and zero comparisons do not
accidentally count as high D registers. Core pair/lane moves and scalar memory
transfers use decoded FP operands. Register-bank admission does not infer a
double-precision arithmetic requirement from a 64-bit storage operand.

The D32 path remains available to the enclosing AArch64 PE. D16 is a standalone
A32 configuration, not a claimed valid ARMv8-A mixed-width profile. Scalar
precision, divide/square-root feature fields, Advanced SIMD subfields, coherent
feature identity and the remaining security/debug cases require separate
qualification before A32-FP can be closed.

## Evidence and reproduction

[Arm reference and QEMU provenance](provenance.json) records the retained
primary sources, exact field definitions and runtime evidence. [Assembly](cases.s)
and [assembler output](assembly.json) retain 35 paired ARM/Thumb encodings.
The independent Cortex-A15 campaign passes 132 cases: 33 operations, two
execution states and two actual accepted D16/D32 profiles. Directed conversions
require a newer architecture than Cortex-A15, so their four RAX controls use
the manual's register-bank rules rather than that QEMU model as an oracle.

The RAX baseline passes the full-bank controls and fails four regression groups:
scalar high-D access, core/memory transfers, crossing block transfers and
Advanced SIMD under D16. Raw failure logs remain in the audit evidence.
The registered `a32_fp_controls` target owns these regressions; no new Cargo
test target or CI shard is required.

```sh
cargo test --locked --no-default-features \
  --features x86_64-suite,smir-jit,hvf --test a32_fp_controls \
  -- --test-threads=1 --nocapture
```

[Validation receipts](qualification.json) record 31 owning tests, 497 VFP tests,
five core-pair tests, formatting and scoped Clippy, all passing.
Runs validate the combined integration checkout, which also contains unfinished
native checkpoint changes; they do not imply closure of C-STATE, C-SMP or C-HVF.

## Standalone FP control register views

The standalone D16 bank has no Advanced SIMD. The guest's CP15 view
therefore reports the following fixed bits and ignores writes to them.
Other fields retain their usual access permissions. The view is recomputed
from the saved MVFR0 value in constant time and uses the existing checkpoint
fields. The AArch64-hosted AArch32 view continues to use its own system controls.
[Arm DDI0406C.d for CPACR, HCPTR and NSACR](../../../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf)

| Profile | Field | Guest readback |
| --- | --- | --- |
| D16 | CPACR.ASEDIS/D32DIS [31:30] | `0b11` |
| D16 | NSACR.NSASEDIS/NSD32DIS [15:14] | `0b11` |
| D16 | HCPTR.TASE [15] | `1` |
| D32 with D32DIS unimplemented | NSACR.NSD32DIS [14] | `0` |

The paired ARM and Thumb regression writes the affected fields as zero,
one, then zero with unrelated register bits enabled. It runs on both banks
and reads HCPTR from Hyp mode. The predecessor failed in both instruction
sets. The D16 controls could read as zero, and D32 NSACR read back a set
NSD32DIS bit despite CPACR.D32DIS being unimplemented.

The baseline log SHA-256 is
`555d9aac03e1886131406527def2dfabb0b7b7206d10b6f6c7cacc18fff48686`.
All 47,691 tests in the five unfiltered macOS Arm64 targets passed with
zero failures or ignores. The final log SHA-256 is
`4ac6a0e85de366c0db6816ade0505f5fdb7dd1ccfa16a26961c6eee8438bc278`.

```sh
cargo test --locked --no-default-features --features hvf,debug \
  --test arm_vfp_a32 --test a32_fp_controls --test a32_fp_pairs \
  --test arm --test isa_oracle -- --test-threads=4
```

QEMU 11.1.2 Cortex-A15 with `neon=off,vfp-d32=off` reported MVFR0
`0x10110221` and CPACR `0xc0f00000` after writes of both `0x00f00000`
and `0xc0f00000`. Its synthetic D16 preset retained writes to NSACR
bits [15:14] and HCPTR bit [15]. The table follows the Arm register
definitions for those fields. The physical standalone D16 control behavior
remains unverified.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Standalone MVFR0.SIMDReg=1 selects the D16 bank with FP and no Advanced SIMD. | High | Use the existing high-register and Advanced SIMD rejection controls alongside the CP15 write/read matrix. A D16 case with Advanced SIMD effects invalidates the derivation. |
| The D32 profile leaves D32DIS unimplemented. | Medium | Verify CPACR.D32DIS and NSACR.NSD32DIS after writes of both bit values. Check that the other writable disable and trap bits still respond. |

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|---|
| RB1 | The public standalone MVFR0 bank field constrains executable register accesses. | Arm DDI0487B.a G6.2.107 and independent accepted QEMU profiles. | D16 admission. | High registers in each operand role, block transfer crossing D15; successful execution of an absent register falsifies it. | Baseline exposed the violation; all represented corrected controls pass. |
| RB2 | Scalar S-register and nonregister encoding bits must remain legal with D16. | S0-S31 alias D0-D15; instruction encodings and QEMU controls. | Legal controls preserved. | S31, fixed-point immediates, VMOV literal and zero comparison; rejection falsifies preservation. | Independent and corrected RAX controls passed. |

## Scope and cost

The guard uses bounded operand inspection and fixed-size instruction
classification: O(1) time and O(1) space for the bounded decoded operand vector.
High-impact remaining work is the other profile/control fields and original
checkpoint/SMP/Intel findings; this register-bank correction does not close them.
Physical A32 execution is unverified. QEMU build identity beyond its version
string is unknown. No native lowering changes follow: the A32/T32 SMIR lifters
admit scalar integer forms and reject these FP families before native execution.
