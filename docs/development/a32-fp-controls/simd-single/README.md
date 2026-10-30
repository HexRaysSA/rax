# A32/T32 single-precision Advanced SIMD admission

`MVFR1.SIMDSP` now admits FP32 Advanced SIMD data processing only for field
value1. Exact decoder classes distinguish integer aliases from FP arithmetic.
The guard covers vector/lane arithmetic, pairwise operations, comparisons,
reciprocal estimates/steps, rounding, integer/fixed conversions, FP16/FP32
conversions and FHM's FP32 accumulation. It runs before access traps and effects.

Integer/storage operations, scalar VFP and separately admitted pure FP16 data
processing retain their own capabilities. A `.f32` modified-immediate VMOV
materializes bits; it is not FP32 arithmetic. The [Arm extracts](storage-and-fhm.asl)
and [provenance](provenance.json) distinguish it from FHM's FP32 accumulator.

Twelve new tests cover91 LLVM-assembled operations in ARM and Thumb. Nine fail
before the change; all58 owning tests,497 VFP tests and five pair-transfer tests
pass after it. Missing/reserved fields, access priority and state/RAM invariance
are checked. Positive integer, storage, scalar and half controls prevent
mnemonic-only over-rejection. Field variations are synthetic admission controls,
not claims about processor identities or coherent physical profiles.

The [independent QEMU results](qemu-results.json) contain364 actual controls:
91 operations x ARM/Thumb x two valid profiles. Full `max` supports the newer
forms; a Neon-disabled Cortex-A15 provides undefined controls while retaining
supported scalar VFP. The profiles also differ in D32 and other optional features;
they do not isolate SIMDSP. Two rejected setup attempts remain in raw evidence.
The [generator](qemu-controls.py) retains the tested local paths and commands.

[Qualification](qualification.json) records assumptions and validation receipts.
Workspace library check and owning-target Clippy pass. This does not establish
current full-library, physical A32, C API runtime or other-platform coverage.
A32 rounding/denormal/coherent-profile/security/debug work and the other three
original findings remain open.
