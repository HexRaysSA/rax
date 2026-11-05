# AArch32 scalar selector admission

Reserved scalar VMLA encodings such as A32 `f2800140`/`f3800140` and Thumb
`ef800140`/`ff800140` previously fell through to VADDW decoding. With FP enabled
they could execute and change vectors; denied controls could select an FP-access
trap instead of the required Undefined exception. The corresponding scalar
VMLS and VMUL allocation boundaries are covered by the same correction.

The decoder recognizes the scalar family before its size check, returns
Undefined for size=0, preserves size=3 related encodings, and requires the fixed
bit6=0 selector for widening add/subtract. The change uses constant time and
auxiliary space. Legal scalar routing and widening integer behavior retain
positive execution controls.

The primary reference is [Arm DDI0597 ID032025](../../specifications/arm/aarch32-isa-2025-03.pdf),
one-based PDF pages 1067/1068 (VMLA), 1081/1082 (VMLS), 1133/1134 (VMUL), and
782/784 (VADDL/VADDW). [Provenance](provenance.json) records the manual hash and
independent tool identities. Feature-dependent FP16 admission and constrained
unpredictability are distinct from the mandatory size=0 guard.

| Assumption | Stress test and falsification probe | Status |
|---|---|---|
| size=0 requires Undefined before FP access and side effects | Instruction-specific primary guards; 12 QEMU reserved cases; enabled, denied, Hyp, and mixed A32/A64 state-preservation checks | Confirmed in stated domain |
| size=3 belongs to related encodings | Exhaustive 2097152-case VEXT neighbor test in the complete owning target | Passed |
| Legal scalar operands and widening integer operations retain their routing | 16 QEMU positive controls and exact register/result checks | Passed |

A 1179648-case canonical encoding census found 32768 baseline VMLA mismatches.
The earlier complete 99-test control target failed three tests before the fix.
The current target adds an exhaustive related-encoding preservation test and
contains 100 tests. Host-specific VFP tests make the owning VFP count differ
between Linux x86-64 and Apple Silicon; these counts are retained separately.

[Qualification](qualification.json) records current complete-target results.
The complete JIT and no-JIT targets each passed 100 control, five pair,
524 VFP, and 46850 ARM tests. The complete C API target passed 245 tests;
workspace Clippy, all-target build, and doctest commands succeeded. The
complete library target passed 12408 tests with zero failures and 36 ignored.
Its aggregate source guard reported later Intel-only edits; the qualification
record preserves that failure and attributes the library results to the frozen
source and executable. All A32 source, test, and runtime fixture hashes stayed
unchanged.
No physical AArch32 validation is claimed. High-impact native backend state,
interrupt, timer, and Intel guest-execution requirements remain outside this
component and keep the four-finding goal open.
