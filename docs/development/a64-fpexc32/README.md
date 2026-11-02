# FPEXC32_EL2 access and selected AArch32 alias

This group makes guest A64 FPEXC32_EL2 transfers use the selected AArch32 FPEXC
view in both the default non-trapping and optional synchronous-trapping profiles.
Previously, the default profile could admit EL1 transfers, expose upper/reserved
bits, and bypass CPTR traps. The optional profile also missed the CPTR and
EL1-capability checks in the guest instruction path.

The instruction preflight rejects EL0/EL1 access and an absent or reserved
ID_AA64PFR0_EL1.EL1 capability before reading an operand, changing the bank, or
retiring. It then applies the existing system-FP access policy, including
CPTR_EL2.TFP, VHE CPTR_EL2.FPEN and CPTR_EL3.TFP. Diagnostic calls retain the
existing InvalidExceptionLevel error for an inaccessible EL; system execution
delivers an Undefined Instruction exception. Higher FP controls deliver EC 0x07,
ISS 0, with the exact fault PC and no retirement.
Existing unbound system-entry timer polling keeps its attempt-time policy. The
file tests use VM-owned Retired time and assert no clock increment on denial.

Allowed reads and writes reuse the same 32-bit VfpState canonicalization used by
A32 VMRS/VMSR. The optional FPTrap and ShortVectors selections remain independent.
An all-ones write reads as follows:

| Selected view | FPEXC32_EL2 |
| --- | --- |
| Non-trapping | 0x40000700 |
| Trapping, no short vectors | 0x6400079f |
| Trapping, short vectors | 0x6000079f |

HCR_EL2.RW selecting A64 execution for EL1 does not remove EL1's implemented
A32 capability or the alias. FPEXC32_EL2 has no effect on A64 arithmetic. Host
register inspection retains its existing direct-helper policy; guest permission
checks are owned by the instruction preflight.

The generic native register image has no FPEXC bank. Original source words
therefore retain a managed interpreter boundary, including an MRS result sent
to XZR or erased by optimization. Native admission tests assert fallback and a
non-FPEXC positive control. Four 128-iteration guest loops require nonzero
bounded native execution of ordinary instructions, then deny the warmed FPEXC
transfer after CPTR changes with exact PC and zero additional retirement. These
probes do not establish native FPEXC execution.

## Primary rules

[Arm DDI0487B.a](../../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf),
D7.2.32, PDF pages 2295-2299, specifies the mapping, width, implemented capability,
accessibility and CPTR traps. This unchanged Arm-authored PDF was retrieved from
an academic mirror; identity with a current Arm-hosted byte stream is unknown.
Its retained provenance and hash are recorded in qualification.json.

[Arm shared pseudocode, 2025-12](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml),
AArch64_CheckFPAdvSIMDTrap, confirms the existing higher-control rule. An initial
hypothesis that CPTR_EL3.TFP cannot trap at EL3 was falsified; that behavior was
preserved. The revision boundary excludes unrepresented nested virtualization,
RME and architectural halting-debug state.

## Evidence and limits

Four new regressions failed against unchanged parent production code. The final
matrix covers lower ELs, every transfer register, absent/reserved capability,
VHE FPEN, both selected profiles and short-vector combinations, reserved bits,
zero-retirement delivery, exact exception frames, real ERET retry, and original
word native admission.

Per runtime-matrix execution, fifteen actual source-free checkpoint files cover
1/2/4 prepared CPUs: six files
after a bank write and before A64 read/A32 ERET, three after FP fault delivery
and before a guest handler clears CPTR and retries, and six before an
unimplemented-alias access with conflicting FP traps. Each constructor runs
after removal of the original kernel and snapshot files. Tests compare complete
public CPU images, instruction counts, coordinator state and the owning VM clock
before and after continuation. Peer startup is prepared through platform requests;
these cases do not establish guest cold startup or physical native execution.

No wire field, context version, exported ABI identifier or C layout changes.
Existing legacy raw storage remains readable through the canonical view; this
group does not rewrite old capture bytes or reconstruct unrepresented state.

The additional dispatch and admission checks use O(1) time and O(1) space per
instruction. Existing native admission remains O(N) in the number of operations.
No performance measurement or hardware-conformance claim is made.

The original A32-FP, C-STATE, C-SMP and C-HVF findings remain open. Complete
profile/security/debug admission, backend/private/in-flight/IRQ/startup/replay
coverage and physical Intel execution require their own remaining evidence.
Exact assumptions, falsification probes, scope impacts and executable/source
hashes are in [qualification.json](qualification.json).

## Final local validation

| Gate | Outcome |
| --- | --- |
| doctests-workspace-v3 | 0 passed / 0 failed / 5 ignored; 0 passed / 0 failed / 0 ignored |
| focused-fpexc32-v3 | 10 passed / 0 failed / 0 ignored |
| owning-root-library-v3 | 11979 passed / 0 failed / 35 ignored |
| owning-arm-v3 | 46850 passed / 0 failed / 0 ignored |
| owning-arm_vfp_a32-v3 | 521 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_programs-v3 | 75 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_native-v3 | 0 passed / 0 failed / 0 ignored |
| owning-smir_jit_aarch32_aarch64-v3 | 26 passed / 0 failed / 0 ignored |
| owning-smir_jit_thumb_aarch64-v3 | 25 passed / 0 failed / 0 ignored |
| owning-checkpoint_cpus-v3 | 12 passed / 0 failed / 0 ignored |
| owning-checkpoint_resume-v3 | 10 passed / 0 failed / 0 ignored |
| owning-checkpoint_config-v3 | 1 passed / 0 failed / 0 ignored |
| owning-retired_clock-v3 | 13 passed / 0 failed / 0 ignored |
| owning-checkpoint_clock-v3 | 16 passed / 0 failed / 0 ignored |
| owning-retirement_clock-v3 | 10 passed / 0 failed / 0 ignored |
| owning-counter_ticks-v3 | 12 passed / 0 failed / 0 ignored |
| owning-retirement_budget-v3 | 14 passed / 0 failed / 2 ignored |
| owning-user_linux-v3 | 43 passed / 0 failed / 1 ignored |
| owning-capi-library-v3 | 241 passed / 0 failed / 0 ignored |

Formatting, all-target build/check/Clippy and without-debug/without-JIT
compilation passed. Exact receipts and source/executable hashes are in
qualification.json.
