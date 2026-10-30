# A32/T32 miscellaneous and fused floating-point admission

The common AArch32 executor checks the capabilities advertised by MVFR1 and
MVFR2 before FP access controls or instruction effects. Failed ARM conditions
and legal Thumb IT predicates are resolved first. This supplements the existing
FP16/FHM checks without changing default feature values or checkpoint formats.

## Capability definitions

The retained Arm-authored primary source is
[`DDI0487B.a`](../../../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf),
G6.2.108 (G6-5069) and G6.2.109 (G6-5073–5074). Its academic-mirror origin and
unverified byte identity to a current Arm-hosted copy are recorded in the
[source provenance](../../../specifications/arm/aarch32-fp-profile/provenance.json).

| Field | Implemented-family admission |
|---|---|
| MVFR1.SIMDFMAC[31:28] | Exactly 1 admits scalar/vector VFMA/VFMS and scalar VFNMA/VFNMS. Zero is absent; 2–15 are reserved. |
| MVFR2.FPMisc[7:4] | 1 adds selection; 2 adds directed integer conversion; 3 adds rounding to integral FP; 4 adds number min/max. Zero is absent; 5–15 are reserved. |
| MVFR2.SIMDMisc[3:0] | 1 adds directed integer conversion; 2 adds rounding to integral FP; 3 adds number min/max. Zero is absent; 4–15 are reserved. |

The primary manual permits only FPMisc 0/4 and SIMDMisc 0/3 in Armv8-A.
Tests of other defined field levels exercise field interpretation; they do not
establish physical Armv8-A profiles. Reserved values fail closed for the affected
family. Ordinary nonfused arithmetic, ordinary conversions and conversion-only
FP16 instructions retain their independent requirements.

FP16 data forms must also pass the existing FPHP/SIMDHP admission. Artificial
combinations advertising FP16 data processing while denying the corresponding
miscellaneous/fused family reject; those synthetic tests do not claim a physical
processor implements such contradictory combinations. FHM keeps its separate
ISAR6.FHM requirement.

The guard performs constant-time field extraction and mnemonic classification,
with constant auxiliary space.

## Execution planes and state

The standalone and mixed AArch64/AArch32 interpreters share the executor gate.
Mixed execution continues to project its enclosing PE's full classic
miscellaneous/fused profile; no new independent mixed-profile selector is added.
Tests cover enabled mixed execution and higher-EL access traps.

The A32 and Thumb lifters continue to reject these profile-dependent FP forms.
They acquire no SMIR/native implementation or profile-free admission. Static
decode remains independent of the executing CPU's selected capabilities.

The complete standalone backend context retains MVFR1/MVFR2, the public register
projection and retirement count. The S3C-backed VMM tests use actual `.rxc`
save/load/construction with two and four CPUs, alternating ARM/Thumb and enabled/
disabled profiles, then compare complete backend records after continuation.
The fixture explicitly marks its preconfigured contexts online before capture;
it exercises coordinator execution and restoration, not guest AP startup.
Their configured software profiles are not claims about physical ARM1176
instruction support or native hardware SMP.

The S3C adapter now supplies the vCPU single-step contract, so the coordinator
uses its exact retirement quantum instead of the legacy 65,536-attempt `run()`
batch. Capability/access/data faults yield with zero retirement before a handler
instruction executes. Pending IRQ delivery, WFI/wake, retiring shutdown stores
and wrapping instruction counters are tested at the same boundary. Its existing
platform/device clock policy and physical board topology are not redefined by
this adapter change.

Progress and idle steps both poll the existing periodic heartbeat, retaining
diagnostics and `RAX_DUMP_PHYS` during continuous execution. A regression forces
an overdue heartbeat and compares complete backend records with a fresh control
after the same NOP. Earlier validation runs were intentionally interrupted when
review found the missing progress-path poll; final gates use the corrected source.

## Independent observations

The [encoding fixture](misc-and-fma-cases.json) contains 86 S/D forms, 28 baseline
controls and 12 FP16 controls. LLVM MC independently reassembles both execution
states. The oracle additionally constructs eight scalar failed-predicate probes
with CPACR and FPEXC access disabled.

QEMU 11.1.2 produced 804 observations across Cortex-A9, Cortex-A15 and `max`:
796 agree with the primary capability expectations. Eight Cortex-A9 vector fused
observations disagree: VFMA/VFMS over D/Q registers execute in ARM and Thumb
despite SIMDFMAC=0. The retained QEMU `translate-neon.c` macro
`DO_3S_FP_GVEC` checks half support but lacks a classic fused-capability check.
The raw outputs and discrepancies are retained; architectural expectations
remain based on the primary MVFR1 definition.

MVFR2 reads are undefined on the selected pre-v8 QEMU models. Their recorded
zero value is an initialized sentinel, distinguished by `mvfr2_undefined=1`.

Reproduce with a fresh output directory and an explicitly selected scratch root:

```sh
TMPDIR=/path/to/scratch python3 -B tools/execution/a32_misc_admission_oracle.py \
  --output /path/to/fresh-observations \
  --llvm-mc /path/to/llvm-mc --ld /path/to/ld.lld \
  --qemu /path/to/qemu-system-arm
```

The command records observations and differences; an `observed` receipt is not
an assertion that QEMU agrees with every primary expectation. Exact versions,
hashes, source lineage and counterexamples are in the
[qualification provenance](misc-and-fma-provenance.json).

## Assumption register

| ID | Assumption and dependent result | Stress test and falsification evidence |
|---|---|---|
| M1 | The represented MVFR fields select the affected instruction capabilities. This determines the admission guard. | Primary field definitions, enabled profiles, reserved values and pre-fix execution failures. A primary requirement selecting these capabilities independently would falsify the rule. The eight retained QEMU differences do not change the primary expectation. |
| M2 | Legitimately failed predicates suppress capability and access checks. This determines exception ordering. | ARM conditions, legal Thumb IT blocks, disabled access and 48 independent skipped-instruction observations. An executed capability fault for a legal skipped form would falsify the ordering. |
| M3 | Intermediate MVFR2 levels and contradictory ID combinations are physical Armv8-A profiles. | **Falsified:** the primary manual restricts Armv8-A to FPMisc 0/4 and SIMDMisc 0/3. These cases qualify software field interpretation only. |
| M4 | Constructing multiple vCPUs makes them online. This determines the file fixture's expected turns. | **Falsified:** the coordinator initializes only CPU0 online; retained failures selected halted CPU0 again. The fixture explicitly activates its prepared contexts. Architectural AP startup remains a separate requirement. |
| M5 | Connecting raw platform stepping preserves the legacy heartbeat. This determines diagnostic compatibility. | **Falsified for the initial adapter:** an overdue timestamp stayed unchanged after a successful step. The corrected Progress path polls the existing heartbeat; the eight platform regressions include complete backend-state equality against a fresh control. |

## Feature-configuration validation

The interpreter-only workspace check exposed two pre-existing A64 retirement
fixtures calling `set_jit_enabled` without its `smir-jit` and AArch64 guards.
Both calls now use the method's exact condition. The test code selected by the
active AArch64/JIT full-library run is unchanged; the recorded source projection
compares byte-for-byte with the pre-correction fixtures. Neither fixture belongs
to the regular library used by the owning integration binaries. Final checks
also compile the interpreter-only and x86 host configurations and execute the
actual `retirement_counters` modules in both JIT and interpreter builds.

## Recorded local validation

The complete owning integration run passed 47885 tests in 27 binaries. The full library passed 11355 tests with 2 explicitly ignored cases; the C API passed 222. Doctests executed zero cases and retained five ignores. Corrected retirement-counter fixtures execute in both feature configurations. Formatting, clippy, workspace builds, interpreter-only checks and x86 cross-compilation passed. Cross-compilation does not establish physical Intel execution. Full source/receipt and source-equivalence boundaries are retained in the qualification provenance.

## Full audit boundary

A32-FP, C-STATE, C-SMP and C-HVF remain incomplete. Remaining complete-profile,
security/debug, private/in-flight, other-ISA/native scheduling and Intel HVF
requirements retain their original scope. This group does not establish
physical A32 or physical Intel execution.
