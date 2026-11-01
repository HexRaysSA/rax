# Restricted scalar VFP operating modes

Scalar VFP instruction admission now observes MVFR0.FPRound and
MVFR1.FPDNaN/FPFtZ. A defined restricted capability value selects a synchronous
Undefined Instruction bounce when the instruction requires an unsupported
operating mode. Guest support software can emulate the operation or explicitly
adjust FPSCR and retry. RAX does not install that guest support software.
The bounce follows ordinary FP access checks and precedes data effects or
instruction retirement. A reserved capability value rejects a dependent
instruction at decode admission, before an access trap.

This is an explicit processing-element subarchitecture selected from Arm
DDI0406C.d A2.7 and B1.11.4. It preserves the existing guest FPSCR read/write
view. Capability values alone do not force control bits to read-as-one or
read-as-zero. The default full-control profile keeps its existing behavior.
Defined restricted profiles expose FPSID.Subarchitecture=0x40, the private RAX
support-code interface. Arm DDI0406C.d B4.1.59 requires bit22=1 for a non-Arm
subarchitecture designer; value 3 would incorrectly promise that no support
code is required. Only bits[22:16] change in this guest view. The raw base
identity and all checkpoint bytes retain their existing representation. This
private virtual-PE identifier is not a claim of a physical vendor assignment.

| Capability value 0 | Supported scalar operating modes |
| --- | --- |
| MVFR0.FPRound | Round to nearest; VCVT forms that always round toward zero retain the specified exemption |
| MVFR1.FPDNaN | Default NaN mode for instructions that process NaNs |
| MVFR1.FPFtZ | Flush-to-zero mode for instructions that process subnormals |

Checks follow the instruction's actual control dependencies. Explicit rounding
forms are distinguished from FPSCR.RMode. Scalar half arithmetic uses FZ16;
half precision conversion follows FPConvert, observes AHP, and ignores FZ16.
Alternative-half conversion does not require NaN propagation. Comparisons do
not require rounding or default-NaN controls. Bit/storage transfers, selection,
absolute/negate, and independent Advanced SIMD operations retain their existing
admission. No arithmetic helper or serialized layout changes.

The bounded decoder and control-field checks use O(1) work and auxiliary
storage. A full-control or Advanced SIMD fast path avoids the extra decode.
AArch32 FP remains outside native SMIR admission; the fixture also verifies the
scalar and FPSID-query interpreter frontiers.

## Evidence and reproduction

`qualification.json` records the observed baseline failure, complete owning
suite results, exact commands/environment, assumptions, source hashes, and
remaining scope. `cases.json` contains reviewed primary-derived instruction
control dependencies and LLVM-derived ARM/Thumb words. The encoding tool checks
those words; it does not derive or independently validate semantic metadata:

```sh
python3 -B tools/execution/a32_restricted_fp_cases.py --llvm-mc /path/to/llvm-mc
```

Run this from the repository root. To regenerate only the assembly/encoding
columns from the reviewed inputs, add `--write`. The tool rejects stale words,
invalid dependency values, and missing cases. Its isolated regeneration and
negative controls are recorded in the qualification evidence.

The scalar matrix covers 135 instructions, ARM and Thumb, eight capability
combinations, and 64 FPSCR combinations: 135 × 2 × 8 × 64 = 138,240 executions.
Denied operations must leave the complete serialized CPU and observed memory
unchanged. Separate cases cover all 14 reserved values for each capability,
access-trap priority, failed ARM/Thumb predicates, independent operations, and
128 guest FPSCR write/read combinations.
Another 3,072 reads check stable FPSID identity across capability/control/base-value
combinations. A 32-case mixed-width test checks the identity, successful full-profile
arithmetic, unsupported-mode faults, and competing EL2 access traps together.

Actual software-backend tests enter the guest Undefined vector, preserve the
fault frontier and retirement clock, execute VMSR/RFE support code, and retry.
The test handler deliberately selects standard controls; it does not emulate the
original unsupported numerical mode. These tests round-trip complete backend
contexts before and after entry. Two- and
four-CPU S3C checkpoint files additionally compare the coordinator trace,
retirement counts, and final public/private contexts against uninterrupted
execution. The CPUs are explicitly prepared online; this is not secondary
firmware-startup evidence. The handler at virtual address 0x4 is backed by RAM
through a retained short-descriptor MMU mapping. An initial fixture mistakenly
placed it in the board's low physical open-bus region; that failed run is
retained and the production board behavior is unchanged. Final review also corrected
both section aliases to Normal inner/outer Non-cacheable memory with TEX remapping
disabled. Arm DDI0406C.d A3.5 requires Normal memory for instruction fetch and PC
loads; Table B3-10 supplies the selected TEX/C/B encoding. The earlier software
pass used Strongly-ordered attributes and does not qualify that architectural
fixture requirement.

## Primary sources and limits

The unmodified Arm Architecture Reference Manual, ARMv7-A/R edition, DDI0406C.d
(ID040418) is retained at
`docs/specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf`, with URL,
checksum, retrieval, and size justification beside it. A2.7 defines the
hardware/support-code split; B1.11.4–5 define bounce handling and subarchitecture
support; B4.1.59 defines FPSID subarchitecture identification;
MVFR0/MVFR1 define the capability fields. The retained Armv8-A DDI0487B.a
G6.2.107–108 and `docs/architecture/arm/asl/{arm_defs,arm_instrs}.asl` supply
register and instruction/operation details. LLVM establishes encodings only.

These are synthetic profile combinations, not a claim that a named physical
Arm processor implements every combination. Physical restricted AArch32
execution is unverified. Existing AArch64 native arithmetic checks exercise
helpers under their recorded controls; they do not validate this A32
support-code subarchitecture. Optional short-vector and exception-trapping
profiles, broader security/debug/virtualization admission, complete backend and
in-flight checkpoints, native scheduling/replay and physical Intel HVF remain
open under A32-FP, C-STATE, C-SMP and C-HVF. This component does not close those
findings.
