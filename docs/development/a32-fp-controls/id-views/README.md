# Coherent AArch32 floating-point ID views

The mixed-width processing element now obtains A64 `MVFR0_EL1`–`MVFR2_EL1`,
A32/Thumb `VMRS MVFR0`–`MVFR2`, and saved/SMIR state from one capability view.
Previously A64 reads returned zero, internal reads returned no value, and A32
execution constructed fresh standalone capabilities independently of saved IDs.
Guest `MSR` writes now report Undefined before changing state. Non-secure EL1
reads honor `HCR_EL2.TID3` and report the complete system-register trap ISS.
A64 ID reads remain independent of floating-point data-access permission.

The existing trusted-host implementation-defined register map can describe a
reduced A32 capability profile. The visible IDs use its low 32 bits. Defined
full-half arithmetic fields are limited by the selected A64 FP16 capability:
`MVFR1.FPHP=3` becomes `2`, and `SIMDHP=2` becomes `1`, when the corresponding
A64 capability is absent. Absent and reserved field values are preserved. The
same effective IDs drive mixed-width instruction admission and FPSCR masking.
There are no new serialized fields or file versions. Existing state import
restores the map; reset selects the configured default profile.

`MVFRn_EL1` remains unsupported by the SMIR instruction lifter, which rejects it
for interpreter fallback. Internal SMIR register-state reads use the shared
view; internal writes return false. This does not add native MVFR execution.

Validation and exact commands are recorded in `qualification.json`,
`assembly.json`, and `qemu-results.json`. The four initial regressions failed on
parent `3361d83566f642c6329d13038124360143ae50ea`. LLVM independently supplies
the A64/ARM/Thumb encodings. The QEMU controls run two whole CPU profiles,
ARM/Thumb alias reads, and TID3 enabled/disabled A64 EL1 reads with an actual
EL2 handler. Cortex-A53 reports `10110222 12111111 00000043`; `max` reports
`10110222 13211111 00000043`. The trapped ESR values are `62300007`,
`62320027`, and `62340047`.

Run the independent controls from this directory:

```sh
python3 -B qemu-controls.py --output qemu-results.json
```

LLVM tools default to `/Users/int/local/bin`; override with `--llvm-bin`.
QEMU is resolved from PATH or supplied with `--qemu`. Temporary objects,
executables and guest binaries are removed automatically, including on failure.
The first control attempt produced matching IDs but timed out at an unsupported
SVC semihosting exit. Its raw output and source remain in the external evidence
directory; the successful probe uses the architectural HLT semihosting encodings.
An expanded RAX test initially cleared the SIMDLS field rather than SIMDSP;
the corrected fixture uses the manual's bit positions, preserving the failed run.

The primary register definitions and trap rules are Arm DDI0487B.a
D7.2.75–D7.2.77. `provenance.json` identifies the retained PDF and exact extract.
The per-field host metadata tests are synthetic controls, not evidence for a
physical CPU implementing every tested combination. In particular D16/VFPv2
combinations are not valid ARMv8-A hardware profiles. QEMU evidence is software
oracle evidence; physical A32 behavior remains unverified.

Architectural EL0 ID denial and Linux CPUID personality emulation are now
separated and locally qualified in
[the EL0 ID policy component](../../a64-el0-id-policy/README.md).
Restricted rounding/default-NaN/subnormal profiles need an explicit selected
subarchitecture; this change does not infer unsupported control-bit semantics.
The remaining profile/security/debug, backend/private/in-flight, coordinated
restore, SMP startup/scheduling/debug/clock/replay and physical Intel HVF
requirements remain open under the original four-finding objective.
