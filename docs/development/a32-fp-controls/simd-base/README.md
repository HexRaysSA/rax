# A32/T32 Advanced SIMD integer and structure-memory admission

`MVFR1.SIMDInt` and `SIMDLS` now reject absent/reserved capability fields
before access traps or architectural effects. Structure loads/stores use
`SIMDLS`; register/data operations use `SIMDInt`, also a prerequisite of
`SIMDSP`. Scalar VFP operations retain their separate precision checks.

The [Arm definition](mvfr1-extract.txt) is from DDI0487B.a G6.2.108.
[Provenance](provenance.json) and [exact LLVM encodings](assembly.json)
identify the retained sources and instruction bytes.

Six regression tests failed before the change. All 46 FP-control, 497 VFP,
and five pair-transfer tests pass after it. Rejection checks cover ARM and
Thumb, missing and every reserved field, denied access, registers, status,
writeback and RAM. Eight new tests are registered in the existing target.
Workspace library check and owning-target Clippy pass.

[Independent QEMU controls](qemu-results.json) cover eleven operations in ARM
and Thumb on enabled/disabled Cortex-A15 profiles: 44 observations. The
[retained generator](qemu-controls.py) records the tested local paths. QEMU
requires Neon and D32 to be enabled or disabled together; these observations
do not isolate individual MVFR1 fields. Per-field/reserved controls are
manual-derived synthetic tests, not claims about physical processor profiles.
The rejected first oracle configuration and all raw outputs are preserved.

[Qualification](qualification.json) records the commands and assumptions.
`SIMDSP`, remaining FP controls, rounding/denormal behavior and coherent
profile identity remain open. This group does not close the overall audit.
