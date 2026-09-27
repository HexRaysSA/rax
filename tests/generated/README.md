# Generated test material

This directory contains checked-in generator output and include-only Rust data.
No file here is an independent Cargo integration-test target.

The ARM ASL corpus under `arm/{a32,a64,t16,t32,sysreg}` retains its original
module names because generated source refers to those names. Only `arm/a64`
is reachable from the current `arm` Cargo target; moving the corpus does not
activate the dormant AArch32, Thumb, or system-register suites.

`arm/oracle_cases/` contains tables included by differential runners:

- `aarch32_sweep.rs`: A32, T16, and T32 instruction encodings.
- `neon_sweep.rs`: Advanced SIMD, VFP, and FP16 encodings.
- `sve2_sweep.rs`: SVE2 and SVE2.1 encodings.

`cortex_m/thumb_oracle.json` holds the Cortex-M4 differential corpus that
`tools/cortex-m-diff/qemu_oracle.py` generates from QEMU; the library unit
tests of `src/backend/emulator/cortex_m_oracle_tests.rs` include it.

`x86_64/inventories/` contains include-only instruction inventories used by
coverage and differential runners. It includes the AVX-512 case table, the
extension-specific unimplemented-mnemonic sets, and the source-diagnostic
inventory. These files are data inputs, not test targets.

`manifest.toml` records the provenance that can be established from tracked
files. A field set to `"unknown"` means the repository does not currently
contain enough information to reproduce it exactly.

The historical structure generator is retained as
`tools/testgen/arm_structure.py`. It is not
a complete regeneration entry point because its required `structure.json`
input is absent.
