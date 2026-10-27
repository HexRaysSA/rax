# Configured AArch64 processing-element affinity

Emulated AArch64 vCPUs now expose their configured ID through a real guest
`MRS MPIDR_EL1`. Previously every core returned CPU zero's affinity. Both
machine and micro constructors use the configured identity; the user-mode
constructor uses the same core builder without changing EL0 access controls.

`AArch64Cpu::new_with_cpu_id` is additive. The existing `new` constructor keeps
its CPU-zero value, `0x80000000`. A linear `u32` ID maps its four bytes to Aff0,
Aff1, Aff2 and Aff3. Aff3 occupies bits 39:32, leaving the reserved/control byte
at 31:24 unchanged except for RES1 bit 31. U and MT remain zero. The native HVF
constructor shares this encoding. VM indices 0..254 retain their previous
native encoding; admission of large native affinities remains host-dependent.

Reset preserves the configured hardware identity. Complete and partial system
state imports retain the destination's read-only MPIDR while transferring the
other represented state. This follows the existing configured RISC-V hart-ID
contract: copying writable state cannot change the destination CPU's identity.
Public configuration/state layouts and checkpoint section formats are unchanged.
Identity allocation and topology consistency remain the embedding environment's
responsibility. This change does not validate all checkpoint topology metadata.

The encoding requires constant time and space. The independent Python model
assembles four input bytes at explicit bit positions; it does not call the Rust
encoder. Sixteen complete guest observations contain 640 bytes; all 80 observed
words undergo corruption checks. An identical existing-API consumer executes
against retained predecessor and proposed libraries. Eleven regressions also
cover 10,000 seeded full-width IDs, reset, complete/partial import, state overlay
and one/two/four separate CPU objects. These objects do not demonstrate a shared
SMP scheduler, interrupt controller, PSCI implementation or Linux SMP boot.

Primary references are the archived Arm BSA 1.0 processor-register table,
Cortex-A53 programming model (MPIDR_EL1 is read-only), and Arm's archived
`ProcessorID()` pseudocode (Aff3::Aff2::Aff1::Aff0). LLVM independently assembles
the guest MRS encoding.

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| The configured ID selects PE identity. | Guest affinity follows the requested ID. | Same-source predecessor/current MRS execution; a nonzero ID returning CPU zero falsifies it. |
| Four affinity bytes represent the full u32 domain. | Encoding preserves every input bit. | Boundary IDs and 10,000 seeded cases; decoding a different ID falsifies it. |
| MPIDR is destination hardware identity. | Reset/import retain affinity. | Import a conflicting MPIDR while checking other state transfers; affinity replacement falsifies it. |
| Existing low native IDs retain their representation. | Existing VM/device-tree indices remain compatible. | Exact encoding equality for all 0..254; changed bytes falsify it. |
| Separate objects are not scheduler evidence. | Claims remain limited to identity. | Any SMP scheduling/startup/IRQ/native high-affinity claim from these fixtures falsifies the boundary. |

Scope expansion: high impact, all-vCPU coordination and shared GIC/PSCI remain
open; medium impact, large native affinities still require host admission proof;
low impact, existing guest system-register access and public wire layouts remain
unchanged. The retained remediation ledger records validation and commit gates.
