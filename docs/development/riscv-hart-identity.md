# Configured RISC-V hardware-thread identity

RISC-V backend construction previously retained the requested vCPU ID in the
adapter while constructing every core with `mhartid=0`. Guest machine-mode CSR
reads therefore reported zero from every represented hart.

Machine, embedded and user adapters now supply their existing u32 ID to the core.
The additive `RiscVCpu::new_with_hart_id` constructor normalizes its supplied value
to MXLEN. Existing direct `new` construction retains hart zero. The existing warm
reset preserves the identity field, and existing readonly CSR import behavior
preserves it across register restoration. The public `RiscVConfig` and checkpoint
structures are unchanged. u32 backend IDs fit both supported register widths;
standalone callers own uniqueness after MXLEN normalization and inclusion of hart
zero in their execution environment.

The archived RISC-V privileged specification, section 3.1.5, defines `mhartid` as
an MXLEN-bit readonly CSR. Hart IDs are unique within an execution environment,
and at least one hart has ID zero. The VMM's existing sequential ID assignment
supplies that domain. This change does not add a multi-vCPU scheduler.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| H1 | The existing backend ID is the represented hart identity. | Existing u32 ID assignment and privileged-specification `mhartid` contract. Actual RV32/RV64 guest CSRR instructions must return the requested ID. |
| H2 | Register width determines the core identity representation. | MXLEN-bit CSR definition; full-u64 core cases and RV32 normalization are explicit. Distinct u32 backend IDs remain distinct in both widths. |
| H3 | Identity persists through reset and CSR import. | Existing reset does not replace `mhartid`; host CSR import ignores readonly fields. Configured nonzero reset/import tests can falsify preservation. |
| H4 | Guest CSR write/privilege rules remain intact. | CSR implementation and import source are unchanged. Real machine-mode readonly writes check cause 2, fault PC, instruction bits and zero retirement; U-mode reads still raise illegal instruction. |
| H5 | Identity observations do not establish RAX SMP execution. | Separate RAX objects and actual QEMU machine-mode SMP references. The RAX execution loop, AP/hart startup and interrupt routing remain separate work. |

Ten regressions cover default-zero compatibility, full-width identities, both
adapter configurations, user-mode identity/protection, reset, readonly import,
architectural traps and groups of 1/2/4 separate objects. An identical existing-API
consumer runs against actual predecessor/current libraries. Its 24 complete
observations contain 1,152 bytes: register width, device mode, requested ID, guest
CSR value, PC and retired count.

Independent QEMU system-mode RV32 and RV64 programs run with 1/2/4 harts. Each hart
reads `mhartid`, emits exactly one UART byte and joins an atomic completion barrier;
the last hart terminates the machine. All 14 output bytes and their original order
are retained. The verifier checks the exact ID multiset without claiming a fixed
inter-hart order. One-bit corruption of every RAX result word is rejected.

An initial readonly test incorrectly expected the host CSR helper to report an
error; that helper intentionally ignores readonly writes. A subsequent assertion
assumed a fault return rather than the existing M-mode trap exit. The retained
failures were corrected by executing the guest instruction and checking its
architectural cause/PC/value and unchanged identity. CSR and trap production code
were not changed to satisfy these assertions.

Identity installation costs O(1) time and space. Oracle output storage is linear
in the 24 observation rows and six reference runs.

High impact: RAX all-hart scheduling, startup protocols, timer/external interrupt
routing and Linux SMP boot remain open. Medium impact: direct core callers control
identity allocation within the MXLEN domain; no global allocator is added. Low
impact: existing M-mode trap exit representation remains unchanged. No physical
RISC-V execution or complete platform/checkpoint/replay claim follows.
