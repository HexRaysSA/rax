# RISC-V backend contexts

The RISC-V interpreter emits producer kind 3 in backend-context bundle section
14. Its inner tag is `RAXRV001`. This record preserves represented hart state
that the public register projection cannot express, including LR/SC reservation,
raw 64-bit counters on RV32, ISA configuration, halt state, and ordered events.

## State and bindings

The core record contains the integer and FP register files, PC, FP status,
privilege, reservation address, machine/supervisor trap and interrupt CSRs,
hart identity, jump-vector table CSR, cycle/time/retirement counters, vector
configuration and register bytes, and the complete vendor CSR store. The vendor
table is sorted and unique. Restore assigns raw state rather than reapplying
CSR write masks or retaining stale target vendor entries.

The adapter record contains its identity, device-binding mode, ordered event
queue, HTIF address, halt state, and process-mode pending trap, completed ECALL
count and precise fault record. An exhaustive core/adapter destructuring makes
new state fields require an explicit serialization/binding classification.

RAM and process translation objects are external bindings. The caller must
capture matching RAM and restore the matching process address space. C API
regions retain their permissions and rebuild the translation before publishing
the candidate engine. A record cannot switch a live backend between system,
embedded and process binding modes. The C API can reconstruct the mode recorded
in its engine header before importing the backend record.

Host-native code-cache entries and cache diagnostic counters are derived. They
are cleared on restore. Native execution is synchronous under the mutable hart
borrow, so this record is taken between native entries, never from a host stack
inside a block.

## Event frontier

An instruction may produce several bridge accesses and then a terminal event.
The old one-slot UART sink overwrote earlier vector-store bytes. It also returned
a UART event before handling the instruction result, losing a later store fault.
The queue now preserves bridge order and appends the terminal result. Subsequent
calls drain queued events before executing another instruction. A failed RAM
write to HTIF does not publish shutdown.

The retained predecessor probe observed UART `A`, stored cause 7, followed by
cause 2 from executing another instruction. The tests require the queued cause
7 to survive context restoration with no additional retirement, followed by the
original halted state. Additional tests cover a four-byte vector UART sequence,
LR/SC continuation, RV32 counter high halves, pending IRQs and process events.

## Admission and compatibility

The inner payload is bounded to 1 MiB. Admission checks the tag, exact decoding,
hart identity, binding mode, register geometry/status widths, sorted vendor CSR
table and event descriptors. The public register image must agree with the
backend image. Restore acquires all fallible adapter locks before any live field
assignment. Poisoned locks and malformed records preserve the target context.

The outer section framing is unchanged. Older bundles without producer kind 3
retain their register-projection semantics. The C API writes context format 6
for RISC-V system/process engines, using the same producer-kind/length framing
as AArch32 format 5. Formats 1/2 remain readable; they did not record an LR/SC
reservation. A restored format-6 profile is retained for future engine rebuilds.
The documented C API instruction count still starts at zero after restore; the
raw backend counter and its relation to future execution are preserved.
Format 6 rejects an RV32 private profile under a `Riscv64` engine header before
publishing the candidate. Valid RV64 extension profiles survive map rebuild and
reset. The direct RISC-V backend API independently supports RV32 contexts.
VMM admission also checks the private profile against the saved machine
declaration before any live CPU, device or RAM import. A self-consistent RV32
record cannot change a declared `Riscv64` machine into an RV32 hart.

Capture/admission take O(B + K log K) time and O(B + K) temporary space for B
encoded state bytes and K vendor CSR entries, including canonical CSR ordering.

## Validation boundary

The semantic group is implemented; current validation and commit receipts are
recorded in the audit ledger after the required gates complete. File tests use
actual VMM backend objects with 1/2/4 contexts and explicitly drive their harts.
They validate context transport and continuation; they do not establish secondary
startup or scheduler execution of all configured harts. The actual CLI workload
separately checkpoints between LR and SC at retirement 1000 and resumes its file.

Other architectures/platforms, all-writer quiescence, whole-VM late-failure
transactions, native state and the remaining SMP/HVF requirements remain open.
