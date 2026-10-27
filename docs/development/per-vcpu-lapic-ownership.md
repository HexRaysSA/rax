# Per-vCPU local APIC ownership

A system-emulation x86 vCPU must access the same local APIC object that the
VMM polls for delivery and captures in a checkpoint. Previously the software
MMU handled LAPIC MMIO using an independent inline object. Guest TPR and ICR
writes therefore did not update the VMM's controller, and all independently
created inline objects reported APIC ID zero.

The VMM now creates one controller owner per configured vCPU and attaches that
owner to the x86 software MMU. Controller zero also supplies the existing BSP
MMIO-bus and base-checkpoint view. Guest loads/stores, interrupt polling and
that checkpoint view consequently share object identity. Standalone MMUs retain
their existing inline controller until an owning VMM explicitly attaches one.

Timer expiry moves into the same IRR used by software-generated interrupts.
Delivery requires an enabled local APIC and an interrupt priority class above
the processor-priority class. A rejected CPU injection retains the IRR bit;
an accepted injection moves it to ISR. Controller locks are released before
CPU injection callbacks, because injection can itself access guest memory and
its device mappings. The attached software CPU does not independently poll
its inactive inline timer.

The architecture uses 256 interrupt vectors and eight 32-bit bitmap words.
Controller polling has O(1) work for this fixed vector space. Per-CPU ownership
requires O(n) controller storage for n configured vCPUs. No host worker thread
or concurrent execution policy is implied by allocating these owners.

Primary reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
revision 086, Volume 3A, Chapter 12: local APIC register map, ICR and interrupt
priority. The retained source is
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`.
Architectural xAPIC software uses aligned 32-bit MMIO accesses. The bridge also
preserves the existing software MMU's smaller and paired-register accesses as
compatibility behavior; those are not asserted to be physical xAPIC semantics.

## Assumption register

| ID | Assumption and dependent result | Basis | Stress test and falsification probe | Status |
|---|---|---|---|---|
| L1 | An attached software MMU and the VMM retain the same controller owner. Register/delivery/checkpoint coherence depends on this identity. | Explicit shared ownership passed through the vCPU adapter. | Execute guest TPR stores, read through the VMM bus and checkpoint, then reverse the direction. Any differing value falsifies the claim. | Confirmed in local software checks |
| L2 | Configured vCPU indices identify the selected xAPIC controller IDs. | VMM construction and the eight-bit APIC ID field. | Construct 1, 2 and 4 CPUs and execute guest ID-register loads on each. A duplicate or incorrect ID falsifies the claim. | Confirmed in local software checks |
| L3 | Interrupt acceptance can re-enter the device graph and can reject delivery. Pending-state conservation depends on callback ordering. | The existing vCPU injection contract returns acceptance separately from success. | An injection probe acquires the controller mutex and rejects the first attempt; IRR must survive rejection and move to ISR only after acceptance. A held lock, missing pending bit or early acknowledgment falsifies the claim. | Confirmed in local software checks |
| L4 | The shared controller's TPR/PPR and software-enable fields govern this software delivery path. | Intel APIC priority and enable rules. | Exercise equal-priority masking, a higher in-service class, EOI and software disable/re-enable. Any blocked delivery or missing eligible delivery falsifies the claim. | Confirmed in local software checks |

## Evidence and remaining goal work

Four VM-construction/guest-execution tests fail against the preceding source:
TPR visibility in each direction, guest self-IPI delivery and secondary APIC
identity. Additional delivery tests exercise rejected injection, lock re-entry,
TPR/PPR, EOI and software enable. These tests provide software execution and
controller evidence. They do not provide physical Intel HVF evidence.

The full four-finding objective remains active. High-impact remaining work
includes executing every online CPU through the actual VMM coordinator,
architectural secondary startup and cross-CPU IPI routing, complete per-CPU
controller/private/in-flight checkpoint state, native HVF TPR/interrupt state
synchronization and actual Intel-host execution. Allocating controller owners
does not close C-SMP or C-STATE.

High-impact remaining state work includes the inactive standalone inline-controller
profile and complete modeled timer phase. Those state owners must also be
covered by the final checkpoint inventory. The current base checkpoint view
continues to name the BSP controller. Low-impact organization: legacy local
APIC tests move to a child module with their test paths and assertions intact.

## MMIO transaction boundaries

The controller connection also exposed a bus-level defect. `MmioBus` split a
32-bit TPR store into four byte callbacks. The first callback wrote the intended
low byte; the following three callbacks wrote zero to the same register.
The inverse visibility test therefore still failed after controller sharing:
five controls passed and that direction failed. Its complete input and output
are retained separately from the original four failing tests.

The bus now preserves a callback's access width while the complete access lies
within one mapped device. It splits only at mapping boundaries and unmapped
holes, retaining open-bus reads and ignored unmapped writes. An address-space
wrap is rejected before any device callback or destination-buffer mutation.
Empty transactions have no side effects. The transaction tests cover widths
1, 2, 4, 8, 16 and 64 bytes, out-of-order registration, mapping boundaries,
holes, address wrap and empty/unmapped accesses. Callback addresses, widths,
write payloads and ordering are compared explicitly.

For k contiguous portions and d registered mappings, dispatch takes O(k*d)
work and O(1) additional bus storage. Device-specific processing of the payload
is additional. Preserving one callback does not claim atomic execution across
two devices or implement an unsupported atomic MMIO instruction profile.

| ID | Assumption and dependent result | Basis | Stress test and falsification probe | Status |
|---|---|---|---|---|
| B1 | The MMIO device interface receives complete mapped transactions rather than independent byte operations. Register side effects depend on width and callback count. | The interface accepts byte slices; the actual TPR inverse-direction test fails with fragmentation. | Check exact callback traces for six widths, boundaries and gaps. Unexpected fragmentation, extra side effects or payload changes falsify the claim. | Confirmed in local software checks |

High-impact remaining coherence work also includes direct `MOV CR8`: its
current execution owner accesses `sregs.cr8` separately from the attached TPR.
That state must be reconciled with controller capture and native SDK state
without introducing lock re-entry during coordinated restoration. This
component does not claim that synchronization is complete.
