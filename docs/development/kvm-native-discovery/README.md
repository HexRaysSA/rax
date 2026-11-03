# Native PC CPU discovery

An actual Linux6.8.0-138 guest, requested with1/2/4 native CPUs, reports no ACPI
MADT or MP tables and selects `nr_cpu_ids=1` in every run. This is independent
of the controlled native startup/IPI guest, which already passes all three
configured CPU counts. `linux-baseline.json` records the console observations;
exit0 follows the owned console quit command and does not mean OS startup passed.

Cold direct-kernel KVM construction now publishes Intel MP1.4 discovery in the
existing E820-reserved BIOS window. The pointer at0x000f0000 refers to an explicit
configuration table at0x000f0010. CPU records use the configured IDs0..N-1,
CPU0's BSP flag, and the same native CPUID signature/features supplied to the
CPUs. The I/O APIC ID/base come from the native IRQchip image. Kernel LAPIC and
I/O APIC versions are compared against actual guest MMIO reads.

The existing KVM default routing connects GSI numbers to the same-numbered
I/O APIC inputs. IRQ0 is input0 here; no QEMU-style input2 mapping or unconnected
I/O APIC ExtINT input is advertised. IRQ2 is the PIC cascade. The local records
describe BSP LINT0 ExtINT and all-CPU LINT1 NMI in virtual wire mode, without an
IMCR. Optional PCI interrupts retain their existing bus-specific discovery.

This path does not publish the unused ACPI builder's unwired PM/HPET devices.
ISO BIOS boot and captured resume RAM retain their existing construction paths.
The firmware bytes are ordinary captured RAM; this change does not introduce a
new checkpoint wire format or implement the complete native checkpoint producer.

The table has44 +20N +152 bytes for N CPUs; the floating pointer adds16 bytes.
For the representable maximum N=255, the total is5312 bytes and ends at0x000f14c0,
inside the reserved64KiB BIOS window. Construction/checksums use O(N) time and
O(N) storage. Publication occurs before any native CPU exists or can execute.

The original complete production library passes the three prior native startup
cases and fails all three new actual-VMM discovery cases:3 passed,3 failed,
0 ignored,0 filtered. The pure production writer passes three component tests,
including every CPU count1..255 and unchanged memory on rejected publication.
The complete changed production library also passes all six native discovery/startup
cases and all ten native I/O cases, without failures, ignores or filters. All17
canonical workspace, feature, lint, documentation, selected-unit and owning gates
pass; the documentation selection retains five documented ignored examples.
Linux discovers exactly the requested1/2/4 CPU IDs with the new firmware. These
MPS-only runs stop at a separately reproduced native PIT/port61 defect; complete
OS activation is qualified with the subsequent speaker-port repair.

`qualification.json` records the current assumptions and required checks.
Primary rules are pinned in the MP1.4 provenance directory and the adjacent
unmodified Linux6.8 references. Native OS all-CPU startup, full virtual topology,
complete native CPU/shared/in-flight restoration, common clocks/replay, remaining
A32/HVF profiles and physical Intel HVF execution remain full requirements.
