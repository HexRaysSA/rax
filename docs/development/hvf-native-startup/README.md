# Native Intel VMM startup controls

The Intel HVF adapter previously inherited the unsupported `deliver_init`
default. The actual coordinator therefore could not deliver an INIT request to
a secondary CPU. The SDK-owner baseline reproduces that error before any native
guest instruction executes. The pending implementation submits INIT to the
permanent CPU owner and uses complete native publication and rollback.

The architectural reset set follows Intel SDM086 Vol.3A Table11-1 and note2 in
the [retained manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
CR0 retains CD/NW and sets ET. General/control/debug state, segment caches,
descriptor tables, EFER, pending vectoring and interrupt shadows are reset.
FP/vector state, XCR0, timestamp ownership, syscall MSRs and the current debugger
controls are preserved. MPX state components are cleared separately from the
other XSAVE components. The native TR/LDTR representations use valid VMX task
and LDT types; their exact SDK and guest behavior still require native execution.

Four focused SDK-owner groups pass: owner-thread dispatch, the reset/preservation
matrix across 1/2/4 CPUs and three cache configurations, removal of a pending
input before a fresh guest entry, and failure injection with complete rollback
or VM fencing. The complete 69-test owner binary remains running. The frozen
Apple Silicon library binary passed 12,440 tests, ignored 36, and failed none,
with no test filter. It predates the three Intel-only INIT source changes and
does not execute that implementation. The
[qualification](qualification.json) records these source boundaries and the
initial harness failures.

The [actual native consumer](../../../tools/hvf/intel_mmio_native_guest.rs) now
registers 149 cases. Its first 146 retain the previously qualified programs.
Cases 146-148 create a complete `Vmm` with the HVF backend and 1, 2 or 4 CPUs.
They reuse the guest bytes from the Linux KVM VMM startup control: a long-mode
BSP copies a real-mode AP trampoline, sends INIT/SIPI, waits for every AP's RAM
marker, then sends two fixed IPIs. Each secondary CPU must enter protected mode,
handle both interrupts, increment its own RAM counter, issue EOI and return to
HLT. The BSP requests ACPI shutdown only after checking the counters. Host checks
also require distinct executing CPUID identities and matching topology leaves.

The consumer compiles, links, signs and passes strict signature validation on
Apple Silicon. Its temporary executable directory was removed. Zero native
Intel startup cases have executed in that local check. The native workflow must
execute all 149 cases before these new controls qualify the backend.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | INIT preserves the native state outside its reset set | Correct secondary reset | 1/2/4 CPU matrix, full FP bytes, clock offset, syscall MSRs, debug ownership, rollback failures | Confirmed in focused SDK-owner controls |
| A2 | The SDK admits real-mode startup and protected-mode interrupt continuation | Native SMP execution | Actual 1/2/4-CPU VMM guest programs, exact RAM markers, CPUID IDs and two EOIs per AP | Native verification pending |

High-impact remaining gates: the complete SDK-owner binary and actual Intel
startup execution. These controls do not establish serialized multi-CPU
checkpoint continuation, complete KVM private state or every advertised native
feature. Medium impact: the hosted Intel runner is itself a hypervisor guest.
INIT work and storage are linear in the bounded captured register and XSAVE
images. The startup observer retains 64 MiB of guest RAM and a CPU-count-sized
set of markers for each of its three sequential VMs.
