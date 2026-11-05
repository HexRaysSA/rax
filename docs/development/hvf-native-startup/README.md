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
and LDT types, following the retained
[Linux VMX implementation](../kvm-native-private-state/references/linux-vmx-v6.8.c).
The native startup controls below exercise their real-mode and protected-mode
continuation through the SDK.

Four focused SDK-owner groups pass: owner-thread dispatch, the reset/preservation
matrix across 1/2/4 CPUs and three cache configurations, removal of a pending
input before a fresh guest entry, and failure injection with complete rollback
or VM fencing. The complete owner binary passes all 69 tests, with no failures,
ignored or filtered cases. Clippy and formatting also pass; engine and test
sources stayed unchanged throughout qualification. The frozen
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
Intel startup cases execute in that local check.

[Run 42014912978](https://github.com/HexRaysSA/rax/actions/runs/42014912978)
then passes all 149 ordered native cases. The
[result](native-pass-42014912978.json),
[observations](native-pass-42014912978.jsonl), and
[guest output](native-pass-42014912978.stdout) retain the native execution and
per-CPU markers. The [archive verification](native-pass-42014912978-archive.json)
checks the execution ZIP checksum and all 18 downloaded files. All 4472 recorded
engine inputs match the integrated implementation.

| CPUs | Executing CPUID identities | Secondary IRQ counters | BSP completion marker |
|---|---|---|---|
| 1 | 0 | No secondary CPU | `0x600d600d` |
| 2 | 0, 1 | 2 | `0x600d600d` |
| 4 | 0, 1, 2, 3 | 2, 2, 2 | `0x600d600d` |

The original 146 controls also pass again on this engine, covering RAM/MMIO,
PAT, reserved MSRs, deadline restore, timer interrupt delivery and TSC-domain
alignment. Native INIT preservation of every FP/private register is not inferred
from these startup programs; the preservation matrix remains SDK-model evidence.
All local validation processes have terminated, and the owned build cache and
temporary consumer directories were removed.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | INIT preserves the native state outside its reset set | Correct secondary reset | 1/2/4 CPU matrix, full FP bytes, clock offset, syscall MSRs, debug ownership, rollback failures | Confirmed in focused SDK-owner controls |
| A2 | The SDK admits real-mode startup and protected-mode interrupt continuation | Native SMP execution | Actual 1/2/4-CPU VMM guest programs, exact RAM markers, CPUID IDs and two EOIs per AP | Confirmed in native cases 146-148 of run 42014912978 |

High-impact remaining gates: serialized multi-CPU checkpoint continuation,
complete KVM private state and the remaining advertised native
profiles. The startup program receives the CPU count through RAM; it does not
qualify complete firmware or OS topology discovery. Medium impact: the hosted
Intel runner is itself a hypervisor guest.
INIT work and storage are linear in the bounded captured register and XSAVE
images. The startup observer retains 64 MiB of guest RAM and a CPU-count-sized
set of markers for each of its three sequential VMs.
