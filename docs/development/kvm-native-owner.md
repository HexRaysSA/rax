# Managed native CPU ownership and checkpoint boundaries

Managed KVM CPU descriptors, run mappings and registered RAM now share one VM
owner. The owner retains weak CPU membership; a checkpoint boundary upgrades
and pins the complete configured set. Native entry and state access take a read
lease, while checkpoint publication takes the VM writer lease. A destroyed CPU,
an unmanaged SDK CPU, or raw SDK VM access prevents a managed checkpoint.

The lock order is reader admission, VM exclusion, profile/membership, then
native CPU core. Writer intent blocks new readers with a condition variable;
the exclusive boundary drops before reader admission reopens. Device
service runs outside both the CPU guard and the entry lease. Raw SDK descriptor
access is unsafe and retains the guards for its borrow; its contract forbids
escaping native run-buffer pointers or bypassing pending-completion invariants.
Poisoned native ownership disables subsequent managed entry and state changes.

Checkpoint capture settles represented PIO/MMIO through the originating CPU's
actual device buses before taking writer/device/RAM locks. Native completion
uses the owned worker's entry-only signal mask and immediate-exit control. A
follow-up native exit is retained. Device failure latches a state error; a
power-off reply publishes VM shutdown before waiting for other native entries
to yield. Public native entry uses bounded 10 ms slices without exposing those
internal scheduling exits as guest events. An additional native counter-loop
regression reproduced a checkpoint writer blocked across the earlier retry
loop, and a second native control reproduced a writer blocked by a requested
5 s host slice. The wrapper now releases exclusion between slices, and native
entry uses a maximum 10 ms host quantum after validating the original request.
Native controls showed that per-slice lease release alone still permits a
writer timeout; the explicit admission gate avoids dependence on RwLock
fairness. The corrected native regression passed eight scenarios, and the complete
11-test host-slice target passed with no failures, ignored or filtered tests.
Later frozen-root qualification is recorded below. Diagnostic PC observation remains
available after an I/O failure, while state import and further entry reject.

Checkpoint construction now initializes the managed PC platform before native
CPU creation. It retains the source-free restore contract: the original kernel
and media files need not exist, and captured firmware bytes are not replaced
by a fresh boot publication. The separate uninitialized `new_resume` staging
constructor retains its existing contract. Native controls exercise 1, 2 and
4 CPU topologies and the restored UART path; CPU creation alone is not evidence
that application processors execute. The complete `kvm_smp` target separately
exercises native startup and multi-CPU execution.

Internal, versioned native banks represent configured/runtime CPUID, register,
system/debug/event/MP state, XCRs, XSAVE, MSRs, admitted nested state, LAPIC
banks, common TSC/clock state, PIC/IOAPIC banks and the owned 24-GSI source
levels. Admission checks every CPU and its actual target owner before native
setters. The SDK `serde` feature and pinned `zerocopy` derives provide checked
representations rather than copying arbitrary native padding as a wire format.
These internal banks do not activate a complete public private-state producer.

The [PC RAM layout](kvm-native-ram/README.md) supplies configured low/high RAM,
boot metadata, native registrations and collateral MMIO admission. Retained
backing padding is not advertised guest RAM, and the 3--4 GiB device window
remains unmapped in KVM. PCI route-cache and older checkpoint compatibility are
documented with that layout.

## Qualification

The combined Linux qualification uses an immutable source view, a source-bound
compiler cfg, hashed reference inputs and a retained test executable. Earlier
overlapping Cargo views reused an incorrect cached test binary; that result and
the overlapping broad qualifications were superseded. A zero-test result is
not accepted. The final qualification records distinguish each actual Cargo
target from nested child test output and from tests that self-skip.

The source identity and complete gate results will be recorded alongside the
native RAM and MOVSXD qualification before publication. The current complete
library run remains pending. The updated writer-admission candidate passes
all-target workspace Clippy/build checks and the complete 27-test native SMP
and 11-test host-slice targets, with no failures, ignored or filtered tests in
either target. Its selected root-library namespaces pass 14 owner, eight access,
16 state-bank, four CPUID, four APIC, seven completion, six VMM service, three
port-service, three MMIO-frontier and 16 debugger-memory tests. Those namespace
runs filter other root-library tests and do not replace the unfiltered gate.

All 244 C API Rust tests, 19 C/C++ consumers and seven ABI objects also pass
for the updated frozen writer-admission candidate. The consumer run links a
retained, hashed dynamic library and removes its owned build artifacts.
The [host fixture controls](native-host-test-assumptions/README.md)
explain the socket/netlink test corrections without changing host sysctls.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| NO1 | Managed descriptors share one VM owner and exclusion | `MemoryOwner` registry and retained boundary cores | Native FD/RAM lifetime | Drop wrappers; use foreign or incomplete membership | A freed FD or admitted mutation under the boundary | Updated 14 owner, eight access and 16 state-bank checks passed; complete library pending |
| NO2 | Device service can re-enter native CPU/IRQ APIs after native locks drop | Callback placement in `checkpoint_io.rs` | Completion and power-off ordering | Actual PIO/MMIO, short replies, failures and executing peers | Deadlock, duplicate effects or peer entry after power-off | Updated seven completion, six VMM service and three port-service checks and complete 11-test host-slice target passed; complete library pending |
| NO3 | Restore constructs the native platform before CPUs | Managed PC initialization and captured construction controls | Source-free restore | Remove source kernel; compare CPUID, UART and firmware for 1/2/4 CPUs | Changed native profile, failed UART or rewritten firmware | Updated complete 15-test minimal target passed, including the 1/2/4-CPU source-free construction control; complete library pending |
| NQ1 | Per-slice read-lease release alone admits a pending writer | Initial correction and native control | Initial quiescence design | Native counter loop with a stopped checkpoint request | Writer timeout despite finite slices | Falsified; retained-CPU repetitions also gave two passes and three failures |
| NQ2 | Explicit writer intent blocks readers until exclusive release | Admission mutex/condition variable and boundary drop order | Updated native quiescence | Four public-run and four requested 5 s native loops; frozen RAM under the boundary | Timeout, changing RAM under the boundary or a spurious architectural exit | All eight scenarios and the complete 11-test owning target passed; broader checks pending |
| NO4 | Qualification identifies the compiled source | Source tags, compiler dependency records and retained executable hashes | Reported test evidence | Reject foreign cached artifacts and zero-test results | Missing fresh compilation, changed input hashes or zero actual cases | Fresh product/owning builds confirmed; test-only fixture repair is separately hashed; complete library checks pending |

## Remaining full checkpoint work

High impact: raw LAPIC banks do not serialize all timer phase and pending-source
state. The [native timer controls](kvm-native-private-state/lapic-timers/README.md)
retain actual counterexamples. The experimental expired one-shot normalization
uses an intermediate encoding without an established production contract.
Kernel PIT/LAPIC timer conservation, all admitted profiles, terminal/deferred
native state, complete rollback and coordinated first entry remain required.
Native platform metadata for nondefault/bare construction also remains open.

The subsequent [halt, IRQ readiness and CR8 correction](kvm-native-owner/halt.md)
passes the complete 15-case host-slice and 31-case SMP targets, plus selected
17-case owner, 16-case state-bank and seven-case native completion namespaces.
Its source-free internal bank controls retain halt and CR8 across 1/2/4 CPUs.
The then-pending workspace and unfiltered library gates subsequently passed
within the frozen-source boundaries recorded below. Those internal
controls do not activate the complete public checkpoint producer described here.

The [common first-entry clock gate](kvm-native-owner/first-entry.md) now stages
the saved native epoch until managed entry. Its four new native controls pass
in the complete 21-case selected owner namespace, including source-free 1/2/4-CPU
guest RDTSC continuations. Broader qualification, the software device-clock
binding, timer phase and complete producer/rollback composition remain open.

The later Linux frozen root passes 13330 tests with zero failures and 82 ignored;
the Apple Silicon frozen root passes 12408 with zero failures and 36 ignored.
The [SDK qualification](hvf-intel-sdk/sdk-model-qualification.json) retains their
input hashes, executable results and per-file source comparison. These are
frozen-source results for unchanged components, not a new whole-checkout run.
They supersede the earlier pending broad-gate notes; the complete public native
checkpoint producer and the kernel timer-phase boundary remain open.

Physical Intel macOS HVF execution remains unverified. The owned-bank, RAM and
construction changes do not close C-STATE, C-SMP, C-HVF or A32-FP. They provide
the native ownership and admission boundary needed by the remaining producer.

Primary sources retained in the repository include Linux v6.8
[`x86.c`](kvm-native-private-state/references/linux-x86-v6.8.c),
[`lapic.c`](kvm-native-private-state/references/linux-lapic-v6.8.c),
[`irqchip.c`](kvm-native-private-state/references/linux-irqchip-v6.8.c),
[`i8259.c`](kvm-native-private-state/references/linux-i8259-v6.8.c),
[`ioapic.c`](kvm-native-private-state/references/linux-ioapic-v6.8.c), and
[`irq_comm.c`](kvm-native-private-state/references/linux-irq-comm-v6.8.c).
Their adjacent provenance records preserve URLs, versions and checksums.

The archived [Rust1.98 RwLock contract](kvm-native-owner/references/rust-rwlock-1.98.html)
explains why checkpoint admission cannot rely on an implicit writer preference.
