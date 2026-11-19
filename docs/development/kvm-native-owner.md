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

## Precise native exception events

Managed VM topology setup enables `KVM_CAP_EXCEPTION_PAYLOAD` and
`KVM_CAP_X86_TRIPLE_FAULT_EVENT` where available. CPU bank version 4 requires
both resulting validity flags. It retains pending and injected exceptions
separately and keeps event reads from delivering pending CR2 or DR6 payloads.
The public `get_state` projection reads registers without accessing the event
or multiprocessing banks.

See sections 4.31, 4.32 and 7.17 of the
[Linux v6.8 KVM API](kvm-public-state/references/kvm-api-v6.8.rst).
In the physical Intel KVM control, the same guest #GP(0) was restored after
source destruction in 70 legacy CPU cases and 70 precise CPU cases. The
legacy destination reported an injected event in every case. The precise
destination reported a pending event in every case. Both ran the simple
guest's handler. The RAX owner tests restore pending and injected #GP through
fresh 1-, 2- and 4-CPU graphs and require exactly one handler invocation per
CPU. A stopped #PF control preserves both the pending payload and the previous
CR2 across capture and a public register overlay. The active L2 tests below
cover one intercepted #GP. Complete native event capture and the public VMM
checkpoint producer remain open.

## Pending triple-fault shutdown

KVM represents the request independently of the ordinary exception slot.
Internal CPU bank versions 2 and 3 did not record it. An idle exception
slot does not establish that no shutdown is pending, so restore rejects those
versions before loading any native banks. New capture requires both precise
event capabilities.

An Intel KVM control queues a double fault while a rejected RDMSR still owes
completion. Completing only the RDMSR queues the triple fault. Both sets of
70 source CPU cases shut down on their next entry. With the legacy event
interface, all 70 fresh destinations ran the guest handler and reached HLT.
With precise shutdown capture, all 70 shut down before executing the handler
or the instruction after the RDMSR. The managed-owner regression exercises the
kernel-generated request on fresh 1-, 2- and 4-CPU graphs after source
destruction. A separate active L2 control observes the resulting triple-fault
exit to L1. The full public checkpoint transaction remains open.

## Active nested VMX and SMM restore

Restore installs vCPU events and the multiprocessing state before the nested
state. The event setter changes the CPU's SMM mode and can discard nested
state. The VMX setter checks the target's current SMM mode before accepting
its saved VMXON and guest-mode flags.
[Linux v6.8 VMX restore](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/vmx/nested.c#L6184-L6211)
[Linux v6.8 KVM selftest load order](https://github.com/torvalds/linux/blob/v6.8/tools/testing/selftests/kvm/lib/x86_64/processor.c#L949-L964)

On physical Intel KVM, the Linux v6.8 SMM selftest passed with events before
nested state. Moving only the nested-state setter ahead of events made the
kernel reject the SMM image with `EINVAL`.
[Linux v6.8 SMM selftest](https://github.com/torvalds/linux/blob/v6.8/tools/testing/selftests/kvm/x86_64/smm_test.c#L173-L193)

The managed-owner fixture runs L2 and settles its port output through RAX
before capture. It serializes native banks, compares with uninterrupted
execution, releases the source VM, vCPUs and registered RAM backing, then
restores into newly registered memory. It checks L1's VMCALL exit, #GP vector
and error code, triple-fault exit, and VMCALL after returning from SMM. Each
case uses one, two and four vCPUs. Physical Intel KVM passed all 12 cases
(28 restored vCPUs). Events-first restore cleared the original `EINVAL`
while preserving the other three continuation paths.

The fixture supplies the SMM address space and directly starts each vCPU.
Public SMRAM ownership, AMD SVM, platform startup and a complete public
checkpoint remain outside this qualification. The retained public-producer
backlog test failed at the same declaration check before and after the fix.
The other 100 KVM library tests passed. The full native `kvm_minimal`,
`kvm_smp` and `kvm_host_slices` targets passed 15, 31 and 15 tests.
Linux workspace all-target Clippy passed.

Restore admission also checks VMX against the incoming SMM event bank before
any CPU or shared-controller setters. It rejects a missing SMM-validity bit,
an active L2 in SMM, and a suspended VMX state outside SMM. On physical Intel
KVM, corrupting the last CPU of each 1-, 2-, and 4-vCPU graph rejected both
types of mode conflict and the missing-validity cases. Every target CPU kept
its initial RIP. The previous restore returned `EINVAL` after changing the
target RIP from `0x1000` to `0x1104` in the one-vCPU control. All 12 valid
source-destruction continuations and all 100 implemented KVM library tests
passed with the new admission check.
[Linux v6.8 vCPU event format and setter](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/x86.c#L5046-L5155)

The same restore admission rejects invalid common nested-state flags and
checks the saved VMX pages before any setter runs. Active and suspended L2
states require a loaded VMCS12 payload. Ordinary VMXON and VMCS12 pointers
must be distinct and 4 KiB aligned. Header-only VMXON, where no VMCS12 is
loaded, remains a separate valid state. CPU capabilities, full VMCS contents
and shadow VMCS compatibility still depend on the admitted native profile.
The admission checks take constant time and auxiliary space per CPU. On
physical Intel KVM, 36 malformed records corrupted only the last vCPU in
each 1-, 2-, or 4-vCPU graph. Every target kept its initial RIP on rejection.
All 12 valid source-destruction continuations and all 100 implemented KVM
library tests passed.
[Linux v6.8 common nested-state setter](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/x86.c#L5786-L5814)
[Linux v6.8 VMX nested-state setter](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/vmx/nested.c#L6147-L6266)

### Suspended VMXON before VMCS load

On the tested Intel Linux `6.8.0-138-generic` host, `KVM_SET_NESTED_STATE`
accepted a 128-byte suspended VMXON record and readback showed its SMM VMXON
flag cleared. The v6.8 setter returns early for VMXON without a loaded VMCS,
before installing the SMM flags. An uninterrupted control and a raw restored
control both executed `RSM` followed by `VMXOFF`, so that suffix alone cannot
verify the saved state.
[Linux v6.8 nested setter](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/vmx/nested.c#L6213-L6257)
[Linux v6.8 SMI and RSM callbacks](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/vmx/vmx.c#L8132-L8171)

RAX preflights this record on a disposable VM with the saved CPU's configured
CPUID and IRQ controller configuration. It compares the header returned by
KVM with the captured header. If KVM drops the suspended flag, a fresh,
exclusively managed destination can reconstruct it through an SMI. A
destination which has already run, begun a restore, or exposed its native
descriptors rejects this fallback before changing any destination banks.

The fallback reserves one 4 KiB page in the SMM address space for the CPU
save area. It sets up VMXON outside SMM and uses a private thread with a
pending signal to let KVM process the SMI and stop before guest instruction
execution. It checks the SMM entry location and the full 128-byte nested
header. The page is removed before installing the captured CPU and IRQ
banks. The normal first-entry clock gate applies the saved clock after
restore. A failure after scratch registration fences the destination, and
the VM holds the backing until KVM confirms removal or the VM closes. Each
restore uses one scratch page and processes affected CPUs sequentially.
[Linux KVM API, KVM_SET_SIGNAL_MASK](https://docs.kernel.org/6.8/virt/kvm/api.html#kvm-set-signal-mask)

An independent raw-KVM matrix on physical Intel exercised 24 cases with 1,
2 or 4 vCPUs, userspace or kernel IRQ controller ownership, and queued or
unqueued SMI states. The source was destroyed before restoring into a new
VM. The checks covered the exact nested header, the entire 2 MiB RAM image,
the peer register canaries and the final `RSM`/`VMXOFF` continuation. The
queued-SMI cases relocated SMBASE and verified exactly one additional handler
entry. The complete public KVM checkpoint producer and in-place restore on
hosts with the lossy setter remain open.

The managed RAX regression reproduced the parent rejection and passed all
12 fresh-destination cases with the fallback. It checked full RAM, saved SMM
events, restored SMBASE, source-free continuation, and removal of the scratch
registration. The same run passed the 12 active or SMM-suspended L2 controls,
101 implemented KVM library tests and 15 `kvm_minimal` integration tests.

| Assumption | Stress test and falsification probe |
| --- | --- |
| The pending signal services the queued SMI without executing guest code. | Require current SMM state, an empty SMI queue and the original handler entry RIP and CS base immediately after EINTR. |
| The temporary slot does not persist in the resumed VM. | Register an overlapping GPA in an adjacent slot after restoration. A stale scratch registration makes KVM reject the overlap. |
| The suspended header and saved event bank are independently significant. | Compare the full header and restore a second pending SMI. An extra or missing handler entry or a changed header fails the continuation. |

## PC RAM layout

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
