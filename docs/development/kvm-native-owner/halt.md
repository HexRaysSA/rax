# Owned native HLT state

The userspace-controller KVM profile must retain its own halted state.
Linux `__kvm_emulate_halt` advances the guest past HLT and returns
`KVM_EXIT_HLT` without changing MP_STATE when the LAPIC is in userspace.
Entering that CPU again without handling the wait executes the next
instruction. The VMM's repeated scheduling makes this an execution defect.

`NativeCore` now retains a userspace halt latch. Repeated public runs and
bounded host slices return HLT without entering the guest. Public register
overlays preserve this state. Invalid host-slice durations still fail before
the halt check. Explicit `wake`, a successfully queued maskable interrupt, or
a successfully queued NMI clears the latch; rejected events preserve it.
Native I/O, sticky failure, power-off and deferred-exit ordering stay ahead of
the halt check. The latch adds constant time and space per CPU.

A stopped immediate-exit KVM_RUN refreshes interrupt readiness for a halted
CPU after checking IF and exported pending/blocking events. This preserves
the kernel's private readiness predicate, including nested execution, instead
of inferring it from IF alone. The current CR8 is copied into the run header
first because KVM imports that input before checking immediate exit. The
previous immediate-exit flag is restored. Unsupported immediate-exit profiles
return an error before this ioctl; unexpected native results become sticky
failures. The probe must not execute guest code or change public registers.

Public state publication, rollback and internal CPU-bank restoration also
synchronize the run-header CR8 input after their native setters succeed.
Otherwise the next ordinary userspace-controller entry would replace a
correctly imported CR8 with the target's old header value. This adds constant
work per state import rather than another ioctl on every guest entry.

The kernel-controller profile continues to use native MP_STATE. Explicit
wake changes HALTED to RUNNABLE, preserving uninitialized/startup states.
It avoids GET_MP_STATE during an owned I/O continuation because that ioctl
can accept pending INIT/SIPI. Failure of the void public wake method is
retained as a sticky CPU error and prevents subsequent guest entry.

The internal CPU bank is version 2 and includes the latch. Its owner captures
and reinstalls it under VM-wide exclusion. Version 1 and a userspace halt
latch attached to a kernel-controller record fail admission before setters.
The incomplete public checkpoint hook rejects a halted userspace CPU rather
than silently omitting its wait state. The complete private/shared/timer/RAM
producer and rollback transaction remain unfinished; this guard does not
establish complete checkpoint support.

## Evidence and qualification boundary

Three independent native controls in `kvm_host_slices` first failed against
the unchanged event-capable production library: 0 passed, 3 failed, no ignored
or filtered tests. The IRQ control observed the post-HLT canary change from
0 to `0xa5` and output `0x5a` without a wake. The other controls failed their
repeated-HLT assertion. The retained baseline records the exact fixture,
library SHA-256, guest bytes and assertion output.

An additional unchanged-library probe confirmed stale readiness after a
parked IF-clear CPU receives a public IF-enable overlay: 0 passed, 1 failed,
2 filtered tests. The first candidate build was explicitly superseded before
its behavioral gate to combine this correction with the halt latch; no test
pass is attributed to that interrupted build. Its receipts and source delta
are retained. The owning target now contains four halt controls, including
IF-overlay admission and a nonzero CR8 preservation check.

A separate unchanged-library native probe loaded CR8 = 3 and executed one
HLT. The following public observation read CR8 = 0: 0 passed, 1 failed,
2 filtered tests. This establishes the ordinary-entry state-import defect
independently of the stopped-readiness refresh. The final controls retain a
nonzero CR8 across public import and across source-free internal bank restore,
then execute native code before checking it again.

The final four-case fixture was also run unfiltered against the unchanged
event-capable library: 0 passed, 4 failed, no ignored or filtered tests. The
preceding halt/readiness candidate passed all 15 host-slice and all 31 SMP
tests, with no failures, ignored or filtered tests in either complete target.
These results do not qualify the later CR8 import correction. Its combined
candidate has now also passed the complete 15-case host-slice and 31-case SMP
targets, including public CR8 import and stopped IF-overlay sampling, with
no failures, ignored or filtered tests in either complete target. The 17
internal bank-owner, 16 state-bank and seven native completion controls also
pass, with no failures or ignored cases in those selected library namespaces.
The source-free owner control executes restored halt and CR8 state on 1, 2
and 4 CPUs after JSON and binary decoding. These namespace runs filter other
library tests; workspace and unfiltered full-library qualification remain
required before publication.

The first library build lacked the tracked Windows file-read observation
fixture introduced by a concurrent master update. That missing include
produced six compiler diagnostics. An isolated signed-offset probe compiled
unchanged on both toolchains, and restoring the exact tracked JSON input
eliminated every diagnostic without changing test code. All three portable
Windows file-read tests then passed. An intermediate harness incorrectly
applied a zero-filter assertion to that selected library namespace; its
terminal failure is retained. The corrected harness checks the exact selected
counts and retains zero-filter requirements for complete integration targets
and the final full library. The fixture annex has a separate checksum and is
excluded from production compiler dependencies.

The changed candidate adds controls for explicit wake, accepted IRQ, IF-clear
NMI, refused IRQ, public overlays and invalid durations. Internal native bank
controls encode/decode JSON and binary records after destroying the original
VM, CPU and RAM owners, on 1, 2 and 4 CPUs. Both halted-to-awake and
awake-to-halted destination replacement use the same saved RIP `0x1001`;
RIP alone cannot explain the expected behavior. Separate controls reject
legacy/controller-inconsistent records and check kernel wake against an
uninitialized peer. Changed-candidate native qualification is pending.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| KH1 | A userspace-controller HLT needs an owned wait latch | Retained Linux halt implementation and native baseline | Repeated entry must remain parked | Code after HLT changes RAM and exits through PIO | Canary changes before a wake | Confirmed defect in unchanged library; corrected complete 15-case host-slice target passes |
| KH2 | Explicit wake must preserve AP startup ownership | VCpu wake contract and KVM MP_STATE API | Kernel wake changes only HALTED | HALTED BSP alongside UNINITIALIZED AP | AP becomes RUNNABLE after wake | Native control passes in the 17-case owner namespace |
| KH3 | MP_STATE cannot reconstruct the userspace wait state | Linux userspace halt branch leaves it runnable | Internal versioned CPU bank retains a separate Boolean | Identical RIP in awake and halted captures; opposite destination state | Restored CPU runs too early or remains halted after awake restore | Source-free 1/2/4-CPU JSON and binary controls pass |
| KH4 | Native event acceptance is the wake boundary | Owned event API and native queue operations | Refused events do not resume execution | IF-clear IRQ refusal followed by NMI | Refusal clears the latch or accepted NMI leaves it set | Complete 15-case host-slice and 31-case SMP targets pass |
| KH5 | Immediate-exit sampling refreshes the full readiness predicate without guest retirement | KVM API run-header contract and Linux `kvm_arch_vcpu_ioctl_run`/`post_kvm_run_save` | IRQ wake after a halted IF overlay | Nonzero CR8, unchanged full public state, parked PC and RAM canary | A changed register/canary, stale readiness or any successful native exit | Native control passes in the complete host-slice target; unsupported capability rejects before entry by source inspection |
| KH6 | The run-header CR8 input must agree with a successfully imported special-register bank | Linux `kvm_arch_vcpu_ioctl_run` imports run.cr8; unchanged native baseline observes 3 becoming 0 | Ordinary execution after public/internal state import | Nonzero per-CPU CR8, source-free restore and actual guest entry | CR8 changes at the first post-import exit | Public import and source-free internal restoration controls pass; broad qualification remains pending |

## Sources and remaining scope

The retained [Linux x86 implementation](../kvm-native-private-state/references/linux-x86-v6.8.c),
`__kvm_emulate_halt`, defines userspace wake ownership. The retained
[KVM API](../kvm-public-state/references/kvm-api-v6.8.rst), sections 4.16,
4.38, 4.39 and 4.64, defines interrupt, MP_STATE and NMI interfaces.
Adjacent provenance files identify these references. The public `VCpu::wake`
contract defines explicit restart behavior.

High impact, in scope and still incomplete: the complete coordinated native
checkpoint producer, rollback, controller/timer phase and first-entry clock
activation. These tests establish no physical Intel macOS/HVF behavior.
