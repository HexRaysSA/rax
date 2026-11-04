# Combined native KVM CPU record

This candidate composes the previously qualified fixed banks, explicit SREGS2,
kernel-sized XSAVE, migration MSRs and nested-state envelope into one owned CPU
record. It captures actual KVM state, derives public registers from that same
capture, validates destination compatibility and restores the stored banks.
It is not connected to the production VMM checkpoint hooks. The retained
[complete-producer witness](../../../../src/backend/kvm/checkpoint_backlog_tests.rs)
remains open; this experiment does not close any complete audit finding.

The exact qualified inputs are under [source/](source/). The implementation is
[cpu.rs](source/src/backend/kvm/checkpoint/cpu.rs); runtime CPUID admission is in
[profile.rs](source/src/backend/kvm/checkpoint/profile.rs). Every input hash,
actual compiler argument, command result and evidence boundary is retained in
[qualification.json](qualification.json) and [result.json](result.json).

```text
source VM + native CPU banks + owned RAM
                 |
          capture and encode
                 |
       destroy every source FD and mapping
                 |
     decode JSON or the actual RAX legacy codec
                 |
     fresh destination + immutable preflight
                 |
       native setters + exact bank recapture
                 |
  guest reads GPR / XMM / upper YMM, or VMREAD + VMXOFF
```

| Experiment | Observed result |
|---|---|
| One, two and four CPUs; userspace and in-kernel controller profiles | Six source graphs, 28 source-free CPU restores through two codecs |
| Protected-mode guest reads restored RBX, XMM0 and upper YMM0 | 84 verified output values |
| Wire, identity, controller, CPUID, XCR, XSAVE, SREGS2 and allocation controls | 700 rejections; every stored destination CPU bank unchanged |
| Loaded VMCS at GPA 0x9000 with GUEST_RIP=0x4142434445464748 | Two combined source-free restores; VMREAD returns that value and VMXOFF succeeds |
| Native Rust build, Clippy and C observer compilation | All commands exit zero; 22 build and 25 Clippy warnings retained |

The warnings are unused copied helpers and existing XSAVE unsafe/style warnings;
none were suppressed. The complete product owning targets were not rerun for
this candidate. The exact standalone compilation uses the retained complete RAX
library for its actual error and public state types, the pinned native SDK and
the actual production codec and XSAVE/conversion sources. It does not substitute
mock SDK structures or error types. The root dependency manifest and lock remain
unchanged. This evidence does not imply a normal product Cargo build has enabled
the SDK's optional serde/zerocopy support.

## Admission and publication contract

The caller must own an exclusively stopped VM and have completed every native
userspace-I/O continuation before capture. GET_MP_STATE accepts pending INIT/SIPI,
so it precedes capture of the other banks. No KVM_RUN occurs inside the CPU
capture or restore helper. The fixed wire envelopes enforce version, bank kind
and exact length; each variable sequence has a bound checked before reservation.
XSAVE layout descriptors and the complete kernel-sized image remain together.

The [Linux v6.8 primary source](../references/linux-cpuid-v6.8.c), especially
`__kvm_update_cpuid_runtime` and `xstate_required_size`, defines the admitted
runtime CPUID changes. OSXSAVE, APIC and OSPKE must agree with CR4/APIC_BASE;
OSXSAVE/OSPKE are mutable only when the host supports their corresponding
features. Standard and compacted XSAVE sizes must match XCR0 and the exact host
component layout. PV_UNHALT can clear relative to a requested profile, but its
effective source and destination values must agree because it also depends on
VM halt policy. Immutable fields, order and CPU geometry must agree. The managed
default MISC_ENABLE_NO_MWAIT quirk is retained; disabling it needs another profile.

The legacy pending-interrupt bitmap is retained separately from SREGS2's PDPTRs.
The helper installs both banks, then XCR/XSAVE, stored MSRs, LAPIC/debug/register
state, nested state, events and finally MP state. Setter failure can leave a
partially changed destination. This API therefore requires a disposable target
or a complete enclosing VM rollback transaction. It is not a transaction itself.

The counter MSRs remain in the record. This helper deliberately leaves their
application to the coordinated clock producer. The stored-bank equality control
excludes only those advancing counter values; no bytes or non-counter banks are
excluded. Source and destination have identical physical XSAVE layouts. Layout
conversion and scaled/rate-changing migration are unsupported by this candidate.

The six basic graphs initialize every CPU as runnable and execute them serially.
They do not prove VMM SMP scheduling. In-kernel-controller targets close after
their final observed OUT, since their HLT would sleep inside KVM without a wake
event. The nested observer separately completes its finite OUT frontier, resumes
VMREAD/VMXOFF and observes HLT with a userspace controller. That finite frontier
does not implement generic multi-exit MMIO settlement. No active L2 guest runs.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| CPU1 | Source capture and destination setters have exclusive stopped ownership | The harness owns all FDs; source destruction precedes decode; concurrent entry would invalidate this contract | Confirmed for these probes; production exclusion remains required |
| CPU2 | Native state banks compose in the recorded restore order | Exact recapture, 84 guest outputs, loaded-VMCS VMREAD/VMXOFF through both codecs | Confirmed for the represented profiles |
| CPU3 | Source and destination share the same architectural XSAVE layout and configured CPU profile | Altered profile, runtime bit, size, descriptor and identity controls reject before setters | Confirmed on this physical Haswell host; heterogeneous migration unverified |
| CPU4 | Malformed wire/profile records cannot mutate the destination | All 700 controls recapture and compare every stored bank after rejection | Confirmed for the enumerated controls; native value setters still require rollback |

## Retained observer failures

The earlier build tried to compare a public state type that does not implement
PartialEq. The observer now checks its expected architectural fields directly;
exact native-bank equality is a separate assertion. An earlier SET_FPU-only seed
left the XSAVE SSE-present bit clear; the corrected observer seeds through the
actual XSAVE writer. An added AVX observer initially retained a real-mode guest;
the qualified guest uses 32-bit protected mode. These observer failures are
retained in the external qualification workspace and are not reported as product
regressions. The final input hashes and zero-exit results refer only to the
qualified revision.

| Impact | Remaining boundary | Blocks complete native checkpoint closure |
|---|---|---|
| High | Production exclusion, membership, private/shared hooks and coordinated rollback/poisoning | Yes |
| High | Shared IRQchip/PIT state, counter aliasing, first-entry clock publication and generic in-flight I/O settlement | Yes |
| High | Actual complete one/two/four-CPU VM files, startup/halt/wake/IRQ and replay | Yes |
| High | Active L2, additional native capability/value profiles and native setter failure rollback | Yes |
| Medium | Other CPU vendors, XSAVE/rate profiles, kernels and physical Intel macOS | No corresponding coverage claim |

Record processing uses O(N) time and storage in its bounded wire size. CPUID
admission uses O(P + C) time for P CPUID entries and C component descriptors.
