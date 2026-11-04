# Experimental expired one-shot restoration

The retained native controls identify a sequence that preserves an expired
one-shot timer's initial-count register without introducing another interrupt.
This is a bounded experiment, not an enabled checkpoint implementation.

| Source phase | Raw restore: destination deliveries | Experimental restore: destination deliveries | Repetitions per method |
|---|---:|---:|---:|
| One-shot completed through EOI and IRET | 1 | 0 | 10 |
| Expired one-shot materialized in IRR, not yet consumed | 1 | 1 | 10 |

All 40 runs used Linux `6.8.0-138-generic` on the existing physical Intel Linux
KVM host. Each source VM, vCPU, run mapping and RAM mapping was destroyed before
constructing the destination. The destination received copied RAM and native
register/controller records; this does not exercise a RAX VM checkpoint file.

The timer's initial count was 1,000,000 counts; its current count was zero.
The initial-count register remained exactly 1,000,000 after restoration.
For all 20 experimental restores, all 1,024 LAPIC bytes, GPRs, SREGS, exported
vCPU events, MP state and 2 MiB of RAM matched the captured records before the
continuation. After the first delivery, the source and destination complete the native I/O
exit, execute the EOI and IRET, and check for another delivery. Each temporary
NMI was observed as pending before restoring the
original exported events. No frequency in Hz is inferred from the count.

## Sequence under test

Both machines use x2APIC. The source's guest handler acknowledges the timer with
an x2APIC EOI MSR write. The destination performs these operations while it is
exclusively stopped:

1. Install the captured LAPIC record with its timer LVT temporarily selecting
   NMI delivery. Preserve the vector, timer mode, initial count and current count.
2. Temporarily set MP state to HALTED and run with an already-pending,
   entry-only private signal, as in the [capture control](pending-materialization.md).
3. Read vCPU events, which processes queued NMIs, then reinstall the original
   source events to remove the artificial notification.
4. Restore the original timer LVT with `KVM_SET_MSRS`, index `0x832`, and restore
   the original MP state. This LVT write does not reload the initial count.
5. Compare the native records and RAM, then execute the actual guest continuation.

The [retained Linux v6.8 LAPIC source](../references/linux-lapic-v6.8.c) supplies
`kvm_apic_local_deliver`, `apic_update_lvtt`, `kvm_x2apic_msr_write` and the raw
LAPIC setter. The [retained x86 source](../references/linux-x86-v6.8.c) supplies
`kvm_vcpu_ioctl_x86_get_vcpu_events` and `kvm_vcpu_ioctl_x86_set_vcpu_events`.
The probe checks behavior on the recorded Ubuntu kernel; its full patched
source has not been independently matched to the archived upstream v6.8 files.

## Assumption register and remaining scope

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| N1 | The temporary HALTED run does not execute the guest; native-state equality depends on this | Compare all exported records and RAM before continuation | Confirmed for these 20 experimental restores |
| N2 | Reading and restoring events removes the artificial NMI; continuation equivalence depends on this | Require one temporary pending NMI, exact restored events and expected guest delivery count | Confirmed for these 20 experimental restores |
| N3 | The temporary raw LVT NMI encoding is suitable for a production restore contract | Establish a supported kernel/UAPI contract across supported hosts and relevant CPU states | Unknown; blocks production use |
| N4 | The sequence generalizes beyond the tested x2APIC expired one-shot | Exercise xAPIC, masked/disabled APIC, periodic/deadline timers, INIT/SIPI, nested execution and multiple CPUs | Unknown; no generalization claimed |

High impact: NMI delivery in the timer LVT uses a raw intermediate encoding
that guest LVT writes mask out. Successful ioctls and repeated native outcomes
do not establish a stable cross-kernel contract. This remains experimental.
The full producer still needs phase representation, common stopped capture,
PIT handling, nondefault profiles, coordinated rollback and first-entry gating.

Medium impact: x2APIC MSR writes require x2APIC mode. Switching an arbitrary
xAPIC guest into x2APIC can change its ID/logical-destination state; that is not
an established substitute for restoring its original timer LVT.

## Replay

On Linux x86-64 with usable `/dev/kvm`, GCC and pthreads:

```sh
python3 docs/development/kvm-native-private-state/lapic-timers/normalize.py > normalization-replay.json
```

This runs all four cells ten times, validates the records and delivery counts,
and removes its temporary executable on success or failure. Each delivery observation uses
a 200 ms alarm; each process has a 5 s watchdog. A no-delivery observation is
bounded by that alarm, not a claim about unbounded future behavior. Probe work
and storage scale linearly with the copied RAM size and repetition count.
The retained [raw observations](expired-normalization-v2.json) identify the
exact [C source](lapic-expired-normalize-v2.c) by SHA-256.
