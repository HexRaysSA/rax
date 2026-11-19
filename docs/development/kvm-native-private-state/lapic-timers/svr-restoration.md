# Expired x2APIC one-shot restoration through SVR

On physical Intel Haswell with Linux `6.8.0-138-generic`, staging the x2APIC
Spurious Interrupt Vector Register (SVR) preserved the completed or pending
phase of an expired one-shot in two destination profiles. The initialized
profile relocated the APIC base and ran the destination before loading the
checkpoint. This exercises the profile that falsified the earlier
[LVT-mask sequence](masked-restoration.md).

| Destination | Source timer phase | Raw destination deliveries | SVR-staged destination deliveries | Repetitions per method |
| --- | --- | --- | --- | --- |
| Fresh, default base | Completed through EOI and IRET | 1 | 0 | 5 |
| Fresh, default base | Expired and materialized in IRR | 1 | 1 | 5 |
| Initialized, relocated base | Completed through EOI and IRET | 1 | 0 | 5 |
| Initialized, relocated base | Expired and materialized in IRR | 1 | 1 | 5 |

Every SVR-staged restore returned all 1,024 captured LAPIC bytes, including
the initial count of 1,000,000 and the zero current count. It also preserved
the exported GPRs, system registers, events, MP state and the contents of
2 MiB of guest RAM. Every run destroyed the source before constructing the
destination. On the source and the SVR-staged destination, any expected
interrupt delivered once and the guest completed EOI and IRET. A report of
zero deliveries describes the fixture's bounded 200 ms observation.

## Sequence

1. Copy the LAPIC image to the stopped destination with the timer's LVT mask
   set. Keep the timer mode, vector, initial count and current count.
2. Write the saved SVR with bit 8 clear using x2APIC MSR `0x80f`. On the
   tested kernel, the write clears the private pending-timer latch and masks
   all present LVT entries. The temporary timer mask suppresses a delivery
   if APICv delivers the immediate expiry during `KVM_SET_LAPIC`.
3. Restore the saved SVR, followed by the saved LVT entries using their
   x2APIC MSRs. Include CMCI when the version register advertises it. The
   timer LVT write leaves the initial count intact. No target guest entry
   occurs during these steps.

The relevant paths are `kvm_apic_set_state`, `apic_timer_expired`,
`kvm_lapic_reg_write` and `apic_update_lvtt` in the
[retained Linux v6.8 source](../references/linux-lapic-v6.8.c). The source
provides the mechanism; the probe measures the installed Ubuntu kernel.
The fixture explicitly populates thermal, performance-counter, LINT1 and
error LVT entries before capture and compares every exported LAPIC byte.

## Assumptions and remaining scope

| ID | Assumption and dependent result | Falsification probe | Status |
| --- | --- | --- | --- |
| S1 | Masking the timer during `SET_LAPIC` and subsequently clearing SVR bit 8 disposes of the artificial expiry. The completed phase depends on it. | Restore a completed timer on both profiles and observe an extra handler invocation. | Confirmed in ten staged restores on the recorded host. |
| S2 | The same sequence preserves the captured IRR and LVT entries. Pending delivery and exported-bank equality depend on it. | Start with a materialized timer interrupt or populated unrelated LVTs, then compare bytes and count deliveries. | Confirmed across the twenty staged restores. |
| S3 | An outstanding expiry is represented in the captured IRR before restoration. Pending-phase equivalence depends on it. | Capture the same expired timer before [source materialization](pending-materialization.md) and compare continuation. | Required by the current fixture. General stopped capture remains open. |

High impact. The sequence is qualified for expired x2APIC one-shots under
the recorded conditions. xAPIC, running countdowns, periodic and deadline
modes, capture at expiry, concurrent sources, and multi-vCPU coordination
need separate evidence. Kernel PIT phase and the production checkpoint
transaction remain open. This diagnostic is outside the runtime restore path.

## Replay

On Linux x86-64 with usable `/dev/kvm`, GCC and Python 3:

```sh
python3 docs/development/kvm-native-private-state/lapic-timers/svr-restore.py
```

The driver generates both fixture sources from the same hashed C parent,
requires forty successful trials by default, and removes its build directory.
The [retained observations](svr-retained-replay.json) include all trial
outcomes and the script and generated-source hashes.
