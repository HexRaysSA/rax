# Native KVM access routing with userspace interrupt controllers

The current managed KVM checkpoint path has no complete public private-state
producer. Its kernel-owned LAPIC timer also has a demonstrated
[phase-export gap](../kvm-native-private-state/lapic-timers/README.md): identical
register banks can require different pending/consumed restoration behavior.
This control investigates an alternative ownership path on an unmodified host
kernel. It does not implement that path in RAX.

The independent [C observer](../../../tools/kvm/userspace_irq_entry.c) creates a
VM without `KVM_CREATE_IRQCHIP` or `KVM_CREATE_PIT2`. Each live CPU's
`KVM_GET_LAPIC` fails with `EINVAL` on the recorded host. Guest instructions
write an xAPIC LVT through MMIO, or write/read the x2APIC LVT MSR, then write and
read `IA32_TSC_DEADLINE`. Userspace retains a distinct deadline value for each
CPU. The guest copies the readback into registers and reaches HLT.

```text
guest APIC / deadline accesses
              |
      KVM userspace exits
       (no kernel IRQ chip)
              |
    observer-owned LVT/deadline
              |
     guest readback and HLT
```

The first two controls installed the MSR filter before CPU creation, then
before and after CPU creation. Both observed the APIC MMIO exit followed by a
filtered deadline read, with the expected deadline write exit missing.
Reapplying the filter alone did not change that result. The current source
retains this control as `--kernel-timer-path`.

Linux v6.8's retained
[`handle_fastpath_set_msr_irqoff`](../kvm-native-private-state/references/linux-x86-v6.8.c)
handles deadline writes before the generic filtered setter. Its
[`kvm_can_use_hv_timer`](../kvm-native-private-state/references/linux-lapic-v6.8.c)
predicate excludes a VM that permits guest MWAIT. The positive control selects
that documented per-VM setting using `KVM_CAP_X86_DISABLE_EXITS`; it changes no
host module parameter or kernel. With the fast timer path excluded, the deadline
write reaches the generic filtered userspace exit on the recorded host.
The upstream source explains this route; the Ubuntu kernel binary was not
disassembled to prove an identical implementation.

x2APIC MSRs cannot be denied by an MSR filter, as documented in
[KVM API section 4.97](../kvm-public-state/references/kvm-api-v6.8.rst).
With no kernel LAPIC, enabling userspace MSR exits for invalid/unknown accesses
provides the separate x2APIC route. Both x2APIC LVT operations arrive with
invalid-access reason 1 in these observations. Deadline accesses arrive with
filter reason 4. The C control checks each exact exit, data value and order.

| Control | Graphs | CPU cases | Positive `KVM_RUN` calls | Result |
|---|---:|---:|---:|---|
| Default kernel timer path, current reproducer | 1 | Stops on CPU 0 | None claimed | Expected deadline write exit missing |
| Per-VM timer path excluded, xAPIC | 15 | 35 | 140 | Exact native readback and HLT |
| Per-VM timer path excluded, x2APIC | 15 | 35 | 175 | Exact native LVT/deadline readback and HLT |

Each positive mode repeats the 1-, 2- and 4-CPU graph five times. All configured
CPUs coexist, but guest entries are sequential: this is not concurrent SMP,
INIT/SIPI or IPI proof. There are 70 positive CPU cases and 315 positive native
entries in total. These finite counts are not failure-probability estimates.
[Observations](observations.jsonl) and [qualification](qualification.json) retain
the source/header hashes, host/compiler identity, earlier failures and cleanup.

On Linux x86-64 with Python 3, GCC, KVM headers and usable `/dev/kvm`:

```sh
python3 -B tools/kvm/userspace_irq_entry.py --output /tmp/rax-userspace-irq-new
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/kvm -p 'test_userspace_irq_entry.py' -v
```

The report directory must be new. A newer kernel may route the default control
correctly; its actual result is retained rather than required to reproduce the
older missing write. Positive cases must all pass. Four protocol tests reject
missing/duplicate CPUs, wrong register or exit values, Boolean scalar aliases,
incomplete optional observations and unsupported expiry/restore claims.
The wrapper removes its temporary compiler/executable directory, and the
recorded remote reproducer directory was also removed. No RAX library is linked.

Guest RAM is exactly 2097152 bytes. The four-level identity tables cover 4 GiB,
including the APIC address, while that address has no RAM slot. Each CPU has a
5 s watchdog; the wrapper bounds each graph process to 10 s. Work is linear in
the fixed CPU count times repetitions; RAM and per-CPU host resources are bounded.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| U1 | Userspace can observe every required APIC/deadline access without a kernel LAPIC | Feasibility of RAX-owned timer/controller state | Require exact MMIO/MSR ordering and distinct readback for every CPU; retain the default-path failure | Confirmed for the recorded xAPIC/x2APIC LVT and deadline accesses in the selected per-VM mode |
| U2 | This route can support complete checkpoint restoration | Complete C-STATE producer | Bind real RAX controllers, preserve pending IRQ/EOI/timer phases, settle in-flight MSRs and validate fresh 1/2/4-CPU continuation | Unproven; not implemented by this observer |
| U3 | Permitting native guest MWAIT preserves all required runtime/debug behavior | Production use of the per-VM timer-path selection | Execute MWAIT, wake it by peer memory and IRQ, verify bounded host slices and checkpoint quiescence | Unproven; the control executes no MWAIT instruction |

High impact: timer expiry, interrupt delivery, the real RAX state producer,
late-failure rollback, idle/debug/MWAIT semantics and complete SMP continuation
remain required. This is routing evidence toward that implementation, and does
not close any of the four original audit findings.
