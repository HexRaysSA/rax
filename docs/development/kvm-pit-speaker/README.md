# Native PC PIT speaker-port ownership

The [managed PC PIT](../kvm-native-owner.md#managed-pc-pit-ownership) now owns
channel 2 and port `0x61` in the VMM. The following records describe the earlier
kernel speaker wiring and the independent IRQ0 acknowledgment experiments.

PC initialization at that revision created the in-kernel PIT with `KVM_PIT_SPEAKER_DUMMY`.
The kernel handled port0x61 together with channel2: gate writes, speaker-data
readback, OUT and refresh-clock status use the native PIT state. Previously the
kernel owned ports0x40..0x43 while the unrelated userspace system-control model
owned0x61; its OUT bit never reflected the native counter.

The generic `KvmVm::create_pit2()` configuration was preserved. Native PC
construction explicitly called the crate-private speaker-wired constructor. A
separate actual native control requires the generic constructor to leave0x61
in userspace.

The native VMM regressions program channel2 mode0 with count16, enable its gate,
and read0x61 using byte, word and dword IN. The guest checks gate/data readback,
zero upper bits for the kernel stub, and eventual OUT, then writes a RAM marker
and requests ACPI shutdown. Its TSC wait is bounded by1000000000 cycles; no
fixed host duration or hard real-time latency is inferred from that cycle bound.

Against the unchanged complete library, all three widths produce0xbad00061 and
fail; all six prior discovery/startup controls pass. The first complete repair
passes all nine cases and all ten I/O cases. Adding the generic-constructor
control then exposes its configuration change:9 passed,1 failed. The final
implementation selects speaker ownership at PC initialization. Its complete
production library passes all ten native cases and all ten I/O cases. All17
canonical workspace, feature, lint, documentation, selected-unit and owning
gates pass; five documented examples remain ignored.

The final production CLI activates exactly1/2/4 CPUs with the same Linux
kernel and command line. Complete numeric activation lines are retained in
`linux-startup-native.json`; each guest then exits through its own console.
Linux still reports LAPIC timer verification failures, failed TSC calibration
and inconsistent die topology. CPU activation does not establish full OS boot
or correct clocks. `qualification.json` retains those open requirements,
complete native checkpoint/replay work and physical Intel validation.

The primary KVM API4.71 defines the speaker flag. The retained Linux6.8
`i8254.c` implements the linked gate/OUT/status behavior. This is the native
kernel device profile; physical PIT/audio equivalence is not established.

## IRQ0 acknowledgment and detached continuation

The [native control](irq0-ack-control.c) runs a real-mode guest with KVM's
in-kernel interrupt controllers. It leaves PIT2 absent and sends a host
`KVM_IRQ_LINE` pulse. An IRQFD with `KVM_IRQFD_FLAG_RESAMPLE` monitors the
route. Its trigger eventfd stays idle, so the pulse and acknowledgment
paths have independent witnesses. The guest writes one port marker on
handler entry and another after EOI.

| Enabled route | GSI0 notifications per tested pulse | Observed at |
|---|---:|---|
| PIC, explicit EOI | 1 | After the PIC EOI |
| PIC, automatic EOI | 1 | By handler entry |
| I/O APIC, edge triggered | 1 | After the LAPIC EOI |
| I/O APIC, level triggered | 1 | After the LAPIC EOI |
| PIC and I/O APIC, distinct vectors | 2 | One after each controller's EOI |
| Both masked | 0 | No handler entry |

A second control shares one I/O APIC vector between masked pin 0 and enabled
pin 5. A pulse on GSI5 alone generates a notification on both observers.
This falsifies a one-to-one association between a GSI0 notification and
arrival of a PIT edge. KVM's PIC clears ISR before notifying, and the
I/O APIC EOI path matches source entries by vector. Kernel PIT2 and the
resample observer both register with the same acknowledgment mechanism.
[Linux v6.8 PIC](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/i8259.c),
[I/O APIC](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/ioapic.c),
[PIT](references/linux-pit-v6.8.c), [eventfd](https://github.com/torvalds/linux/blob/v6.8/virt/kvm/eventfd.c).

The detached control captures RAM and the CPU, LAPIC, PIC and I/O APIC banks
after the pulse, after handler entry, and after EOI. It destroys the source VM
and its eventfds before rebuilding those banks and attaching a fresh observer.
The replacement continues without a second pulse. Across 60 single-route
continuations, each guest entered its handler once and produced one total
acknowledgment. An event already observed on the source did not reappear on
the replacement. The existing IRQ state can carry a pulse across these
boundaries. A managed timer must retain its own consumed notification state
and interpret notifications under the controller's routing policy.

The control also ran 35 direct route cases on a physical Intel Xeon E5-1650 v3
with Linux 6.8.0-138-generic. The experiment uses the raw KVM UAPI. RAX's
checkpoint format and the timer's pending expirations, mask transitions,
watchdog delivery and oscillator phase remain outside this test.

Run on Linux x86-64 with access to `/dev/kvm`.

```sh
probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' EXIT
cc -std=gnu11 -O2 -Wall -Wextra -Werror \
    docs/development/kvm-pit-speaker/irq0-ack-control.c -o "$probe_dir/irq0-ack"
timeout 100s "$probe_dir/irq0-ack"
```
