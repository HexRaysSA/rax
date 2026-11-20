# Native LAPIC one-shot migration counterexample

An already-delivered one-shot timer produces another interrupt after raw
`GET_LAPIC`/`SET_LAPIC` restoration in all five settled native controls. The
source produces no extra interrupt. This is a confirmed representation gap,
not a production fix or a complete RAX checkpoint test.

The physical Intel Haswell host runs Linux `6.8.0-138-generic` with APICv enabled;
see [host.json](host.json). Each destination is created after destruction of the
source CPU, VM and mapped RAM. The settled control explicitly copies its saved
RAM, general and special registers and LAPIC record into the new graph. No FP,
XSAVE, nested, shared-controller or complete VMM restoration is inferred.

| Control | Native observations | Meaning |
|---|---|---|
| [Expired, not yet consumed](lapic-expired-pending-control-v1.json) | Source and destination each reach the timer handler in 5/5 runs | Discarding every expired one-shot would lose a required delivery |
| [Delivered, output settled](lapic-settled-phase-control-v4.json) | Source reaches one handler; source continuation reaches HLT without another delivery; destination reaches another handler in 5/5 runs | Raw restoration introduces a duplicate after delivery |
| Same settled control, before delivery versus after EOI | All 1024 LAPIC bytes match in 4/5 runs | The exported LAPIC register bank alone does not identify the required phase |

The fifth record comparison differs in the pending vector's IRR bit. Both
outcomes are retained. Counts describe these finite observations, not a measured
failure probability.

The one-shot uses vector `0x41` and an initial count of 1,000,000 native timer
counts. The fixture waits 100 ms before observation and bounds each guest entry
by a 200 ms signal timeout. It makes no conversion from timer counts to seconds
and establishes no LAPIC/TSC calibration. The Python wrapper also bounds each
whole native process by 5 s.

The settled control completes the handler's debug-port output with
`KVM_RUN.immediate_exit` before reading its state. Saved RIP is `0x2004`, after
the output instruction. Its unreal-mode data segment permits the 32-bit EOI
MMIO address. The source subsequently clears ISR through EOI, executes IRET and
halts at `0x1002`. These checks distinguish a new interrupt from replay of an
uncompleted output or a segment-limit fault.

## Reproduce

On Linux x86-64 with GCC, Linux KVM headers and usable `/dev/kvm`:

```sh
python3 docs/development/kvm-native-private-state/lapic-timers/replay.py
```

The wrapper compiles and executes both retained C sources five times, verifies
the recorded behavioral distinction, prints JSON and removes its temporary
executables. A changed kernel that does not reproduce the counterexample fails
the behavioral assertion; that result needs inspection rather than relabeling.
These diagnostic sources are not registered as a passing Cargo regression for
an unfixed production behavior.

## Primary sources and limits

[Linux v6.8 LAPIC source](../references/linux-lapic-v6.8.c) supplies the relevant
`apic_timer_expired`, `cancel_apic_timer`, `set_target_expiration`,
`kvm_apic_get_state` and `kvm_apic_set_state` definitions. The GET path exports a
calculated current count; the SET path cancels and reconstructs the timer. A
zero current count in one-shot mode installs an immediate deadline when the
initial count remains nonzero. This source explains the observed duplicate;
the native observations apply to the recorded Ubuntu kernel build.

[QEMU v9.2.0 KVM APIC source](../references/qemu-kvm-apic-v9.2.0.c) is retained
as a comparison implementation. Its conversion stores initial-count and
virtual-clock information rather than providing a separately exported KVM
pending-timer phase. No QEMU execution or equivalent failure is claimed here.
Both references retain upstream notices and provenance/checksums alongside them.

The [assumption register](qualification.json) confirms settled I/O and executable
EOI, and falsifies sufficiency of the LAPIC register bank alone. High-impact
remaining work is an owned timer-phase representation or canonicalization that
preserves both pending and completed cases, integrated with the actual stopped
boundary and first-entry gate. Unconditionally zeroing the initial count does
not satisfy both controls. PIT phase/reinjection, periodic/deadline profiles,
complete production rollback and physical Intel macOS remain separate required
work. All four original audit findings remain open.

The later [pending-materialization control](pending-materialization.md) tests a
candidate capture prerequisite without executing the original guest. It leaves
the restoration counterexample above unresolved.

The [experimental x2APIC restore control](expired-normalization.md) preserves
the initial-count register and distinguishes completed from still-pending
expired one-shots in 40 native controls. Its temporary raw NMI encoding is not
an established production restoration contract.

The later [masked-restoration control](masked-restoration.md) tests an LVT-mask
alternative without artificial NMI delivery. It appears effective on fresh
default graphs, but initialized relocated graphs retain a duplicate despite
exact exported-bank equality. All 24 observations are retained; the candidate
does not supply the missing general timer-phase contract.

The [SVR staging control](svr-restoration.md) clears the private expiry latch
with a guest-legal x2APIC register write. It preserves absence or presence of
the pending timer interrupt on both destination profiles in twenty staged
trials. The result covers an expired x2APIC one-shot with source pending
interrupts already materialized in IRR.

## Future expiry with a zero current count

Linux v6.17 reports the remaining timer phase in whole counts. A one-shot
with less than one count left can therefore report zero before it fires.
The [native probe](lapic-zero-count-before-expiry.c) selects a bus cycle of
20,000,000 ns and a divider of 128, so one timer count spans 2,560,000,000 ns.
Its early sample must find an initial count of one, a current count of zero,
and no pending or in-service interrupt for the timer vector. The guest must
remain in HLT during the first entry, reach the timer handler after the
configured interval, then finish EOI and IRET without a second delivery.
The probe requires both xAPIC and x2APIC cases to pass.

Run the [native KVM LAPIC timer phase workflow](../../../../.github/workflows/native-kvm-lapic-phase.yml)
on a Linux x86-64 host exposing `KVM_CAP_X86_APIC_BUS_CYCLES_NS`.
The [hosted run](https://github.com/HexRaysSA/rax/actions/runs/44761608392/job/136375298551)
passed on Linux `7.0.0-1014-aws`. In each mode the exported 1,024-byte
LAPIC record was identical before expiry and after delivery and EOI.
The observed delivery time includes the KVM exit and userspace readout.

| Mode | Early sample after programming (ns) | Handler output observed after programming (ns) | Changed LAPIC bytes |
| --- | ---: | ---: | ---: |
| xAPIC | 5,708 | 2,560,233,398 | 0 |
| x2APIC | 4,726 | 2,560,177,101 | 0 |

These cases rule out using the LAPIC record alone to classify a zero count
as settled. The test compares the LAPIC bank and observes native delivery
and EOI. Exact capture and restoration through the RAX VMM remain open.

[Linux v6.17 LAPIC code](https://github.com/torvalds/linux/blob/v6.17/arch/x86/kvm/lapic.c)
[Linux KVM API for the APIC bus period](https://www.kernel.org/doc/html/v6.13/virt/kvm/api.html#kvm-cap-x86-apic-bus-cycles-ns)
