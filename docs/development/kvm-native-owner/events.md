# Managed native IRQ and NMI delivery

The managed KVM CPU adapter now implements the public event methods through
its retained native owner. Calls take VM entry exclusion and the CPU guard.
They reject a poisoned owner or sticky I/O failure, and defer delivery while
native I/O, a device callback or a deferred exit still owns the boundary.
The complete 31-case native owning target passes with no failures, ignored or
filtered tests. Broader qualification remains pending.

Without an in-kernel IRQ chip, maskable delivery requires the kernel's sampled
interrupt readiness, current IF, no interrupt shadow, and no queued interrupt,
exception or NMI. A successfully queued vector remains in the native event
bank. A second managed call must leave that vector intact. Kernel-controlled
PIC/LAPIC profiles retain their own maskable interrupt path and return false
from these userspace IRQ methods.

The readiness sample may remain conservative after a public register overlay:
a subsequent bounded native turn refreshes it. The adapter does not infer
readiness from IF alone, which would omit nested and other native blocking
state. It does not request extra guest-visible interrupt-window exits.

For a CPU parked by the owned userspace HLT latch, an immediate-exit native
sample refreshes readiness without executing the instruction after HLT.
This permits an IF-enable register overlay to admit a wake event while
preserving the kernel's private blocking checks. See the separate
[halt and CR8 qualification](halt.md) for this later correction and its
remaining gates.

NMI delivery ignores IF and checks the exported pending, injected and
NMI-blocking state before the SDK's atomic queue operation. For an in-kernel
LAPIC, external NMI admission additionally checks that LINT1 is unmasked and
selects NMI delivery. Guest APIC IPI processing remains inside the kernel.
The code does not replace an entire GET_VCPU_EVENTS image to inject one event;
such replacement could erase a concurrently arriving native notification.

## Native regression and qualification boundary

The four cases in `tests/suites/backend/kvm/smp/events.rs` are registered in
the existing `kvm_smp` Cargo target. The unchanged qualified production library
fails all four, with zero passed, ignored or filtered cases. The retained
baseline identifies both the library and fixture by SHA-256. One intermediate
fixture revision failed compilation because the public segment granularity
field is Boolean; that attempt supplies no behavioral evidence. The corrected
fixture was rerun against the unchanged library and again failed all four.

The changed implementation passes the complete owning target, including
the original 27 native startup/controller cases. The new cases execute two
handler/IRET rounds on each of 1/2/4 actual managed CPUs, check that a second
IRQ cannot replace a pending vector, and test NMI delivery with IF clear.
They separately check NMI blocking after output settlement and before IRET.
The kernel-controller case enables the LAPIC and unmasks LINT1 in guest code,
executes its NMI handler, then masks LINT1 again and requires refusal.
VM and memory wrapper handles are dropped before the delivery checks, so
the CPU's retained owner must supply the live descriptors and RAM.

The initial changed owning run reported 30 passes and one failure. The failed
fixture incorrectly required a userspace HLT exit from a kernel-controller
CPU. A diagnostic using the same production library observed the actual NMI
handler output, IRET and stable halted RIP `0x1027`, while bounded entry returned
`None`. The retained Linux `__kvm_emulate_halt` explicitly distinguishes kernel
blocking from userspace HLT exits. The corrected fixture checks the exact
frontier, two further parked turns and refusal after the guest masks LINT1.
Its address is `0x1000 + (12 + 12 + 2 + 12 + 1) bytes = 0x1027`: SVR setup,
LINT1 setup, output, LINT1 masking and HLT. Production code did not change for
this correction. Compiler dependency records exclude the integration fixture
from production inputs; a separately hashed test annex and freshly built owning
executable identify the final result. The final fixture also fails all four
cases against the unchanged old library.

These tests do not restore a RAX checkpoint file or establish complete native
CPU/shared/timer serialization. Current qualification uses an immutable source
view, a distinct compiler cfg and a retained test executable. The complete
library gate remains required before publication of this candidate.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| KE1 | Managed IRQ calls must conserve the single queued external vector | KVM API 4.16 and Linux `kvm_vcpu_ioctl_interrupt`/event export | No lost IRQ when two calls precede entry | Queue different vectors; execute the first handler twice on 1/2/4 CPUs | A second accepted vector replaces the first or a peer executes it | Confirmed in the complete 31-case native owning target |
| KE2 | Native I/O and sticky errors must be resolved before event admission | Managed I/O ownership and event-boundary checks | Precise instruction/event ordering | Calls before output settlement and after an unsolicited input reply | Native event acceptance during an incomplete instruction, or silent success after a sticky failure | Confirmed in the complete native owning target; unchanged library fails the error-surfacing case |
| KE3 | Kernel-backed external NMI admission follows LINT1 configuration | KVM API 4.64 and QEMU's `do_inject_external_nmi` | Retained kernel controller ownership | Guest unmask/mask writes and real handler execution | Delivery through a masked/non-NMI LINT1 or missing delivery through the admitted route | Guest NMI-mode unmask/mask controls passed; other LINT modes are not exercised here |
| KE4 | Native readiness and event banks expose the represented blocking state | Linux `post_kvm_run_save` and `kvm_vcpu_ioctl_x86_get_vcpu_events` | IF/shadow/pending-event admission | Settled output, queued IRQ/NMI and handler-before-IRET boundaries | A second event overwrites pending state, or IF-clear NMI is refused | Represented 1/2/4-CPU cases passed; explicit shadow/nested variants remain unqualified and fresh overlays may require a bounded native turn |
| KE5 | The executable identifies the candidate source | Source map, distinct compiler cfg and frozen executable | Behavioral qualification | Require fresh engine and owning-target builds and nonzero complete test counts | Foreign cached code, changed input hash or filtered owning target | Fresh production build and final owning executable confirmed; test-only annex has dependency evidence; full library pending |
| KE6 | Kernel-controller HLT produces a userspace exit | Initial fixture assertion | Initial kernel-NMI test | Observe the handler, IRET, halted PC and further bounded turns | Entry returns `None` at the stable HLT frontier | Falsified; fixture corrected against the primary kernel behavior |

## Primary sources and remaining scope

The retained [KVM API](../kvm-public-state/references/kvm-api-v6.8.rst),
sections 4.16, 4.64 and the `kvm_run` readiness fields, and
[UAPI header](../kvm-public-state/references/kvm-uapi-v6.8.h) define the native
interfaces. The retained [Linux x86 implementation](../kvm-native-private-state/references/linux-x86-v6.8.c)
supplies queueing and exported event semantics. In particular, the userspace
controller branch of the retained interrupt setter queues directly, so the
managed pending-vector check is required rather than relying only on EEXIST.
The retained [QEMU KVM APIC source](../kvm-native-private-state/references/qemu-kvm-apic-v9.2.0.c)
implements the documented LINT1 check for external NMI. Each primary reference
has adjacent provenance and checksum data.

High impact: complete owned timer/controller integration, native private and
in-flight producers, coordinated rollback and first-entry clock activation
remain required. Event-method support does not replace those components or
close any of the four original audit findings. Physical Intel macOS HVF
execution remains unverified. No new wire field or native checkpoint producer
is activated by this change.
