# Software I/O APIC interrupt conservation

The original controller generated another edge message whenever an already
asserted source was reported. Consuming a level message did not set remote
IRR, and there was no EOI completion path. All four added baseline regression
groups failed; the existing sixteen module tests passed.

The controller now keeps at most one unaccepted message per input pin. An edge
requires an inactive-to-active transition. Masked edges are discarded; an
asserted level is reevaluated on unmask. Delivery status represents an owned,
unaccepted message. Acceptance of a fixed/lowest-priority level message clears
delivery status and sets remote IRR. Further level reports wait for a matching
EOI. A matching EOI clears remote IRR for every matching pin and reissues an
unmasked level only while its source remains asserted. A changed route updates
an unaccepted message; masking or withdrawing an unaccepted level cancels it.
Changing the trigger mode to edge clears the previous level's EOI wait.

The advertised version-0x20 controller also implements directed EOI at offset
0x40. Its PC bus registration now includes that register. The `set_irq` input
is a normalized asserted/deasserted source, as in the existing KVM source API;
it is not a raw voltage measurement of the physical input pin.

The existing checkpoint field layout is unchanged. It retains the RTEs,
asserted inputs and ordered messages without replaying register writes during
publication. Input decoding bounds the message vector to 24 elements before
reserving storage. Admission rejects duplicate pins, stale route metadata,
contradictory delivery status, impossible remote-IRR state and an active fixed
level with no represented pending/accepted phase. Such an old incomplete level
record cannot be reconstructed by silently reasserting the source.

## Independent controls

[`ioapic_native.c`](../../../tools/hvf/ioapic_native.c) uses Linux KVM directly,
without linking RAX. It observes eighteen controller frontiers across edge and
level inputs. Native guest instructions unmask the IOAPIC and write LAPIC EOI;
KVM UAPI reads capture IOAPIC remote IRR and LAPIC IRR/ISR/TMR. The in-service
frontier is explicitly installed with `KVM_SET_LAPIC` before EOI. Consequently
this control does not prove interrupt-handler entry or a full device workflow.
Its executable and all native graphs are removed after the observations.

The checked-in JSON fixture records those observations, host/kernel/compiler
identity, source hash and evidence boundary. The production-source harness
passes 27 tests, with no failures, ignored or filtered tests. It includes
source-free JSON/binary checkpoint phase continuations and comparison with the
native frontiers. The initial child-module visibility failure is retained
separately; no behavioral test ran in that failed build. The later complete frozen root and workspace checks passed on both recorded
hosts. Their source boundaries remain distinct from this historical module
harness; see the [SDK qualification](../hvf-intel-sdk/sdk-model-qualification.json).

Primary semantics are Intel document 631120-002, *Intel 500 Series Chipset
Family On-Package Platform Controller Hub Datasheet, Volume 2*, section 25.1.3,
pages 938--939 (redirection entries), and section 25.2.3, pages 949--950
(directed EOI). The [retained primary PDF](references/intel-500-pch-registers-631120-002.pdf)
has an adjacent URL/retrieval/checksum provenance record. Linux v6.8
[`ioapic.c`](../kvm-native-private-state/references/linux-ioapic-v6.8.c)
and [`lapic.c`](../kvm-native-private-state/references/linux-lapic-v6.8.c)
provide the independently executed kernel implementation and its trigger-mode
and EOI paths. These sources have separate platform/implementation scopes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| IRQ1 | The tested fixed-delivery transitions agree with the selected Intel controller semantics | Primary RTE/EOI definitions and eighteen independent KVM frontiers | Edge/level conservation and EOI phase | Repeated assertion, masking, actual guest unmask, asserted/deasserted EOI, malformed saved phase | A mismatch in native observations or source-free continuation | Confirmed for the recorded fixed-delivery cases; other delivery profiles remain separate |
| IRQ2 | Complete VMM routing can preserve PC-controller-before-LAPIC lock order and avoid CPU callbacks under model locks | Existing checkpoint lock order | Multi-CPU delivery and coordinated restoration | Blocked injection, destination changes, queued EOI and failed host publication | A lock cycle, lost message or duplicate accepted effect | Component routing passed in the recorded complete roots; full profile and native Intel limits remain |

## VMM composition and remaining gates

The VMM now consumes the software IOAPIC queue for fixed, lowest-priority and
edge-NMI messages, including physical/logical destinations and disabled-target
backpressure. Accepted vectors retain their trigger mode in each local APIC.
Level EOIs create owned per-CPU broadcast FIFOs; routing transfers those
broadcasts back to the IOAPIC without holding model locks across CPU callbacks.
UART levels and the PIT IRQ0-to-GSI2 override feed that same source/controller
path. Native KVM controller ownership bypasses duplicate software routing.

Complete execution records carry nonempty EOI FIFOs in the required RAXEXE10
extension. Empty queues retain the earlier exact execution bytes. Nested,
truncated, oversized, empty and inconsistent extension frames reject. Base-only
capture/publication rejects pending broadcasts instead of dropping them.
Source-free 1/2/4-CPU file continuation, UART acknowledgement and PIT/controller
integration tests are registered and passed within the recorded complete
frozen roots. Their platform and source boundaries are retained in the
qualification record.
The controller/routing/LAPIC/timing source-module harness passes175tests with no
failures,ignored or filtered tests. The first combined Cargo library check also
passes; these results do not replace the owning binaries or full library gate.

High impact: SMI/INIT/ExtINT and level-NMI delivery profiles still require their
complete platform contracts. Remaining
PC peripheral sources, physical Intel macOS Hypervisor.framework execution,
remaining native profiles and whole-VM checkpoint completion remain open.

## Backend source ownership

The x86 emulator and Intel HVF previously accepted `Vm::set_irq_line` assertions
into detached queues with no production consumer. Deassertions were ignored.
The baseline public-API control also observed successful publication for invalid
GSIs 24 and 4294967295. That source API now binds once to the same I/O APIC Arc
used by the PC MMIO bus and checkpoint inventory. VMM construction installs the
binding before creating CPUs, for both boot and detached checkpoint targets.
Repeated binding of the same controller is idempotent; another controller,
an unbound source, invalid GSI or poisoned controller returns an error.

Both assertion levels update the controller immediately. The controller owns
edge detection, masking, queued delivery and remote IRR, so no backend-only
source phase remains to serialize. The controller source is acquired before
Intel native exclusion, matching checkpoint capture's controller-to-writer
order. Publication mutates the line only after both guards succeed and invokes
no CPU, SDK entry or bus callback.
The global Intel record retains its existing wire layout with an empty
`pending_irqs` field. Historical nonempty detached-assertion records remain
decodable for inspection but cannot be admitted for restore: they omit the
source level/history needed to reconstruct controller state. Shared native
restore does not replay source setters or overwrite the separately owned PC
controller.

The binding regressions cover edge/level changes before scheduling, repeated
high reports, invalid GSIs, controller identity and publication failure.
The VMM file test exercises the backend API on both source and restored target.
The later complete SDK-owner binary passes all 59 tests, and both complete
frozen roots pass with their recorded source boundaries. The
[SDK qualification](../hvf-intel-sdk/sdk-model-qualification.json) binds those
results to the current source files. Run 41978606771 failed its first RAM-only
control without retaining the exit; run 41983036300 subsequently observes
failed-entry reason `0x80000021`. The
[shadow-import correction](../hvf-intel-frontier/control-shadow-import.md)
passes the complete 60-test SDK owner suite. Corrected actual RAX run
41992554080 has built and retained its signed consumer; native execution is
pending. See the [frontier diagnostic](../hvf-intel-frontier/README.md).
Cross-compilation and SDK mocks do not establish native guest behavior.
