# Classic GIC CPU-interface and exception delivery

The classic single-Security-state GIC now keeps IAR, HPPIR and EOIR accesses in
their architectural groups. Wrong-bank reads return INTID1023 without consuming
the globally selected request; wrong-bank EOI writes preserve active state and
priority. A lower-priority request from another group cannot bypass that selection.

| Group | Acknowledge | Priority drop / EOI | Signal | PSTATE mask |
|---|---|---|---|---|
| 0 | ICC_IAR0_EL1 | ICC_EOIR0_EL1 | FIQ | F |
| 1 | ICC_IAR1_EL1 | ICC_EOIR1_EL1 | IRQ | I |

SGI register forwarding follows IHI0069H Table12-14, including its DS=1
exceptions. SGI1R can generate a configured Group0 request; SGI0R cannot generate
Group1. Secure/non-secure source state and absent EL3 are tested explicitly.
The unbanked public Gic convenience methods retain their existing interfaces.

The historical irq_line handle remains an aggregate interrupt-request handle.
A pending CPU path resolves the selected group under the GIC mutex before applying
masks. Ordinary no-request polling retains its atomic fast path. Direct ArmCpu
stepping reports InterruptPending without taking a vector; system interpreter
and bounded native entry take the corresponding IRQ/FIQ exception. EL2/EL3
routing, implicit lower-target masking, higher-target mask bypass, TGE independent
of E2H, and existing AArch32 Hyp delivery are covered within the represented profile.
This does not qualify every optional interrupt, virtualization or debug control.

WFI wakeup is independent of PSTATE.I/F; WFE can complete on an eligible
unmasked IRQ/FIQ without an event-register signal. Direct wait polling publishes
current timer outputs with zero counter advancement. The existing spurious-wakeup
policy and controller-less physical-timer fallback remain represented.

With E1NWF=0 and DPGS=0, an Any-routed SPI selects the first awake,
group-enabled PE. Exactly one participating PE receives the selection. WAKER
and group changes retarget it deterministically. Affinity routing retains the
previously qualified disabled-group exclusion policy.

GICD enable/pending clear aliases read their corresponding state. GICD and GICR
set-active writes preserve pending state; clear-active removes only active state.
These MMIO operations do not perform the CPU-interface priority drop. Word state
registers cover classic SPI32-1019 and private SGI/PPI0-31 respectively; reserved
INTIDs remain excluded. No broader MMIO-width or optional GIC profile claim follows.

## Checkpoint boundary

There are no new serialized fields or frame tags. Controller selection is derived
from the represented group, routing, WAKER, active and pending state. Restoration
publishes into target-owned aggregate handles and resolves the type from restored
state; there is no separately serialized IRQ/FIQ cache. Existing source-bearing
migration and rejection of ambiguous legacy pending sources remain unchanged.
The correction does not retain historical wrong-bank or Group0-as-IRQ behavior.

The six source-free files cover prepared 1/2/4-PE cohorts and both interrupt
groups with 128 MiB RAM. Guest code wakes each Redistributor, configures and pends
SGI7, enables both groups and waits with masks set. After capture/save/load, the
source kernel and checkpoint files are removed before constructing a fresh VM
from the loaded bundle. Re-restoration retains target-owned handle identity.

Both source and restored VMs then unmask the appropriate signal. Each PE's
exception-entry turn retires zero instructions and retains its saved ELR. Guest
handlers acknowledge through the correct bank, issue a wrong-bank EOI, inspect
RPR and active state, attempt a wrong-bank IAR, then issue the correct EOI and
return. Complete CPU state, counts, controller/coordinator state and the selected
Retired clock are compared before entry, at the entry boundary and after return.
Counts are nine retired instructions before entry and twenty after continuation
per PE. These are 28 post-snapshot handler executions across source and target.
They are prepared cohorts, not guest cold-start coverage.

## Evidence and limits

qualification.json records the exact tested source and executable hashes,
commands, observed reds/greens, Assumption Register, host/toolchain and omitted
gates. No stopped or compilation-failed iteration is a passing gate. In particular,
a discarded TGE/E2H interpretation and a probe missing activation readback are
recorded as invalid evidence, with corrected independent probes retained.

The current host is Apple M4 Max, macOS 27.2, Rust 1.99.1, LLVM 23.1.1.
There are twenty-one new root test declarations and one new standalone
controller-less timer test. The final unfiltered root result is 12,073 passed, zero failed and 35 ignored.
The registered cluster target passes all 27 cases. The 23 owning executables
include one cfg-empty target; qualification.json contains every count and command.
The Linux-AArch64-only native suite is cfg-empty on this host. No new hardware
or QEMU GIC oracle, native Intel VM execution, or C/C++ consumer rebuild is claimed.

Selection remains O(P(32+S)) time for P PEs and S SPI storage entries, with
O(P) participation selection and constant additional target storage. Per-word
state reads inspect at most32 interrupts. No throughput benchmark is claimed.
Public C ABI identifiers/layouts and instruction encodings are unchanged.

Primary rules are retained in [Arm IHI0069H, ID020922](../../specifications/arm/gic-ihi0069.pdf),
sections2.2.1,2.3.2,4.1,4.6.2,12.1.10,12.2.11-14 and the GICD/GICR state-register
descriptions; [DDI0487B.a](../../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf),
D1.14 and D1.17, supplies interrupt mask/wakeup rules. The retained
[Arm XML2025-12](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml)
TakePhysicalIRQException/TakePhysicalFIQException functions govern TGE routing.

The original A32-FP, C-STATE, C-SMP and C-HVF findings remain incomplete. Remaining
high-impact work includes full backend/private/in-flight and transactional state,
startup/clock/replay/debug and native controller profiles, native streaming FPSR
reentry and physical Intel qualification. A separate root-linked five-case probe reproduces GICD_TYPER under-reporting of
the configured SPI domain, including the default topology; this remains controller
discovery work. Optional GIC/NMI/LPI and complete
security/virtualization/debug behavior are not established by this group.

Historical ax.trace preservation failed before this group; its writer/cause and
original-content recovery remain unknown. This group guards its present bytes,
the primary executable and the protected guest processes. It does not relabel
the earlier loss as successful preservation. Pre-existing untracked user files
and other checkouts remain outside the owned change set.
