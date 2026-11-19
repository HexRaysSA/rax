# Intel interrupt-window acknowledgement

Restoring a native checkpoint may restore primary execution-control bit 2.
When RFLAGS.IF is set and STI/MOV-SS blocking is absent, this requests a VM exit
before an instruction. The former handler resumed without clearing the request,
so the same window could exit repeatedly without reaching a queued guest exit.

The handler now clears only bit 2 and verifies the full primary-control readback.
Monitor-trap and other control bits retain their current values. An already
cleared request needs no write. A read, write, or readback failure propagates
through the existing native-entry fence before another guest entry. A window
acknowledgement consumes no caller-owned interrupt, advances no guest RIP, and
does not create an instruction retirement or debugger completion.

The acknowledgement takes O(1) work and storage: one read if already cleared,
otherwise two reads and one write. Existing iterative dispatch remains O(n) for
n internal exits with O(1) host stack.

## Evidence boundary

The existing compiled backend with an independently specified SDK model observed
five failing window regressions and two passing event-slot/SDK-acknowledged
partitions. These are iteration results, not a complete owning-target result.
Complete affected targets passed: 12 event/policy cases, 14 run-loop cases,
52 actual-owner SDK cases with debug and 49 without debug, all unfiltered and
without ignored cases. Workspace format/check/build/clippy and Intel-target
clippy passed. Seven focused SDK cases also passed; these overlap the complete
targets. Exact receipts and unchanged-parent-library proof boundaries appear in
[qualification.json](qualification.json).

The SDK fixture also now models normal VM exits clearing entry-event valid and
failed entry preserving it. No backend operation was added to clear this
hardware-owned bit. Explicit normal/failed-entry cases accompany that fixture
correction.

The fixture runs actual RAX owner, entry, checkpoint and dispatch code against
modeled SDK storage. It executes no Intel guest instruction and does not create
a native Hypervisor VM. Physical Intel qualification, general interrupted-event
reinjection, other native startup/IRQ profiles and deterministic replay remain
open.

## Checkpoint with a queued CPU entry event

The native `entry-irq` profile runs an Intel HVF guest that arms a LAPIC timer,
enables interrupts and halts. In the restored case the stopped CPU accepts
vector `0x51` into its entry slot and the LAPIC acknowledges it before capture.
A fresh VM and vCPU reuse the stopped guest memory, restore the LAPIC model
and load the captured CPU record. The test resumes without injecting the event
again. It checks that the handler has yet to run at restore, runs exactly once
after entry, clears the in-service timer with a guest EOI and returns to the
original guest execution. A direct run exercises the same handler and checks.

Both cases passed at `ef0673a138a99ff96099929d3673e829746fcd6f` on a virtualized
Intel Core i7-8700B running macOS 15.7.9 with SDK 15.5. The process ran x86-64
without translation. The signed executable, both workflow archives and 4,767
engine inputs matched the recorded source.
[Native job](https://github.com/HexRaysSA/rax/actions/runs/44366953908/job/135023164979)
[Artifact verification](native-entry-irq-verified.json)
[Observations](native-entry-irq-observations.jsonl)

This exercises the native CPU record and its relationship with the caller-owned
LAPIC. The profile uses one CPU and in-memory records. Full VM checkpoint
publication, concurrent interrupt sources and general interrupted-event
reinjection remain open. The local build and workflow checks are recorded in
[entry-irq-qualification.json](entry-irq-qualification.json).

## Sources

The retained [Intel SDM](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
Vol. 3C Section 26.6.2/Table 26-6 and Appendix C define the control and exit reason
7. Sections 29.2 and 28.8 distinguish normal-exit and failed-entry handling of the
entry-event valid bit. The primary checksum, assumptions and falsification probes
are retained in [qualification.json](qualification.json).

## Controller-owned IRQs during native slices

The Intel HVF VMM checks for an eligible PIC or local APIC request after
normal arbitration. A finite slice can ask the CPU owner to watch for an
interrupt window when guest IF, an STI/MOV-SS shadow, or an occupied entry
slot delays that request. VM exit reason 7 then yields to the coordinator
before the next guest instruction. Normal PIC/LAPIC arbitration offers the
vector on the following turn. The controller acknowledges it only after the
entry slot accepts it.

A watch set by the slice is cleared before it returns, including when the
host deadline or a different guest exit wins. The CPU owner's quiescence
guard covers the whole operation. A restored window control remains armed
until it produces a window exit. Setting or clearing the control verifies
full readback and takes O(1) work and storage. IRQs that first become pending
during a native slice are observed by the next VMM controller poll.
When the SDK capability cannot toggle the control, delivery uses the normal
controller polls at host-slice boundaries.

The `irq-window` native profile runs `STI; NOP; CLI` in three cases. A run
without the watch completes with its IRQ still queued. The direct and
stopped-restore cases yield before CLI, accept the same queued vector once,
and execute the guest's EOI and continuation marker.
