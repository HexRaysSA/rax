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

Both cases passed again at `748b0a5937bb098d146d114e9de56cd5c35ae197` on
hosted Intel macOS. The direct and restored observation records match the
earlier run byte for byte. The downloaded executable passed strict signature
verification, and all 4,884 engine inputs matched the source revision.
[Repeat native job](https://github.com/HexRaysSA/rax/actions/runs/45064920436/job/137338825983)

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

### Hosted Intel witness

All three cases passed at the signed revision
`1ce2a958e4b7b121bcfdb1ca995a02bb6c878b81` on a virtualized
Intel macOS 15.7.9 runner with SDK 15.5. The probe ran in
a native Intel process. The verifier matched both workflow archives, the signed
executable, and 4,846 source files.
[Native job](https://github.com/HexRaysSA/rax/actions/runs/44572002098/job/135729325300) [Verified receipt](native-irq-window-verified.json)
[Guest observations](native-irq-window-observations.jsonl)

| Case | Guest handler visits | Controller after continuation |
| --- | ---: | --- |
| Unarmed control | 0 | Vector pending |
| Direct | 1 | EOI accepted |
| Fresh vCPU with restored LAPIC | 1 | EOI accepted |

The restored case uses a stopped CPU record, guest RAM, and a caller-held
LAPIC image. Full coordinated file restore and native multi-CPU IRQ ordering
remain open. Portable coordinator tests separately covered four CPU selections
and the PIC and LAPIC priority gates.

## Controller-owned NMIs

The Intel VMX profile enables virtual NMIs when the SDK capability allows
it. VM entry then blocks another NMI until the guest's IRET removes the
block. The coordinator watches primary execution-control bit 22 for each
selected CPU with a pending local APIC NMI. Exit reason 8 yields before the
next instruction. The LAPIC retains the NMI until VM-entry injection accepts
it. BSP arbitration offers an NMI the entry slot before a competing PIC IRQ.
Guest IF and LAPIC processor priority govern maskable interrupts separately.

The checkpoint records the guest interruptibility field and the VM-entry
event slot. A legacy record can adopt the virtual-NMI policy when all other
profile fields match and its saved NMI block is clear. An older producer's
unrecorded handler state cannot be reconstructed. Restore rejects a legacy
physical-NMI block on migration and rejects a queued NMI when the target
lacks virtual blocking. A target with virtual blocking can deliver NMIs
through controller polls if its SDK disallows toggling the window control.

| Assumption | Dependent behavior | Falsification probe |
| --- | --- | --- |
| VM entry establishes the virtual block and IRET clears it. | The queued second NMI waits for the first handler to return. | An interruptible VM-entry slot after the handler's OUT and before IRET, or a watched slice that passes the first instruction after IRET. |
| Restore preserves the VMCS interruptibility field before execution. | A restored CPU resumes in the original handler. | Acceptance of another NMI immediately after restoring the stopped handler to a fresh CPU. |
| The software controller retains an event until the CPU accepts it. | Each selected CPU watches only its own pending NMI. | A blocked AP NMI disappears, arms another CPU's watch, or is suppressed by a maskable priority gate. |

The `nmi-window` native probe has unarmed, direct and restored cases and
records each handler visit. Its restored case covers a stopped CPU record
and reused guest RAM. The coordinator and SDK-model tests exercise selected
CPU routing, VMX controls and publication without executing guest instructions.
[Intel SDM, Vol. 3C, Sections 27.2, 27.3, 28.2.1.1 and 28.6.1.1](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

### Maskable IRQ control at the virtual-NMI revision

The three maskable IRQ cases repeated at `14207bec0fd12e03bc6dcb168b0bb261a3867ffb`
on a virtualized Intel macOS 15.7.9 runner. The unarmed IRQ remained pending.
The direct and restored cases delivered one handler visit each and accepted
EOI. Their observation file is byte-for-byte identical to the earlier control.
The receipt verifies both workflow archives, the signature on the x86-64
consumer and the fingerprints of 4,878 engine inputs. This evidence covers
maskable IRQ behavior on the revision that enables virtual NMIs.
[Hosted job](https://github.com/HexRaysSA/rax/actions/runs/44650128989/job/136002666451)
[Verified receipt](native-irq-window-virtual-nmi-revision.json)
[Guest observations](native-irq-window-observations.jsonl)

### Hosted virtual-NMI entry failure

Attempt 2 of the NMI run used the same signed revision and a virtualized
Intel host with macOS 15.7.9 and SDK 15.5. Framework availability and the
signed consumer passed verification. The first NMI returned exit reason
`0x80000021` before the handler's port exit. Bit 31 denotes VM-entry
failure and the basic reason `0x21` denotes invalid guest state. The run
completed zero of its three NMI cases. The failing field is unknown.
[Hosted job](https://github.com/HexRaysSA/rax/actions/runs/44648442574/job/136020341962)
[Verified failure receipt](native-nmi-window-failure-verified.json)
[Intel SDM, Vol. 3C, section 28.8](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

On a first-handler failure, the probe creates a fresh VM per control
and reports the request result, guest RIP and RFLAGS, and observed exit.
Each control changes one input used by the failing case.

| Assumption under test | Control and falsification probe |
| --- | --- |
| The guest enters successfully with its configured state and no event. | Skip the NMI request and require the initial guest's HLT. |
| The public state projection does not alter VM-entry admission. | Supply the explicit initial state instead of projecting it from the vCPU. Compare the first handler exit. |
| An NMI can enter before the first guest instruction. | Complete a guest OUT first, then inject with IF clear. Compare the first handler exit. |
| IF does not gate NMIs. | Set IF for the cold entry and compare the first handler exit. |

The controls run only after a failure and produce no successful-case
records. The verified failure blocks native NMI qualification in C-HVF.

### Cold entry without an event

The first diagnostic run lost communication with the hosted runner during
guest execution. The signed build survived. The run produced neither guest
observations nor a guest log, so the failure phase within the guest probe
is unknown. [Hosted job](https://github.com/HexRaysSA/rax/actions/runs/44661487412/job/136040528403)

The independent `nmi-baseline` profile uses the same cold VM construction,
IDT and guest state as `nmi-window`. It leaves the VM-entry event slot empty
and requires HLT at the expected RIP, the continuation marker, and zero NMI
handler visits. The assumption that the cold guest state itself permits
VM entry is falsified if that control returns a VM-entry failure. The
baseline runs in its own job and its single observation covers only entry
without an injected event. Each `nmi-window` diagnostic logs its phase before
the host entry call or teardown.

The Intel macOS consumer cross-build linked and passed strict signature
verification with the hypervisor entitlement. All 21 prepared-consumer tests
and 16 workflow checks passed locally. The dispatch choices match the probe's
profile list. The cross-build performed no guest entry.

The `1190a9e3a` hosted Intel run produced one successful `nmi-baseline-hlt`
record with zero NMI handler visits. The signed executable and both archives
matched their digests. The 4,879 engine files and 15 consumer inputs matched
the Git tree. The host reported an untranslated GenuineIntel process inside a
macOS 15.7.9 guest. This verifies the cold setup without an injected event.
Virtual NMI delivery and bare-metal Intel execution remain open.
[Native control](https://github.com/HexRaysSA/rax/actions/runs/44671968208/job/136074789095)

### Phase diagnostics on the hosted runner

The phased `nmi-window` run at `4b2bff026` preserved the signed guest
consumer before entering the execution step. The hosted runner then lost
communication. GitHub retained one build archive and did not publish a
runtime archive. The build archive matched the service's digest. Its
4,879 engine inputs and 15 consumer inputs matched the commit, and the
x86-64 executable passed strict signature verification with the hypervisor
entitlement.

The cold-entry control and the phased probe used byte-identical guest
executables. The control verified entry with an empty event slot. The
phased run yielded no handler count or phase observation, so whether the
first injection or a subsequent diagnostic ran is unknown. Native
virtual-NMI delivery remains unqualified.
[Hosted job](https://github.com/HexRaysSA/rax/actions/runs/44673875789/job/136080967265)
[Verified build receipt](native-nmi-phase-build-verified.json)

### Hot entry and independent SDK control

The signed `nmi-hot-entry` consumer reached its ordinary guest port marker
and completed it before offering the NMI. The next entry failed with reason
`0x80000021`, before any handler port exit. [Hosted RAX consumer](https://github.com/HexRaysSA/rax/actions/runs/44738498804/job/136295848412)

The independent SDK-only program staged event `0x80000202` with guest
interruptibility initially zero. The empty event slot reached HLT, and
the maskable IRQ produced one handler visit, IRET, and continuation. Both
NMI trials, with IF clear or set, failed with reason `0x80000021` and exit
qualification zero. The saved interruptibility value was 8 and no handler
instruction ran. The runner required the virtual-NMI pin control, so the
probe could not test entry with that control disabled. The program uses the
Apple SDK directly. It reproduces the failure on the virtualized Intel
runner independently of the RAX backend. The cause in the host stack and
bare-metal behavior remain unknown.
[Hosted SDK-only control](https://github.com/HexRaysSA/rax/actions/runs/44743699288)

- Tested SDK probe revision `9df2e9c5990415f5ceb0de7ed4c4b07bc3354adf`
- Runtime artifact `14632670471`, SHA-256 `83de7c43dde09996458b492fb503391f6c3f8aa098217acd708b8617a2f39df5`
