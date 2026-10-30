# Native AArch64 checkpoint integration

Native VMM guest startup, scheduled multi-CPU execution and stopped checkpoint
transport are locally qualified on physical Apple Silicon. Guest CPU_ON starts
secondary CPUs; pending power transitions, shared GIC state and in-flight scalar
I/O survive actual `.rxc` files and fresh VMM restoration.

Full C-STATE, C-SMP and C-HVF remain incomplete. Streaming FPSR preservation,
already-entered VM reconstruction, complete clock/timer/debug/replay and writer
coordination, broader I/O/IRQ profiles and physical Intel execution remain open.

## Current qualification

[qualification.json](qualification.json) records exact source manifests, command
receipts, primary sources, assumptions and boundaries.

| Source phase | Executed result | Scope |
|---|---|---|
| v39, final source | 94 portable and 3 signed native tests passed | Power/format/snapshot/configuration; both PSCI conventions/conduits including the 32-bit affinity parameter; SDK PC wrap and owner clocks. |
| v37, before the final argument-width and PC-wrap fixes | 20 signed native checkpoint tests and 1 owner-clock test passed | Guest-driven startup, 1/2/4-CPU file continuation, coordinator execution, pending start/stop, I/O, GIC, rollback and lifecycle; streaming failure explicitly excluded. |
| v36, earlier source | 59 runtime tests passed, 21 native tests ignored | Broader software coordinator, device, storage and private-state file paths. This is not current-source execution of the whole runtime suite. |

The two final production changes narrow AFFINITY_INFO's level argument to its
specified uint32 width and use wrapping PC addition. Earlier represented inputs
have identical behavior; their new edge cases passed on the final signed binary.
Current workspace production-library check, Clippy, workspace format and explicit
owned Rust format checks passed. No full current root library, all-target,
current C API runtime or native Intel execution is claimed.

## Producer graph and admission

A native AArch64 bundle contains the complete ordered public CPU set, one
`HVF_AARCH64_CONTEXT` private record per CPU, one required shared VM record,
and physical memory covering the actual native RAM window. The private CPU
and shared VM records use distinct inner version tags, `RAXHVA04` and
`RAXHVM02`. Required outer section 16 uses `RAXVMC01` framing. Older readers
reject unknown required sections rather than discarding them.

Native public projections have no software keyed execution object. File
admission validates them against typed native records. Standalone and software
snapshot admission retains the keyed-state requirement. Missing records,
foreign producers, differing CPU profiles, public/private disagreement,
inconsistent CPU0 state, and differing RAM/GIC topology are rejected. A
projected low-memory image cannot replace actual native physical RAM.

Native CPU records are limited to 131080 bytes including their eight-byte tag.
Shared framing is limited to 67174400 bytes. The inner shared codec reserves
65536 bytes for topology and IRQ metadata. Lengths are checked before payload
allocation. GIC bytes are opaque SDK state: portable framing does not establish
SDK compatibility.

## Ownership, capture and restoration

One permanent worker creates, accesses, runs and destroys each SDK vCPU. The
front end can move between caller threads. A shared exclusion boundary prevents
native entry, IRQ changes, mapping changes and topology changes throughout
checkpoint capture or restoration. Public/private CPU pairs come from one
owner operation. Shared GIC state is captured once, separately from per-CPU ICC
registers. Mapped guest backing outlives its SDK mapping.

A target register/feature inventory is discovered independently before entry.
Capture includes supported system registers, 32 Q registers, debug controls,
virtual timer mask/offset, SError, supported active SME storage, pending scalar
MMIO reads, undispatched scalar writes, consumed reply data and deferred destination-write errors. New SDK
APIs are resolved when complete checkpoint support is inspected; missing APIs
prevent complete checkpointing without importing newer symbols at backend load.
Optional ZT0 presence follows the independently recorded SME2 capability.

The SDK SIMD setter takes a C vector argument. A leaf AArch64 assembly wrapper
loads that value into V0 before tail-calling the SDK function. A Rust byte-array
aggregate does not have the equivalent calling convention.

`Vmm::new_resume_bundle` constructs a fresh native destination. Admission is
repeated under the stopped backend boundary. The transaction backs up all CPU
records, shared GIC state and physical memory, then restores CPU architecture,
RAM, shared GIC state and per-CPU ICC/TLB state. Device, clock and coordinator
publication follows successful backend restoration. On failure, the backend
restores the backups; a failed rollback disables further native entry.

The SDK specifies GIC restoration before any destination vCPU has entered.
Restoration into an already-entered native VM therefore rejects before mutation.
Reconstructing a running native VM for in-place restoration remains unfinished.
Bare CPU projections and standalone private CPU imports cannot replace the
coordinated CPU/RAM/device transaction.

An outgoing scalar MMIO store retains its address and complete operand after PC
advance. Native entry re-emits that store until successful caller dispatch is
acknowledged through `VCpu::complete_io_out`. The VMM acknowledges only after
its output dispatch succeeds. The typed private record preserves the pending
store through a real file and rejects conflicting input/output transactions,
invalid scalar widths and wrapping output extents. Native schema 04 is required;
the earlier experimental native schemas are rejected. The v12 signed native test passed real file restoration, repeated pending
exits, actual VMM device dispatch/acknowledgement and guest PSCI shutdown.

A failed native destination-register write preserves the full device reply.
After file restoration, the original error is surfaced, then the same reply is
retried without performing another device read. Short replies retain the request.

## Executed validation and limits

The frozen v8 root library test binary passed six portable native-format,
65 snapshot and 11 configuration tests. Five explicitly selected ignored native
tests passed on physical Apple Silicon after signing the actual root test binary
with `com.apple.security.hypervisor`:

- Actual 1-, 2- and 4-CPU VMMs saved and loaded real `.rxc` files, restored fresh
  native VMs, completed pending eight-byte MMIO loads and executed guest
  continuations. The files contained 32 Q registers per CPU, ESR/FAR, timer
  compare values, shared SDK GIC bytes and IRQ output levels.
- An injected SDK-boundary destination-write failure preserved consumed PL011
  data through a real file. Restoration retried that data and left the next
  input byte unread. This is injection evidence, not a naturally observed SDK
  register-write failure.
- A real SDK rejection of a deliberately invalid opaque GIC image occurred
  after CPU/RAM restoration. Rollback preserved both CPUs' private state,
  shared GIC/IRQ state and destination RAM.
- CPU destruction closed surviving front ends before more SDK entry.
- A natural short read reply reported incomplete status; a full reply completed.

Portable tests use synthetic CPU storage and opaque GIC bytes. They establish
framing, coherence, rejection and file persistence, not native execution.
The earlier v4 runtime run passed 59 tests with two native tests ignored, then
those two were executed explicitly on its signed binary. That result is not a
full runtime execution against the later restoration changes. Complete affected
library/workspace and relevant feature/platform gates remain required.

The v9 signed run passed seven native tests and failed one newly added SME
execution test. Full private-state equality before 1/2/4-CPU continuation,
failed-rollback poisoning and legacy-projection rejection passed. The new SME
test assumed WFI would stop execution. A direct SDK probe demonstrated continued
execution past WFI with SME active; the test then reached uninitialized code.
The corrected guest uses explicit PSCI SYSTEM_OFF. This test correction is not
a native SME restoration fix; its four-mode execution remains under v12 validation.

Two additional pre-fix regressions were observed: a completion error without
its consumed reply was accepted, and an undispatched native store disappeared
through a real file. The missing-reply correction passed all eight v10 portable
native-format tests; 65 snapshot and 11 configuration tests also passed.
An initial v10 configuration filter selected zero tests; only the corrected
`config::` run counts as execution. Schema 03 and store acknowledgement are
under v12 validation, including actual VMM device dispatch and guest continuation.

## Primary sources

Exact SDK headers and retrieval provenance are retained under
[the macOS 27.2 Hypervisor SDK reference](../../specifications/apple/hypervisor-sdk-27.2/provenance.json).
Relevant contracts are `hv_vcpu.h` (owner thread, SME transitions and timers),
`hv_vcpu_types.h` (handle/vector ABI), `hv_gic_state.h` (stopped capture and
shared blob contents) and `hv_gic.h` (restore before entry and ICC registers).

[Primary Linux register metadata](../../specifications/arm/native-context-feature-registers/provenance.json)
identifies `ID_AA64SMFR0_EL1.SMEver[59:56]`, with encoding 1 introducing SME2.
Apple's headers identify the 64-byte SME2 ZT0 register and its ZA-enabled access
contract. Two pre-fix decoder tests reproduced missing/unsupported ZT0 admission;
the corrected v6 tests passed.

## Assumption register

| ID | Assumption | Stress test and falsification probe | Status |
|---|---|---|---|
| N1 | Stopped owner operations coherently capture and restore native public/private state. | Compare every field before guest continuation and execute across all streaming/ZA modes. | v9 full private-state comparisons and scalar continuation passed; v11 corrected active SME test pending. |
| N2 | Complete native files require independently admitted CPU/backend/VM and physical RAM records. | Remove records, alter identity/profile/projection/topology, and replace native RAM with a low-only image; require rejection before publication. | Represented v8 admission tests passed. |
| N3 | A late shared SDK error can restore the prior CPU/RAM/GIC state. | Submit well-framed invalid SDK GIC bytes after changing source CPU/RAM/IRQ data; compare every target private record and RAM after rejection. | v8 actual SDK rejection and rollback passed. |
| N4 | Consumed input survives a failed native destination write. | Inject one write failure, save/load a real file, resume, and verify that the next PL011 byte remains unread. | v8 passed. |

The exact 2025-12 [ZERO (tile) instruction XML and notice](../../specifications/arm/native-context-feature-registers/sme-zero-provenance.json)
are retained unchanged from the previously pinned Arm archive. The operation
checks SME/ZA enablement and clears the selected ZA tiles. LLVM MC independently
provided the guest instruction encodings.

## Streaming FPSR counterexample

The corrected v12 SME test passed both non-streaming modes, including actual
ZERO {ZA} after real file restoration. In streaming mode, the pre-entry SDK
getter returned FPSR=1, but guest continuation and the post-entry getter exposed
`0x0800009f`. Z/P comparisons passed before this FPSR assertion failed.

Direct SDK probes reproduce the difference independently of RAX. Guest MRS and
the SDK getter agree. Writing FPSR through the SDK again does not preserve 1 on
re-entry. A guest SMSTART/MSR FPSR/MRS FPSR sequence observes 1 within one entry;
a later entry beginning at MRS, without a guest mode transition, observes
`0x0800009f`. The raw architectural FPSR encoding is not accepted as an SDK
system-register alternative. These observations do not establish a working
native entry/restoration path; complete streaming checkpoint continuation
remains unfinished. The failing test is retained.

The SDK header documents FPSR effects of streaming-mode changes. The retained
[Arm SME supplement, DDI0616 B.a](references/arm-sme-ddi0616ba.pdf),
B1.2.1 rule RMHTLZ on page 32, specifies FPSR=0x000000000800009f when the
effective value of PSTATE.SM changes. Neither contract establishes that ordinary
hypervisor re-entry should act as a guest mode transition. The diagnostic is
scoped to this physical host and SDK. The earlier reference to the local generic
SVE pseudocode did not establish this SME rule and has been corrected.

## Bounded findings

- High: guest-visible streaming FPSR preservation fails on this host, including
  direct SDK re-entry. A working entry/restoration path remains required.
- High: native counter epochs, absolute timer values and active timer/IRQ state
  require explicit continuation semantics and execution evidence.
- High: scalar input/output and the represented active UART SPI case now have
  native file-continuation evidence. Broader I/O profiles and independently
  concurrent device writers remain unfinished requirements.
- High: streaming FPSR, active timer/IRQ continuity, entered-VM reconstruction
  and broader I/O profiles still require their full final evidence.
- High: guest-driven two/four-CPU native startup and coordinator continuation
  are qualified. Full bounded scheduling, debug and replay semantics remain open.
- High: physical Intel HVF evidence remains absent.
- Medium: a null SDK GIC-state object now uses the same null-safe owner as GIC
  configuration; the injected null-return branch has not been executed.

## Historical terminal gates

The v12 format/snapshot/configuration selections passed 9/65/11 tests. The signed
physical native selection completed with eight passed, one failed, zero ignored.
Its failure is the retained streaming FPSR assertion. Both non-streaming modes
passed; the streaming ZA-enabled fourth mode was not reached after the third
mode failed. Complete workspace/all-target checking passed, including C API
compilation. The complete unfiltered archived v12 root library test binary finished with
11376 passed, zero failed and 11 ignored in 4652.04 s. This qualifies the frozen
v12 source, not the later schema04 changes. No completed semantic-group commit has
been made, and all four audit findings remain open.

## Native register-overlay correction

The v13 signed regression observed an unserviced MMIO read disappearing after
an unrelated X5 edit through `update_state`. The native front end inherited the
default implementation, which delegates to `set_state` and cancels pending I/O.
The v14 override applies the owner-thread public register overlay directly.
Explicit successful `set_state` replacement retains its cancellation semantics.

The corrected physical native test passed unserviced-read, consumed-reply and
unacknowledged-write cases. Complete private native Context equality allows only
the intended X5 change; rejected EL2h overlays leave the whole state unchanged.
All 85 focused format/snapshot/configuration tests passed again. These are v14
results, distinct from the archived v12 full-library run.

The native-only build uses a task-local pass-through workspace wrapper to obtain
a different Cargo executable filename in the same cache. This preserved the
then-running v12 executable. The official
[Cargo environment-variable contract](references/cargo-environment-variables.html)
and its [retrieval provenance](references/cargo-provenance.json) are retained.
No global Cargo configuration or compiler flags changed.

## Active SPI qualification

The direct SDK probe acknowledged group-1 level-sensitive SPI 33 at priority
0x80, saved and restored active GIC state, and observed reassertion after EOI
while the input remained high. Deassertion followed by EOI produced spurious
IAR 1023 and RPR 255, with no active/pending bit. The v15 signed physical RAX VMM/file test passed (one selected test,
zero failures or ignores). Its [guest source](active-uart-spi.s) and independent LLVM
[encoding provenance](active-uart-spi-provenance.json) are retained. It combines
PL011 receive state, a pending FR read, active GIC priority, real `.rxc` restore,
actual VMM input dispatch and IRQ deassertion. Before and after file restoration
the complete private CPU contexts agree. Guest EOI/IAR observes SPI 33 again
while the UART level is high; consuming byte 0xab through the VMM then lowers
the line, and the next EOI/IAR observes spurious 1023 and running priority 255.
The final UART state and backend IRQ shadow both record deassertion. This masked-IAR fixture does not
establish exception-vector delivery or architectural SMP startup.

## Terminal native CPU state

The v16 signed physical baseline failed after restoring a real SYSTEM_OFF/HVC
file: the next CPU run did not retain its terminal Shutdown result. That first
assertion did not print its unexpected exit or PC, so this receipt alone does
not establish post-shutdown marker execution. Later variants were not reached.

The corrected implementation adds a private shutdown latch, includes it in
experimental CPU schema 04, restores it through the coordinated transaction,
and reports Shutdown before another SDK entry. Ordinary register overlays
retain this state; explicit `wake` and successful `set_state` replacement clear
it. Terminal records reject unfinished input/output transactions. The v17
physical test passed all four variants (one selected test, zero failures or
ignores). Repeated terminal runs preserve the complete private context; register
overlays retain the latch, and both explicit restart APIs execute the marker.
The portable selection passed nine tests and failed one stale fixture that
used version 4 as its unknown tag. That literal is now invalid `?`. The v18
format/snapshot/configuration selections passed 10/65/11 tests, and workspace
formatting passed. The actual active UART/GIC VMM/file continuation also passed
again with schema04. Only the portable fixture differs between v17 and v18 Rust
inputs; the four-case native terminal test was not redundantly re-executed. No complete-group or
full-library v17 passing claim follows from the native result. The independently assembled
[HVC/SMC streams](terminal-psci.s) and their [provenance](terminal-psci-provenance.json)
cover SYSTEM_OFF and SYSTEM_RESET. Explicit embedding restart is not a claim
that a complete architectural cold boot has been implemented.

## Register APIs, helper validation and CPU lifetime

The earlier blanket teardown policy was a RAX regression. A signed direct-SDK
pthread control executes a surviving CPU after a peer is destroyed, then
recreates CPU 0 in the same VM after its original owner exits. The public RAX
regression failed after peer destruction in v22 and passes in v23. Destruction
now releases that logical identity after the permanent owner joins; surviving
CPUs retain the VM and mapped backing. Actual failed owner teardown still
poisons subsequent operations, and incomplete CPU sets still reject complete
checkpoints. VM-destroy failure retains mapped backing rather than freeing it;
that rare failure branch was source-reviewed, not fault injected.

The MMIO helper now creates a fresh VM per independent case to isolate guest
and controller state. The maintained state/MMIO CLIs passed in v21, including
63 state-verifier mutations, and both native helpers pass on the v23 library:
12 state cases plus invalid-mode rejection, and 108 MMIO loads with 216 short
replies, 216 repeated pending exits and explicit state replacement. The tools
use Cargo's reported archives, verify signatures and remove temporary native
executables without copying library archives into evidence.

The earlier review overstated a second setup requirement. Live `create_vcpu`
permits an unconfigured topology, and `admit_memory` checks backing identity
only when a mapping exists. The unconfigured/unmapped state helper therefore
remains an intentional register-API compatibility control. Its v23 runtime
result passes. Complete checkpoint capture has stronger graph
requirements than standalone register access.

The software AArch64 shutdown overlay and native PC-only write regressions fail
in v19 and pass after correction. v23 passes 14 ordinary owning integration
tests and both explicitly selected signed native tests, covering pending input,
pending output and terminal PC updates as well as peer destruction, identity
reuse and retained-VM execution. The C API shutdown/explicit-restart regression
passes in the 224-test v21 C API suite; that suite predates the v23 native
lifetime edits. The root VMM peer-lifetime test and new startup-failure test pass in v24;
complete current root-library/platform gates remain pending. These results do not close the
streaming FPSR counterexample, entered-VM reconstruction or architectural SMP.

## Validation cleanup

Native validation through v23 is terminal. The single Cargo cache and scratch
root were deleted at 06:44 UTC after process/open-handle checks, removing
1133 files and 3043192832 allocated file bytes. Repository source/index
fingerprints and original guest processes 28735/28737 were preserved. Exactly
the original checkout and one integration worktree remain. Subsequent active
A32 validation reuses the same single cache location; remove it when idle.


## Native construction ownership, v24

The SDK handle now becomes an owned core immediately after successful
allocation, before MPIDR setup or kick-thread creation. Later constructor
errors and unwinds therefore run the permanent owner's destructor. This also
uses the existing failed-destroy VM poison path for rejected initialization.
Kick-thread creation uses the fallible
[Rust Builder API](https://doc.rust-lang.org/std/thread/struct.Builder.html#method.spawn);
[the retained standard-library references](references/rust-thread-provenance.json)
document its distinction from the panicking free `spawn` function. The SDK
owner-thread destruction contract is retained in `hv_vcpu.h`.

v24 builds the actual root library test executable and passes 86 portable
format/snapshot/configuration tests. The explicitly selected signed native
peer-lifetime and injected kick-startup failure tests pass. The latter proves
peer access, logical-ID reuse, complete capture and subsequent VM allocation
after the injected error; actual OS resource exhaustion was not reproduced.
The real-file test passes one/two/four-CPU continuation, including recycling
CPU1 before capture in the two- and four-CPU sources. All restored private
contexts compare equal before pending MMIO completion and guest continuation.
Normal production-library check and Clippy pass across the workspace, including
C API compilation. This is not a complete root-suite or C API runtime result.

The stronger v25 case recreates logical CPU2 before CPU1 in a four-CPU VM.
Only the test fixture changes from v24; production sources remain identical.
It passes the signed native file test: all four restored private contexts
compare equal and every CPU completes its pending read and executes its guest
marker. This observes logical creation order, not internal SDK handle allocation.
Across v24/v25 there are 86 portable passes, four selected signed-native test
passes and four retained actual checkpoint files. Earlier production checks are
reused because only the test fixture changed in v25. The checkpoint group
remains in progress, including streaming FPSR, entered-VM restoration, complete
clock/timer/writer coordination and actual native SMP requirements.


## Native coordinator and owner clocks, v30/v31

Native owner requests now forward the caller's timing context explicitly and
remove that binding at request completion. The signed owner test checks two
nested contexts, exact manual retirement publication and a subsequent unbound
request. This is a worker-binding test, not a native hardware retirement meter.

The actual signed root executable passes 15 selected checkpoint tests, plus
that owner test. This includes the previous restore/rollback, active PL011 SPI,
shutdown, pending I/O and owner-lifetime cases. New two/four-CPU tests execute
guest RAM writes and MMIO through actual coordinator turns, save actual `.rxc`
files, restore through `Vmm::new_resume_bundle`, preserve a nonzero cursor and
continue all online CPUs. Another test verifies SDK-GIC-handled WFI returns to
the coordinator. CPUs are prepared online explicitly: native PSCI startup is
still open. Cancellation does not claim retired instructions.

There are 86 selected portable context/snapshot/configuration passes. The
complete retirement-budget and timing binaries pass 16 and 12 tests. Workspace
library check and Clippy pass; these are not a complete current root-suite,
all-target-link, doctest or C API runtime result. Native inputs are frozen in
`coordinator-v30-source.json`; they remain unchanged by the later A32 SIMD base
admission commit, whose own complete targets are separately qualified.

The separately rerun streaming test still fails: FPSR1 becomes guest-visible
`0x0800009f` with SM enabled. Non-streaming ZA-off/on phases pass before that
failure. Streaming ZA-on is not reached; no streaming fix is claimed.

An exploratory exact-budget implementation was withdrawn after independent SDK
controls exposed GIC-handled WFI: the SDK advances PC, retains the step bit and
waits internally; cancellation followed by another entry can execute the next
instruction before a software-step exit. The proposed kick-exclusion lock also
prevented return from that wait. Raw v29 failure/sample, source archive and SDK
v7/v8 controls are retained. This falsifies that candidate on the tested M4 /
macOS27.2 combination; it is not a general impossibility claim. Native exact
retirement, startup, debugger CPU selection, clocks/replay, entered-VM restore
and full timer/interrupt/writer coherence remain open. Intel peers are still
offline, with processor types unknown.

The durable receipt is `coordinator-qualification-v31.json` under the native
checkpoint evidence directory. Build and scratch directories are removed after
all phase processes terminate; source, raw failures and pinned tools remain.


## Native PSCI startup and power graph

The native ARM virtual platform exposes flat Aff0 CPU identities and AArch64
EL1. Guest `CPU_ON` (SMC32 or SMC64 convention, through HVC or SMC) requests
secondary entry; the coordinator installs the owner-thread CPU entry and only
then marks that CPU online. SMC32 arguments are truncated to 32 bits without
changing the caller's AArch64 execution state. Reserved affinity bits,
out-of-topology CPUs, unaligned entry points and entry points outside mapped
RAM reject. `AFFINITY_INFO` supports affinity level zero; duplicate startup
returns `ON_PENDING` or `ALREADY_ON` according to the retained transition.

Startup uses EL1h with DAIF masked, X0 containing the context identifier,
SCTLR_EL1.I/C/M clear, and SCTLR_EL1.EE copied from the requesting CPU.
The SDK-created SCTLR platform value supplies the other initial control bits.
SME mode, public architectural storage, timer controls, consumed input,
unacknowledged output and deferred I/O errors are initialized before startup is
acknowledged. Previously entered CPUs require the SDK TLB invalidation API
for restart. That API is available from macOS 27; older-host hotplug execution
has not been established. Startup resolves these operations independently of the
complete checkpoint API set.

`CPU_OFF` stops the calling CPU without a VM shutdown. Its pending stop blocks
further native entry until the coordinator removes it from the online set.
`SYSTEM_OFF` and the existing reset-as-shutdown behavior apply to the whole VM,
including a request made by a secondary CPU. Explicit `wake` and state replacement remain
the public restart operations; register overlays retain the terminal state.

Shared native version 02 retains ordered start/stop requests, per-CPU power
states, the caller's endianness for each pending start and VM-wide shutdown.
Requests are inspected without consumption and removed individually after
successful publication. A partial startup failure leaves every unacknowledged
request available for retry and checkpointing. Bundle admission checks the power
graph against the coordinator's online set. Native file completion also requires
the coordinator and VM clock sections. Earlier experimental version 01 records
lack this information and are rejected explicitly.

The primary contract is [Arm DEN 0022D](../../specifications/arm/psci-den0022.pdf),
sections 5.5-5.7 and 6.4. The new signed native regressions cover actual guest
startup, two- and four-CPU coordinator execution, CPU2 publication failure with
CPU3 queued, pending start/stop file restoration, CPU power-off/restart, both
calling conventions/conduits, data endianness and secondary-initiated shutdown.
Their current execution receipts are maintained in the audit ledger; source
presence alone is not native execution evidence.

Power graph validation uses O(n) time and O(n) scratch space for n CPUs.
Transition publication/removal uses O(n) time; retained requests and states use
O(n) space and contain at most one pending transition per CPU (n <= 255).


The v35 endianness regression initially assumed that this Apple M4 Max guest
profile could execute with EE=1. Its target assertion failed. An independent
signed SDK probe read ID_AA64MMFR0_EL1=0x10000f100022 (BigEnd=0, not implemented):
the SDK initially accepted SCTLR_EL1.EE=1, but native entry cleared that bit and
the guest MRS observed EE=0. The corrected test compares the target to the
caller's actual execution mode and records the feature value. This host proves
little-endian startup only; portable graph tests separately preserve pending
big-endian metadata. The raw failure and both independent probe versions remain
retained rather than being converted to a native big-endian coverage claim.
