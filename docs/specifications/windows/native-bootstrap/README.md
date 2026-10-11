# Installed Windows loader startup

Native-library mode now enters the selected installed NTDLL LdrInitializeThunk
with a saved architecture CONTEXT before DLL/TLS/application execution. Its
public PEB.ProcessHeap, PEB.Ldr and initial TEB.ThreadLocalStoragePointer remain
zero for RTL initialization. The host's HLE heap and module lists remain private
mapping/parameter bookkeeping. Built-in DLL mode retains its existing synthetic
thread lifecycle and published HLE data.

Baseline RAX:19dc289d75cb02cdf5e22d7f91a278ed9b591985; owning Assist root:
fcf698e3f626572742ddbf761ffdcc1105246787. Owning C++ source remains
c4cb8f6a0dd7c0d068d2defd411599fba9e32b7e; subsequent root commits change only
engineering records and the Gitlink. Eight compiled source identities are frozen
in source-hashes-reviewed.json. No public ABI, dependency, ISA, default, schema,
permission, persistence or packaging contract changes.

## Independent initial-state and entry evidence

Six suspended controlled-child captures cover initial PEB/context and separate
TEB observations on ARM64, x64 compatibility and x86 WoW64. Each initial process
heap/loader/TLS pointer is0, each main parameter is the process PEB, and each
never-resumed child is terminated and waited successfully. CONTEXT sizes are
912/1232/716 bytes. These profiles share a Windows11 ARM64 build29683.1000 host;
x64 compatibility is not physical x64 kernel proof.

Fresh child-only COW breakpoints independently capture the loader arguments on
ARM64 and WoW64: saved CONTEXT and that child's NTDLL allocation base. The
producer drains EXIT_PROCESS_DEBUG_EVENT and confirms termination before closing
its original handles. The initial ARM64 capture has valid arguments but a wait
timeout before exit-event draining; its original producer/output are retained
as a separate failed-cleanup phase. The x64 compatibility capture fails to reach
the callable export and exits4. It supplies no loader-argument evidence.

| Profile |Initial live thread RVA |Live captured loader RVA |Selected on-disk loader RVA |Limit |
|---|---|---|---|---|
|ARM64 |0xE4D30 |0xEF6E0 |0xEF6E0 |Native host capture |
|x64 compatibility |0x23BB30 |unknown |Not admitted as pure x64 by ARM64 runtime |Callable compatibility target0x317880 was not captured |
|x86 WoW64 |0x1BFFB0 |0x17C0 |0x2EEA0 |Live compatibility rewriting differs from file export |

Compatibility-only live entry offsets must not be copied into mapped file
exports. The emulator resolves the selected file's LdrInitializeThunk and
RtlUserThreadStart exports, checks both are in its native executable mapping,
and caches them only after both succeed. Missing/wrong-module/non-executable
exports fail without HLE fallback. Main saved start parameters become PEB;
secondary start parameters and full integer/FPU state remain preserved.

The pinned PHNT declarations and primary Microsoft API/ABI references are in
primary-contracts.md. Selected ARM64/x86 loader bytes consume two arguments and
call NtContinue with TRUE. The x86 file's RtlUserThreadStart moves EAX/EBX to
the caller-stack argument positions. selected-entry-contracts.json retains only
bounded entry bytes and exact private DLL identities. Physical pure x64 entry
stack evidence is unknown; the8-byte return slot is an explicitly retained
inference from Microsoft's callable-entry ABI.

The original ordinary fault is independently bounded by the selected ARM64 PE
exception table/xdata and matching Microsoft PDB: RtlpAllocateNTHeapInternal
RVA0x26450..0x267B0, exclusive end,864 bytes; fault RVA0x26528 is+0xD8.
RSDS GUID matches the PDB, RSDS age1 matches DBI age1, and information-stream
age4 is distinct. ntdll-fault-provenance.json and original bounded PDB identity
retain the proof. Searching for the first raw RSDS byte sequence was falsified
by an instruction-byte coincidence; the final identity uses the PE debug directory.

## Context lifetime and scheduling

The saved CONTEXT sits below the application's saved SP and above the loader's
call frame. All scratch arithmetic/access is checked before context/frame or
CPU publication. CONTEXT plus caller scratch is bounded to780..792 bytes on
x86,1304 on x64,976 on ARM64. A fixed80-byte frame-zero buffer suffices; no VM
scratch allocation is introduced. Context/frame placement is O(1) for these fixed ABI
sizes; the first thread also pays the existing module/export lookup cost. Calculations and alignment rules are reproduced in primary-contracts.md.

A thread becomes attached only when its resumed PC equals the cached native
RtlUserThreadStart entry. That boundary releases the existing initial-process
scheduling gate and dispatches no host DLL/TLS callbacks. A peer remains
unattached until its own loader reaches that boundary. Native Rtl exit routes
use NtTerminateThread/NtTerminateProcess outcomes, avoiding duplicate synthetic
normal-exit notifications. This source ownership review does not establish
successful application startup or shutdown.

Eight portable behavioral tests cover all three guest ABIs: main/secondary full
context and stack layout, read-only scratch and underflow, private loader data,
native TLS with independent built-in control, required exports, exact attachment
boundary, and actual scheduler selection. One Windows-only test observes installed
ARM64+WoW64 process construction before its first instruction, checking cold
PEB/TLS, private allocator survival, installed loader PC and saved main context.
It does not run the whole native loader.

Two observed regressions fail with the corresponding baseline source restored
alone: native PEB.Ldr and native static TLS each publish0x10A40 instead of0.
The overlays affect only owned files, and reviewed bytes are restored in finally.
Their snapshots/hashes are intermediate phases, separate from final eight-source
identities. Formatting preserves all final compiled source hashes.

## Assumptions and change surface

assumptions-and-scope.md retains the complete B1..B5 register, stress tests,
falsification probes, phase corrections and bounded findings. B1/B5 are confirmed
for all three selected initial-state profiles. B2's two-argument/NTDLL-base
contract is confirmed by ARM64/WoW64 entry captures; pure x64 callable-stack and
compatibility-to-file-entry correspondence remain retained/unknown.

| Plane |Status and evidence |
|---|---|
|Plugin lifecycle |Unaffected: guest construction only; no plugin/profile/IDB changes |
|UI state |Unaffected: no Qt/widget/copy changes |
|Conversation/lane |Unaffected: existing process result/error/cancellation contracts |
|Agent backend |Unaffected: native/ACP request contracts unchanged |
|Prompt/context |Unaffected: no prompt or IDB context source changes |
|Tool schema |Unaffected: existing process names/schema/metadata |
|Permission/mutation |Unaffected: installed-file scope retained; no host kernel forwarding |
|Main-thread dispatch |Unaffected: guest memory/CPU only; no IDA/Qt API |
|Mesh/MCP |Unaffected: transport/discovery/identity unchanged |
|Transport/crypto |Unaffected: no transport, key or crypto edits |
|Persistence |Unaffected: no schema/settings/history or persisted format change |
|SDK/ABI |Unaffected: C API1.11.0; owning ABI/archive consumers validated separately |
|Optional engines |Unaffected: decoder/ISA/lifter/SMIR/lowering/JIT/device policies unchanged |
|Update/release |Unaffected: no pin dependency refresh, version/default/package policy change |
|Targets/platforms |Affected: shared Rust source/test registration on Windows/macOS/Linux; installed-file acquisition remains Windows-only; owning archives/process consumers |
|Tests/docs |Affected: native startup tests, controlled-child producers/replay, engineering records/Gitlink |

High: class107 relationship6 and wider NT services, including alertable
NtContinue, remain full-native-startup dependencies. Pending APCs must not be
dropped or represented as completed. Wider application/native IDA/Qt/package
validation remains incomplete. Medium: five retained Windows lowering failures
limit broad-suite results; earlier Linux timeout failures have an unknown cause
although this group's complete Linux run passes; physical x64 Windows kernel proof is absent. Linux
x86-64 validation runs under container translation on the ARM64 host. These
limits are recorded; no nonblocking adjacent subsystem is changed.

## Reproduction

Run python3 check_native_bootstrap.py with --source-root pointing to this group's
frozen RAX checkout after later source changes. The mandatory byte manifest,
native producer identities, primary provenance, red/green phases, ordinary
observer identity, owning archive/core/source coherence and recorded gates are
checked independently. Missing manifests, tampered records and Python -O must
fail. Replay does not execute an oracle or a build.

The original capture drivers record their selected host paths and compiler setup;
they are not portable provisioning scripts. Initial PEB-only drivers expect the
initial producer copied to their native-startup-probe.cpp input name. TEB drivers
expect the final producer at that same name; loader-entry drivers use their own
producer. Native helper sources are copied/hash-verified from the owning Windows
host. PE machine/hash identities are retained without executable bytes. No DLL,
PDB, EXE, complete symbol list or complete disassembly is redistributed.


## Recorded final gates and ordinary execution

|Host/environment |Startup |Full pass/fail/ignored |C API |All targets |Integration |
|---|---|---|---|---|---|
|macOS ARM64 native |8 |7596/0/2 |168 |pass |Windows fixtures544; Windows memory cfg0 |
|Linux x86-64 container under ARM64 translation |8 |7590/0/2 |168 |pass |Windows fixtures544; Windows memory cfg0 |
|Windows ARM64 native |9 |6989/5/2 |168 |pass |Native Windows memory4; Unix fixtures cfg-excluded |

All five owning C++ consumers pass on all three hosts. macOS CLI/MCP rebuild,
seven selected CTests and two protected-text scans report zero failures. Windows
process-tool182 checks and process ABI162 checks pass, as do disabled-engine
refusal, ABI1.11 drift and allocator/panic/unwinding through the single Rust
archive. Exact21 gates, summaries, five Windows lowering failure names and
compiled-source identities are in validation.json. Original full-suite logs stay
in task storage; compact retained summaries identify selected tests, failures
and counts with original/recorded byte hashes in gate-recording-provenance.json.
These checks are separate from native IDA/Qt/package execution.

Fresh native owning Assist/core archives pass full4673/260-member structural
walks. Their SHA256, lengths, eight matching source hashes and empty core
features are in native-owning-archive-hashes.json. Cargo JSON identifies the same
current core linked by the ordinary observer and embedded into Assist.

The byte-identical ordinary observer changes from the original first-fault1459/
access-violation exit1500 to initial ProcessHeap0, no exception, and explicit
unsupported NtQuerySystemInformationEx class107 relationship6 at40500. The
change is40500-1500=39000 additional scheduler calls, not an instruction count.
Four ordinary fresh-archive programs (smoke, MSVCRT/UCRT streams, whoami) reach
that same unsupported service. Their C API reason5 is internal failure; the
exit_code0 field does not mean successful guest exit. This establishes ordinary
loader-entry/heap ownership progress, not completed native userland.

The first exception's symbol identity and these unmodified startup results
supersede the previous query group's bounded unknown-routine/manual-startup
limits. They do not retroactively turn that earlier group's ordinary AV into
successful startup. Wider NT services, alertable NtContinue and the parent
application/platform/package matrix remain outstanding.

|Quality gate |Startup-group evidence |
|---|---|
|QG1 |No normative judgment needed |
|QG2 |B1..B5 register reconciled; pure x64 inference/failed capture explicit |
|QG3 |Entry/PEB/TLS/context/scheduler behavior and before/after ordinary execution covered |
|QG4 |Exact byte/alignment/range arithmetic; scheduler counts distinguished from instructions |
|QG5 |Phase corrections, compatibility offsets and broad-suite failures exposed |
|QG6 |Pinned PHNT/license, native captures, matching PE/PDB, source/archive identities verified |
|QG7 |High remaining NT/application blockers and medium host/test limits bounded |

RAX's additional worktree, behavioral-evidence and repository-consistency gates
are covered by exact owned paths, all affected Cargo/owning targets, frozen
sources, schema/default/ABI preservation and the independent replay. Completion
applies to this semantic startup group; the full userland goal remains active.
