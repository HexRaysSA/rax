## Current increment: native performance-counter query (2026-10-14)

`NtQueryPerformanceCounter` uses measured sequential caller stores and one
clock source across native/public timing and shared frequency. See
[the counter contract and evidence](../../specifications/windows/native-performance-counter/README.md).
Ordinary CRT programs now require process-information class35; full completion
remains unproved.

## Previous increment: selected image-section mapping (2026-10-14)

`NtMapViewOfSection` creates guest image views from pinned installed Sections,
with native/WoW64 fault ordering, image relocation, partial/large-page geometry
and close/unmap lifetime. See [the mapping contract](selected-image-section-mapping.md)
and [native evidence](../../specifications/windows/native-section-map/README.md)
for measured scope and final validation. Full ordinary Windows completion
remains an active, unproved requirement.

## Previous increment: installed image-section opening (2026-10-13)

`NtOpenSection` appends a stable native export and returns typed guest image-section
handles from the selected installed KnownDll namespace. Acquisition closes native
handles and retains bounded authorization, case-policy, attributes and extent
metadata. All 93624 captured open/duplication rows replay through shared service
paths. WoW64 direct-root CHPE selection and write-specific guard copyback are
measured separately from directory/link behavior. No guest section query, image
mapping or complete ordinary guest exit is claimed. Final platform/owning gates,
assumptions, identities and ordinary continuation are separately recorded in
[section-open evidence](../../specifications/windows/native-section-open/README.md).

## Previous increment: absent thread-token opening (2026-10-13)

`NtOpenThreadToken` decodes all four ABI arguments, validates the thread handle,
object type and either query grant0x40/0x800, then returns STATUS_NO_TOKEN0xC000007C
in the current personality without token attachments. Missing handles, wrong
objects and absent query grants preserve captured INVALID_HANDLE/type/access
precedence. DesiredAccess/OpenAsSelf cannot reach an ACL decision without a
thread token. Token attachment/class5 remains explicitly unsupported; native
positive token births are retained as contrast controls, not emulated success.

Native64 failure output pointers are untouched. WoW64 skips null output;
nonnull output is zeroed4B even after kernel failure. Copy faults override
status; writable guards consume once, readonly guards remain armed, and
cross-page faults leave no partial store. The constructor's existing write
protection/guard policy is extracted unchanged and shared; the thread-slot
setter retains its separate regular guard policy. RTL translation returns1008.

13 actual native producers retain26352 full mature observations,6192 absent
replays,80 absent signed/zero-extended negative pseudo rows and96 cross-page
rows. Two complete fresh ARM64 original SVC36/true-LR cases preserve output8B
and exact parent handle sets; child77 is a capture stop. Four portable and five
Windows focused tests include actual installed ARM64/WoW64 leaves/RET16. The
checker rejects33 rehashed controlled semantic/provenance falsifications.
Full gates, current archive/source identities, assumptions, both plane maps and
ordinary observer evidence remain separately owned by
[thread-token evidence](../../specifications/windows/native-thread-token-open/README.md).
C API1.11.0, Assist ABI, dependency/default-feature contracts are unchanged.
Physical x64 kernel/other builds and whole current-root plugin/GUI/packages
remain unknown/excluded. The overall full-process goal remains active.

## Previous increment: scheduler shared-data thread slot (2026-10-13)

NtSetInformationThread class57 binds the current thread to a guest-owned
SchedulerSharedData resource. Native24B/WoW12B Action/owner/slot layouts preserve
native full writable-probe and WoW length/read/kernel/copy ordering, including
hidden binding after output-copy failure. Thread access0x20 and owner access0x1
are required. Free ignores caller owner/slot; assignment validates the owner
before bound/noncurrent NOT_SUPPORTED. Other actions retain measured failures.

Each owner lazily reserves8192B MEM_MAPPED RW and commits4096B initially.
Its128 lowest-free64B slots commit the second page as needed; the129th binding
fails with C000009A. Free preserves bytes; assignment zeroes64B. Handles and
thread bindings independently retain the owner; final release/exit/drain retire
its view. Partial drain consumption is covered. Allocation identity prevents
ABA reuse from clearing/freeing a replacement view. Explicit native unmap
retains the cached returned address. No guest request calls host NT, and no
unverified TEB offset or kernel counter/timing behavior is introduced.

26 actual native producer identities,39488 original byte/status/guard/binding
rows, two complete first-entry/true-LR cases and four-profile lifetime,66-worker,
130-worker capacity and remote/unmap controls define this bounded increment.
Four portable and five Windows focused tests include installed ARM64/WoW64
leaves. Exact final full/owning counts, archive/source identities,25 controlled
falsifications, assumptions and ordinary observer results are recorded in
[thread-slot evidence](../../specifications/windows/native-scheduler-thread-slot/README.md).
The frozen owning roots compile current scoped RAX sources and nine matching
current C++ consumers; unrelated current-root/plugin/GUI/package claims remain
excluded. C API1.11.0, Assist ABI, feature defaults and dependency pins are unchanged.
Full ordinary guest exits remain unproven; next boundaries remain explicit.

## Previous increment: scheduler shared-data constructor (2026-10-13)

NtSetInformationProcess class 112 creates a distinct guest-owned
SchedulerSharedData resource, grant 0x1/flags 0, for the current process after
PROCESS_SET_INFORMATION 0x200 validation. Caller contents are ignored. Native64
requires exactly 8 B and probes before birth; WoW64 requires 4 B and can leave a
hidden live handle when its final caller copy faults. Writable guards consume
once; READONLY|GUARD denies without consuming. Numeric native range/alignment
checks precede lengths; handle/rights checks precede touching output.
Final close and process drain release the resource; generic aliases retain its
identity. Slot/data operations and other process owners remain explicit
unsupported boundaries, independent of the constructor. No guest input is
forwarded to host NT. The PHNT query-only comment conflicts with the actual
setter capture; captured build 29683 behavior owns this contract.

All 16016 constructor rows, 204 owned births and two complete fresh original
entry/true-LR captures bind four mature caller profiles. Two portable tests and
three Windows tests pass, including actual installed ARM64/WoW64 leaves.
The unchanged owning observer advances114140->115067:
115067-114140=927 scheduler calls. Three ordinary programs now stop at
NtSetInformationThread class 57/service 0xD/PC0x1800010D0; installed whoami.exe
still stops at NtTraceEvent 0x5E. All four retain reason 5/internal failure;
exit_code 0 is not a guest exit. Shared constructor and scoped owning consumers
build on Windows/macOS/Linux; exact full counts, baseline failures and archive
provenance are in the evidence record. Public Rust Object gains the new variant;
C API 1.11.0, Assist ABI, feature defaults and dependency pins remain unchanged.
See [scheduler-data evidence](../../specifications/windows/native-scheduler-shared-data/README.md).

## Previous increment: native symbolic-link objects (2026-10-13)

`NtOpenSymbolicLinkObject` and `NtQuerySymbolicLinkObject` use immutable,
guest-owned `SymbolicLink` resources for captured KnownDllPath entries. Fixed
installed selection captures each target, maximum grant and subject
ACCESS_SYSTEM_SECURITY status; acquisition closes native handles before guest
execution. Guest pointers, handles, names and desired access are evaluated
inside the selected namespace. Uncaptured targets and security/QoS contexts
retain explicit unsupported boundaries. Final links can be opened with
OBJ_DONT_REPARSE; intermediate link traversal retains the directory policy.

Native64 query write-probes the descriptor's first 4 B with 2 B alignment, then
reads its fields. WoW64 captures an unaligned 8 B descriptor first and copies
the complete descriptor back after the kernel phase. Its copy can override
the kernel status, after reached kernel guards have been consumed; original
MaximumLength/Buffer survive ReturnLength aliases.
Both profiles probe the entire declared buffer capacity and optional 4 B
ReturnLength before handle/type/query-right checks. Optional ReturnLength
requests target bytes plus a 2 B NUL; omitting it requests only target bytes and
never writes a terminator. Successful copies precede Length and ReturnLength
stores. Guards, crossing faults, aliases and partial effects follow the native
corpus rather than generic Nt/Zw prose.

Generic read/execute map to 0x20001, write to 0x20000 and all to 0xF0001.
MAXIMUM_ALLOWED expands from the captured ceiling for opens. Duplicate access
allows zero and discards SYNCHRONIZE/MAXIMUM_ALLOWED; invalid specific link
rights deny after eligible CLOSE_SOURCE. The independent directory control
shows its unknown low specific rights are filtered instead. Unknown high bits
deny before source close. Arc identity, inherited/protected handles, tagged
roots, empty-name typed-root reopen, copy-fault cleanup and final drain retain
the measured native object/handle lifetime.

All 131,944 native rows from 15 families and four caller profiles replay on
macOS, Linux and Windows. Seventeen portable focused tests and 18 Windows tests
pass; the Windows test executes installed ARM64/x86 NTDLL, including x86 RET 12
and 16 B caller-stack cleanup. Two complete fresh ARM64 original-entry/true-LR
captures bind service 0x138 to installed MEM_IMAGE NTDLL. Fresh compatibility
startup and physical x64-kernel proof remain unknown. Public Rust `Object`
gains `SymbolicLink`; opaque C API 1.11.0, Assist ABI, feature defaults and
dependency pins remain unchanged. Ordinary installed-library startup and full
process exit are validated separately from these syscall and lifetime gates.
The unchanged owning observer advances from scheduler call 91,011 to 97,257
(6,246 calls); all four programs stop at `NtQueryVirtualMemory` class 14,
service 0x23, instruction PC 0x180001240, before guest exit.
See [symbolic-link evidence](../../specifications/windows/native-symbolic-link-open/README.md).

## Previous increment: native directory objects (2026-10-12)

`NtOpenDirectoryObject` selects guest-owned immutable `Directory` resources from
three bounded installed namespace catalogs: `\`, `\KnownDlls` and
`\KnownDlls32`. Native acquisition uses fixed query-only host paths and closes
its owned handles before guest execution. Guest pointers, desired access and
handles are never forwarded to the host. Captured maximum grants, system-security
status, NT case policy, entry types and KnownDllPath targets govern guest lookup.
Uncaptured directory children, matching WoW64 system-path redirection and
unselected security contexts remain explicit unsupported boundaries.

Native64 output probing precedes input capture. WoW64 converts attributes and
pointed-to names before flags/security/QoS tails, performs measured system-root
prefix probes, uses a temporary output and then copies to the caller. Guard,
alignment, alias and crossing behavior follows 69,684 native open/duplicate
rows across ARM64, x64 compatibility, x86 WoW64 and x86 LAA profiles on Windows
10.0.29683.1000 ARM64. Immutable Arc identity survives namespace drop; duplication,
inheritance/protection, close-source policy, lowest-free handle reuse and final
release match the retained independent native corpus. A protected WoW64 duplicate
can remain unreturned after caller copy failure, matching measured object state.

The installed ARM64/x86 NTDLL leaf tests pass, including x86 RET12 argument
cleanup. All shared replay rows pass on macOS, Linux and Windows. Fresh original
entry/true-LR evidence is ARM64 only; fresh compatibility and physical x64-kernel
proof remain unknown. Public Rust `Object` gains `Directory`; the opaque C API
1.11.0, Assist ABI, feature defaults and dependency pins are unchanged.
The unchanged ordinary observer advances90924->91011 (87 scheduler calls) to
NtOpenSymbolicLinkObject0x138; all four owning programs reach that boundary before
guest exit. Full ordinary application execution remains an active incomplete goal.
See [directory object evidence](../../specifications/windows/native-object-directory-open/README.md).

## Previous increment: native provider traits (2026-10-12)

NtTraceControl function30 captures provider traits once on a process-local
EtwRegistration. Its24 B header contains a64-bit handle,64-bit buffer address,
USHORT length and six ignored bytes on all measured caller profiles. Nonempty
output write probing, required4 B ReturnLength write probing and full input read
probing precede class-specific lengths. Input must be24 B and output at least120 B.
Referenced pointer must be non-NULL and length1..65535 B before handle/type checks.
Existing traits return STATUS_UNSUCCESSFUL before accessing the referenced buffer.
The structural parser requires the matching16-bit total length, a bounded NUL
name and exact exhaustion of records with size at least3 B. Unknown types and
non-UTF-8 name bytes retain native acceptance. Malformed payloads return
STATUS_FILE_CORRUPT_ERROR, mapped by measured RTL to ERROR_FILE_CORRUPT (1392).
Measured RTL also preserves STATUS_GUARD_PAGE_VIOLATION verbatim.

Successful capture retains immutable owned bytes and then stores zero ReturnLength;
output has no reply bytes in the measured dormant profile. Failed probes/parser
checks do not publish state. Close/reuse/drain release traits with the provider.
Time is O(T), retained space O(T), auxiliary parser space O(1), T<=65535 B.
No host ETW session/controller forwarding or delivery is introduced. Functions
other than15/27/30 remain explicit unsupported boundaries. Public C layouts and
selection defaults are unchanged; the public Rust Object variant gains traits.

Native evidence has four complete mature profiles with9407 cases each, plus
four completed ARM64 debugger captures and two excluded warmups. Fresh x64/WoW64
startup capture and physical x64-kernel proof remain unknown. Ordinary execution
advances from scheduler turn50692 to90924 (90924-50692=40232 calls), where
NtOpenDirectoryObject service0x58 at PC0x1800015C0 remains unsupported. All four
ordinary owning programs reach that boundary before guest exit.
See [provider traits evidence](../../specifications/windows/native-etw-provider-traits/README.md).

## Built-in registry services

KernelBase exports `RegCloseKey`, `RegOpenKeyW`, `RegOpenKeyExW`,
`RegOpenCurrentUser`, `RegQueryValueExW`, `RegGetValueW` and
`RegNotifyChangeKeyValue` for the core registry API sets.
GameOS Advapi32 forwards to these public names.
Opened handles share the native guest registry's key objects, access grants
and x86 view selection. `RegQueryValueExW` returns the stored type and exact
data bytes, including for the unnamed value. `RegGetValueW` supports subkey
selection, type filters, string terminators and zeroing on failure. Expandable
strings require the `RRF_NOEXPAND` flag. A size-only query reports the required
byte count, and a short buffer returns Win32 error 234 (`ERROR_MORE_DATA`).
Registry watches retain guest events and share native notification cleanup.
Predefined root registrations use process lifetime. Immutable guest snapshots
have no content mutations to deliver.

The portable profile starts with an empty guest registry. Opening an absent
ordinary subkey returns Win32 error 2. Where a partial snapshot is supplied,
its coverage determines which keys and values can be resolved. Merged Classes
views and live performance-provider queries are outside that profile.
`RegOpenCurrentUser` opens a closeable handle to the captured primary-user hive
when it is present.
A drive mapping supplies guest files and does not populate the registry.
[Registry value query contract](../../specifications/windows/native-nls-registry/regqueryvalueexw.md)

## Built-in ETW provider services

The portable profile exposes the 23 NTDLL `Etw*` targets forwarded by desktop
Advapi32 build 10.0.18946. KernelBase exposes the public aliases, including
`TraceEvent` forwarding to `EtwLogTraceEvent`. Provider and classic-provider
API sets select KernelBase. An import through a GameOS Advapi32 forwarder
and a direct NTDLL import resolve to the same address.

`EventRegister` captures the 16-byte provider GUID before writing the 8-byte
registration handle. It creates a process-local `EtwRegistration` with grant
`0x804` and zeroes the rest of the internal 160-byte request. A null GUID
returns Win32 error 87. The object table governs capacity. The dormant profile
discards callback and context pointers, reports all providers disabled, and
returns from writes on a live provider without reading event descriptors or
payloads. Unregistering a foreign, closed or protected handle returns error 6.

`EventSetInformation` supports empty binary tracking information (class 0),
a structurally valid, once-only provider traits blob (class 2), and a one-byte
descriptor-type switch (class 3). The portable class selection follows the
retained 18946 x86 NTDLL. Reserved and unknown classes return error 50.

Classic registration writes a zero trace handle. Classic queries and logging
return zero. Activity-ID control writes a zero GUID for `EVENT_ACTIVITY_CTRL_GET_ID`
(1), as used by GameOS WinHTTP. Other activity controls and trace-instance
creation return success and leave caller buffers untouched. Session control, callback delivery and
host tracing are outside this profile. The private scenario-write signatures
are recorded in the [retained PHNT declarations](../../specifications/windows/native-etw-register-guids/phnt-ntwmi.h).

## Previous increment: native provider registration

# Windows handle/service integration

Current native ETW provider registration (2026-10-12):
`NtTraceControl` function 15 (`EtwRegisterGuids`) captures a fixed 160 B private
header and creates a distinct process-local `EtwRegistration` resource with
access grant `0x804`. The object retains the captured request, including its GUID
and opaque fields; caller memory changes do not alter that state.
Repeated GUIDs produce distinct resources. Native probes admit 1,030 simultaneous
registrations per tested group; the public `EventRegister` limit does not define
this private syscall's capacity. Final close and process object-table drain
release the resource. Registration requires no host ETW operation.

Nonempty, non-NULL output receives a full write probe; required `ReturnLength`
receives a 4 B write probe. A nonempty, non-NULL input span is then read-probed
before checking the exact 160 B input length and minimum 160 B non-NULL output.
This order differs from function 27's length-before-capture rule. Byte alignment
is accepted. The reply preserves captured bytes except the zero-extended handle
at offset 24 B, size 160 at offset 44 B, and zeroed reply tail 112..160 B.
The complete reply copy precedes the 4 B `ReturnLength=160` store, even when that
store overlaps the returned handle. Wrong lengths and faults preserve bytes and
create no resource in the measured stable-mapping profile.

The new resource cannot be duplicated. Its `DuplicateHandle` adapter preserves
measured output-zeroing, raw guard error `0x80000001`, access-denial, target and
close-source ordering. Native64 output-copy faults preserve the source; WoW64
can close it after admissible desired rights. Access denial preserves the source
on both ABIs. Wait admission fails for the measured nonsynchronizable grant.
Other object types retain their existing duplication and wait behavior.

Four mature native profiles establish header, length, pointer/protection/guard,
alias, duplication and simultaneous-resource matrices. Fresh ARM64 entry/true-LR
captures observe installed NTDLL's first registration and diagnostic registration
before the process notification Event. Fresh compatibility capture remains
unknown. The public C API 1.11.0 and Assist Rust ABI 184 remain unchanged; the
internal Rust Object enum gains the registration variant. The private meaning of the reply tail is unknown. Guest tracing
controllers, enabled-provider replies and notification delivery remain explicit
unsupported boundaries, distinct from dormant provider registration.
See [provider registration evidence](../../specifications/windows/native-etw-register-guids/README.md).

Historical native ETW process notification Event registration (2026-10-12):
`NtTraceControl` function27 (`EtwAddNotificationEvent`) consumes exactly4 B
containing a zero-extended ULONG handle on native ARM64/x64 and WoW64.
A nonempty non-NULL output receives a full write probe, then required4 B
`ReturnLength` is write-probed, then exact input length and non-NULL input are
validated before capture. Buffers accept byte alignment. NULL output is ignored
regardless of length. Event type and modification right0x2 precede the once-only
busy check. Success retains a separate private process Event reference and
stores zero to `ReturnLength`; failures preserve bytes and do not pin another
Event. Guard consumption follows the first reached probe. Input/return aliases
observe the store after capture. Event type/signal remain unchanged; caller
close/reuse cannot clear the registration, while object-table drain clears it.
This uses no host ETW calls and leaves the public C API1.11.0/Assist ABI184
unchanged. Native kernel evidence contains23160 complete cases, excluding3
fresh debugger warmups. Four mature profiles agree on5730 cases each; fresh
ARM64 first/lifetime, ReturnLength faults, and aliases supply240 sequences.
Fresh x64/WoW64 publication/lifetime remains an explicit same-kernel assumption.
Other TraceControl functions and host ETW delivery remain explicit unsupported
frontiers. Ordinary full-process startup/exit is validated separately.
See [ETW notification evidence](../../specifications/windows/native-etw-notification/README.md).

Historical native process-scoped well-known WNF subscriptions (2026-10-12):
`NtSubscribeWnfStateChange` captures an 8 B name, ULONG change stamp, ULONG event
mask and optional 8 B opaque identifier. Native ARM64/x64 probe and clear the
entire output before name capture. WoW64 first reads the output's 4 B prefix,
captures the name and runs with a private output, then copies the entire 8 B.
Its final copy failure can override an input status or follow publication;
no partial identifier bytes are written in the measured crossing cases.
Installed-runtime selection snapshots the fixed Notifications registry key and
creator primary-token SID/groups through query-only handles, released before
execution. The captured build has1613 provisioned names, including9 process
names. Only the measured process scope and bounded classic DACL forms are
admitted; unknown scopes/descriptors, restricted tokens, AppContainers, matched
generic rights and standalone publish-only grants remain explicit unsupported
inputs. The catalog is metadata, not host WNF state or guest token authority.
Private process-owned records retain opaque generations, requested stamps/masks
and pending metadata. Repeated subscription preserves identity and replaces the
request; unsubscribe removes the record. Arriving metadata signals the already
registered Event; earlier metadata is not signaled retroactively, and unsubscribe
does not reset its signal. No new guest handles or host subscriptions are used.
The installed29683 corpus includes4-profile name/mask, pointer, alias, syntactic
domain and840 guard/copy cases; fresh ARM64 probes constrain Event ordering and
all9 process names across32 masks. Fresh x64/WoW64 Event effects remain a stated
same-kernel extrapolation. State creation/update, data/name-information queries,
subscription delivery/acknowledgement and nonprocess scopes remain unsupported.
The opaque C API1.11.0 and Assist Rust ABI184 are unchanged. These subscriptions
advance one startup service; complete ordinary guest execution remains separate
work. See [subscription evidence](../../specifications/windows/native-wnf-subscribe/README.md).

Historical native WNF process Event registration (2026-10-12):
NtSetWnfProcessNotificationEvent consumes one HANDLE; type and right0x2 precede
once-only registration. The first valid Event gains one process-owned reference,
independent of aliases/caller handle reuse, without a signal/type change. Repeat
valid calls returnC0000718; NULL cannot unregister. Object-table drain removes
the pin. The measured RTL error mapping is1359 ERROR_INTERNAL_ERROR.
There are192 mature native rows over four callers and48 complete fresh ARM64
sequences, plus5 RTL translations. Seven portable/eight Windows tests pass,
including actual installed native/WoW64 leaves and x86 RET4/8 B caller cleanup.
Fresh compatibility debugger failures are retained as diagnostics; their first
state is an explicit same-kernel extrapolation. Registration uses a new private Objects ledger; public Object/Proc variants
and opaque C ABI contracts remain unchanged. Full-suite counts7660/0/2,7652/2/2,7063/5/2 preserve prior
Linux/Windows failures. The identical observer advances44258->46245 (1987
scheduler calls) to NtSubscribeWnfStateChange0x1CD; all four ordinary programs
still fail before guest exit. State/subscription/delivery were unsupported at that boundary.
See [WNF registration evidence](../../specifications/windows/native-wnf-process-event/README.md).

Historical native worker-factory BindingCount updates (2026-10-12):
Class3 uses exact4 B capture -> typed factory -> right0x4 validation. Zero sets
0xFFFFFFFF; other ULONG bit patterns add signed32 deltas with saturation. Native
basic-query bytes32..36 verify1196 validation rows plus104 repeated transitions.
Six portable/seven Windows tests pass; hard/soft setters retain independent
state. Public Rust WorkerFactory gains binding_count:u32, initially the measured
zero; opaque C API1.11.0/Assist Rust ABI184 are unchanged. Original Linux timeout
and Windows lowering failures remain. The identical observer reaches
NtSetWnfProcessNotificationEvent at44258, from42802 (1456 scheduler calls).
All four ordinary programs still fail before guest exit. See
[binding-count evidence](../../specifications/windows/native-worker-factory-binding/README.md).

Historical native worker-factory soft-maximum requests (2026-10-12):
NtSetInformationWorkerFactory class14 retains the last successful unsigned
request independently from the hard maximum. Exact4 B length -> input capture
-> typed handle -> right0x4 order and one-shot guard behavior replay all1196
native rows. Five portable/six Windows tests pass; class5 regressions remain.
Public Rust WorkerFactory gains soft_maximum:Option<u32>; None means no captured
request, not a native default. The native default/stored effective soft limit
and active-worker behavior remain unknown. C API1.11.0/Assist Rust ABI184 are
unchanged. All host build/C API/owning selections pass; original Linux timeout
and Windows lowering failures remain. The identical observer reaches class3
at42802 from42609 (193 scheduler calls), and all four ordinary programs still
fail before guest exit. See
[soft-maximum evidence](../../specifications/windows/native-worker-factory-soft-maximum/README.md).

Historical native worker-factory maximum setting (2026-10-12):
NtSetInformationWorkerFactory class5 captures an exact4 B unsigned maximum
before typed handle/right0x4 validation; guard faults are consumed once, with
no partial mutation. All956 native rows replay across four caller profiles.
Four portable/five Windows tests pass, including actual RET16/20 B x86 caller
cleanup. Object shape and C ABI1.11.0 remain unchanged. The identical observer
advances42564->42609 (45 scheduler calls) and explicitly fails class14. All
ordinary programs still fail before guest exit. See
[maximum evidence](../../specifications/windows/native-worker-factory-set-maximum/README.md).

Current native wait-packet association/cancellation (2026-10-12):
`NtAssociateWaitCompletionPacket` and `NtCancelWaitCompletionPacket` use owned
guest object identities, measured access/validation precedence, optional BOOLEAN
store-fault suppression, FIFO packet delivery and alias/final-close teardown.
Native-width completion records preserve NTSTATUS and ULONG_PTR information.
There are 996 exact native row replays across four installed-kernel caller
profiles; nine portable and ten Windows tests pass, including actual
ARM64/WoW64 leaves. The public Rust completion queue payload changes, while
C ABI1.11.0 and Assist Rust ABI minor184 remain unchanged. macOS/Linux/Windows
all-target, C API and owning gates pass. Original full-suite failures remain
in the evidence: Linux io_uring timing and Windows BZHI/FP16 cases, plus the
initial Windows thread-clock failure and its passing isolated run.
The unchanged observer reaches NtSetInformationWorkerFactory0x1B1 at42564,
379 scheduler calls after the prior association boundary42185. All four native
ordinary programs still fail before guest exit. NtRemoveIoCompletion and worker
mutation/activation remain separate services. See the
[native association evidence](../../specifications/windows/native-wait-packet-associate/README.md).

Native wait-packet construction evidence (2026-10-12):
`NtCreateWaitCompletionPacket` creates a real process-local notification-signaled
object with measured grants and final-close lifetime. Public single/multiple
waits admit packets and dormant legacy/IR timers. Wait-any permits duplicate
aliases and consumes one automatic-event signal; wait-all rejects aliases before
consumption. Four installed-kernel caller profiles supply 1368 observations,
with 1228 exact constructor replays and 40 explicit namespace/security/privilege
exclusions. Seven portable tests and eight Windows tests pass, including installed
ARM64/WoW64 leaves. These measurements supersede native-unknown claims below only
for the measured behavior. Association/cancellation is described above; full
application exit remains separate work. See the [native evidence](../../specifications/windows/native-wait-packet-create/README.md).

Baseline: 4312bb48ec169c48c67ea8ab55bbacda702e5e93, branch user-win.
The baseline tracked tree/index was clean. Unrelated pre-existing untracked
content is excluded. Owned source: dll/{files,handles,locks,threading}, registry/
kernel migration, objects.rs, sync.rs, process/{mod,sched,start,thread}.rs and
hle/dispatch.rs. Owned evidence: feature documents, retained service sources,
this/master document, separate services PE fixtures and user_windows runner.
No dependencies, default features, toolchains, native admission or C ABI change.

## Acceptance and scope

The group exposes thread creation/control/APCs, named events/mutexes/semaphores,
single/multiple/alertable waits, critical sections, SRW locks, condition/address
waits, same-process handle duplication/flags and synchronous file services.
Each architecture has ABI tests and a compiled guest PE program. These establish
implemented conformance, not complete Windows/native-kernel equivalence.

Object names compare exactly; Local aliases the single modeled default session
and Global is distinct. Wait sets pin objects transactionally and release pins
once on completion/cancellation. Per-handle grants survive same-access duplication.
Reduced file grants cannot regain FileObj permissions. ReadFile/WriteFile/
CloseHandle move from kernel into file services without shadowed exports.
Cross-process duplication, protected close-source duplication, non-file access
escalation and custom security descriptors remain explicit rejected branches.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Guest mappings remain stable through HLE preflight/copy | Serialized scheduler/AddressSpace contract | Lock/file publication | Cross-page read-only output | Concurrent embedding clone mutation falsifies contract | Retained |
| S2 | One client session and process-local objects are admitted | Proc owns Objects | Exact-case Local/default alias and distinct Global | Prefix/case/type collisions | Name tests; separate processes cannot share Objects | Confirmed profile |
| S3 | Non-file access escalation needs unmodeled tokens/ACLs | Microsoft DuplicateHandle permits object-dependent escalation | Explicit unsupported branch | Request rights absent from source | Verified token/access-check implementation; native comparison | Retained |
| S4 | Ordinary CreateThread commits usable reservation above a terminal guard | Original thread-creation profile; later fiber stacks have initial commitment and controlled guard growth | CreateThread size adaptation | Rounding/overflow/invalid ID output | Stack/rollback tests; native VirtualQuery unknown | Retained; scope revised to ordinary thread creation |
| S5 | Unix device/inode identity distinguishes live files | Host metadata | Sharing/deferred deletion | Hard links, replacement, symlinks | Concurrent replacement between final check/unlink falsifies atomicity | Retained; atomic namespace not claimed |
| S6 | Expected guest results are specification-based | Retained Microsoft contracts; no native recording | Conformance conclusions | Execute same PE on Windows builds | Native run may falsify expectation | Retained; native result unknown |
| S7 | Fixtures reach guest behavior, not just imports | Exit checks, import counts, deadline, scheduling variation | Integration coverage | Slices 1/4096 and failure codes | Run whole user_windows binary and inspect counts/results | Confirmed: all 30 tests passed; six service executions cover three ISAs and both slices |
| S8 | Guest programs do not free/recycle personality-owned TLS system allocations | Standard APIs do not transfer ownership of these allocations | Address-based TLS teardown tracking | Forged guest TLS pointer must not redirect teardown | Explicit HeapFree/reuse of genuine system allocation exceeds profile; no allocation-generation model exists | Retained |

## Change-surface map

| Plane | Status |
|---|---|
| Direct decode/execute | Unchanged semantics; all three compiled guest ISAs exercise existing cores |
| CPU state | Existing ABI/callback/TLS/TEB marshalling reused |
| Memory/MMU | Checked storage and stack allocation affected; no MMU contract change |
| SMIR lift/IR/interpreter/optimizer/native lowering/JIT runtime | Unaffected; direct interpreter-only Windows execution |
| Backend/machine/device | Unaffected; services are inside process personality |
| Oracle/analysis | Unaffected; no instruction/stateless output changes |
| C ABI | Unaffected; new internal services are not exposed by capi |
| Tests/docs/CI | Existing explicit user_windows target gains reachable tests; no matrix/target change |

## Complexity and bounded findings

Handle allocation: O(H) time, O(1) extra space for H handles. Transactional wait
pinning: expected O(N) time, O(U) space for N IDs and U distinct objects; admitted
N <= 64. I/O uses O(B) buffer space for B <= 16,777,216 bytes.

High, non-blocking for admitted profile: host check/unlink is not atomic against
external filesystem mutation; identity revalidation detects replacement but
does not implement Windows namespace transactions. High: ordinary thread
creation retains eager commitment; later DLL lifecycle and
[fiber/FLS](windows-fibers.md) groups implement normal notification/cleanup and
controlled fiber guard growth under explicit profiles, not complete native
private-state equivalence. High: host console
reads can block the sole scheduler thread; asynchronous console/pipe dispatch
is not claimed. Medium: native private lock-word encodings/fairness and full
ANSI/Unicode conversion are unknown. Low: slice-1 performance is unmeasured.
High, pre-existing and non-blocking for normally mapped system TLS storage:
TlsFree clears its slot bitmap before fallible slot writes across threads.
A protected/forged TLS pointer can fault after partial cleanup. Native behavior
for corrupted private TLS state is unknown; no atomic fault rollback is claimed.
Guest freeing/recycling system-owned TLS blocks violates S8; tracked addresses
are not allocation-generation identities.

## Verification and Quality Gates

Host: AArch64 macOS; Rust stable 1.98.1. The frozen combined tree passed:

- cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=4 --quiet:
  6,454 library tests passed, two ignored; all 30 Windows integration tests and
  all 10 CI contract tests passed, with none ignored or filtered in either
  integration target. The ignored library tests are the two explicitly ignored
  optional microkernel lowerer fixtures, not Windows tests. The library registry
  lists 182 Windows unit tests. The Windows runner verifies the service fixtures
  at scheduler slices of 1 and 4,096 instructions for each guest architecture.
- cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1 --quiet:
  all 30 tests passed again, with none ignored or filtered.
- cargo +stable check --workspace --locked --no-default-features --all-targets:
  passed, including rax-capi compilation.
- cargo +stable check --workspace --locked --no-default-features --features x86_64-suite,smir-jit --all-targets:
  passed. Feature compilation does not establish native JIT/KVM/HVF execution.
- cargo fmt --all --check: passed. The staged whitespace check passes for all
  owned hand-maintained source, fixtures, documentation and provenance records.
  A full-index git diff --cached --check reports upstream trailing whitespace
  only in manifest-declared retained primary snapshots/licenses; those bytes
  remain preserved rather than silently changing their provenance hashes.
- All 58 retained service-reference entries matched their declared SHA-256
  hashes: 32 thread/synchronization, nine lock, and 17 file references. Separate
  license hashes also matched. All four service fixture source/script hashes
  and all three compiled PE hashes/sizes passed the integration provenance test.
- Public lock-layout compile probes passed nine assertions per guest ABI
  (27 total), using the recorded MinGW-w64 headers, not a native Windows SDK.

QG1: no ethical judgment is required. QG2: S1-S8 and the service-specific
registers identify dependencies and falsification probes. QG3: acceptance is
covered by reachable unit and compiled-guest tests within the stated profile.
QG4: fixed-width ABI/layout arithmetic, checked allocation rounding and bounded
buffer calculations remain explicit in source and service documents. QG5:
unsupported branches fail explicitly; native unknowns and non-blocking profile
limits are recorded above. QG6: primary references and artifact hashes verify;
native Windows differential results remain unknown. QG7: high/medium/low
out-of-scope findings are recorded without expanding implementation authority.
These gates establish this service group, not completion of Windows emulation.


## Native absent image-extension query (2026-10-13)

NtQueryVirtualMemory class 14 now describes complete guest PE images without
kernel CFG/SCP extension owners, consistent with class-6 ImageExtensionPresent=0.
Native64 preserves valid type/flags, writes zero RVA/size, then optional 24 B
ReturnLength. WoW64 rejects the unavailable conversion after its existing optional
4 B ReturnLength preprobe. Whole SIZE_T write probes, overflow/user-range guard
suppression, pointer/handle/rights/flags/type order and aliases follow the actual
build29683 captures; no guest input is forwarded to a native host query.

Thirteen actual producers bind 83,088 mature native observations: 80,568 exact
portable replays plus 2,520 explicit native present-SCP controls. Two complete
fresh ARM64 original-entry/true-LR cases restore the exact native handle set.
Five portable tests and the sixth installed ARM64/WoW64 leaf test pass. Full
suite outcomes are recorded in the evidence table: macOS and Linux pass, while
Windows retains the exact four BZHI/one FP16 baseline failures. C API (168 tests),
all-target builds, integrations and five owning C++ consumers per host pass; macOS CLI/MCP,
seven selected CTests and protected-text scans pass in scoped frozen embeddings.
Native archives pass 4673/260-member walks, 92 actual source hashes and empty
core features. The unchanged 11,177 B observer advances 97,257->114,140:
114,140-97,257=16,883 scheduler calls. Three ordinary programs now stop at
NtSetInformationProcess class 112/service 0x1C/PC 0x1800011D0; installed whoami.exe
stops at NtTraceEvent 0x5E/PC 0x180001620. All four retain reason 5/internal failure;
exit_code0 is not a proved guest exit. Full same-host process support remains
an active incomplete goal. Kernel extension ownership, broader native builds,
physical x64 kernel and whole current-root plugin/GUI/package validation remain
explicit limits. The independent partition/provenance checker and all 17 controlled
falsifications pass; reconciled assumptions, complete plane map and evidence are
in [image-extension evidence](../../specifications/windows/native-image-extension/README.md).

### Compact process TLS replacement (2026-10-14)

The installed class35 packet, slot/vector changes, startup sentinel, enumeration,
caller aliases and native/WoW64 failure ordering are documented in
[TLS evidence](../../specifications/windows/native-process-tls/README.md).
Its1040 native controls cover four profiles. The C API remains unchanged;
ordinary Windows completion remains an active requirement.

## Installed compatibility-cache lookup

`NtApphelpCacheControl` operation 6 now queries a bounded immutable snapshot
of the installed base compatibility database. Counted UTF-16 names, actual flags,
fixed packet capture, output alignment, guards, aliases and WoW64 copyback follow
recorded native behavior. Other operations remain explicit unsupported paths.
The [contract and native evidence](../../specifications/windows/native-apphelp-cache/README.md) own the format, assumptions,
platform gates and ordinary-startup limits.

## Selected installed CSR data section

`NtOpenSection` and `NtMapViewOfSection` retain captured data-section grants,
opaque committed bytes, reserved runs and independent view lifetime. The
[contract and native controls](../../specifications/windows/native-shared-section/README.md) record532 native
controls, startup allocation flags, platform evidence and remaining frontiers.
Full ordinary Windows process completion remains an active requirement.

### Unnamed pagefile-section construction (2026-10-15)

`NtCreateSection` now creates a real process-owned, page-rounded anonymous
backing object for supported unnamed pagefile sections. All seven original
arguments use the existing ARM64/x64/x86 service transport. WoW64 attribute
conversion, early allocation/protection validation, output and 8-byte maximum
capture, deferred validation and error-handle copyback retain the independently
measured order. `PAGE=0` has a different validation stage from other invalid page
values. No guest argument is forwarded to a host NT creation call.

Native controls cover 10,920 creations across ARM64, x64, x86 and x86-LAA on
ARM64 Windows build29683: 5,544 priority controls and 5,376 protection/allocation
cross controls, with 1,516 explicitly closed section handles. The original
owned debug child supplies an unchanged seven-argument 65,536-byte read/write
SEC_COMMIT call and naturally exits41. The replay compares10,876 native statuses,
output/max-size bytes, available section metadata and grants; 44 captured cases
require explicit unsupported results for separately unimplemented modes.
NOCACHE takes precedence over WRITECOMBINE, and WC alone rejects executable
sections after maximum-size capture. Source, producer PE machine/LAA and stdout
identities are retained with the corpus.

Backing size is bounded at67,108,864bytes(64MiB), and positive maxima round up to
4,096-byte pages without changing the caller's input. Same-process duplication
retains the backing until the last handle closes; failed or unsupported calls
publish no object. Named/file-backed/custom-security, privileged permanent,
large-page/based/64K/no-change modes, larger backing requests, guest mapping and
NtQuerySection remain explicit separate frontiers. Constructor completion is
not ordinary process completion. See the native-section-create corpus for the
assumption register, scope maps, primary reference and validation records.
