# Explicit CRT onexit table probes

This bundle contains 36 compiler-produced PE executables: x86, x64 and ARM64
times UCRTBASE and genuine CRT runtime API-set bindings times six programs,
plus six compiler-produced guest companion DLLs, for 42 physical PE inputs.
The executables have a custom `entry` and call `kernel32!ExitProcess`.
The companion DLLs have a custom `DllMain` and call `kernel32!TerminateProcess`
for their detach witness. Neither substitutes ordinary MinGW/MSVC
`main`/`wmain` startup, stdio cleanup or CRT `exit`.
No native Windows oracle was available.

The only table imports are the genuine `_initialize_onexit_table`,
`_register_onexit_function` and `_execute_onexit_table`. No named UCRT `atexit`
or `_onexit`, fabricated legacy table export, or archive alias is admitted.
MSVCRT's installed table helpers are static compatibility bodies, not evidence
for native named table exports. The retained MinGW `onexit_table.c` is a
comparison algorithm, not a native UCRT oracle.

## Independent assertions

| Program | Assertions |
|---|---|
| `basic` | NULL/uninitialized failure profile; initialized empty drain; invalid-until-reinit; NULL skipping, exact three-callback LIFO, ignored integer callback results, 32 reuse cycles and 1024 registrations |
| `mutation` | Copied/misaligned representation rejection without callbacks; guest changes to detached future slots are read lazily in reverse; NULL mutation is skipped |
| `nested` | Other-table drain; register/execute without reinit fails; explicit reinit creates an independent nested generation; a further live generation survives outer completion; nested malloc/memset/free |
| `repair` | Real guest VEH repairs NOACCESS/PAGE_GUARD on the next old-buffer slot after a callback; previous callback executes once; saved table argument is clobbered but the captured pending frontier survives |
| `terminal` | A worker callback's ExitThread(93) is observed by its peer; remaining callback/call-site sentinels do not run; reuse succeeds; later process exit cancels remaining callbacks; guest companion PROCESS_DETACH drains a prepared table exactly once |
| `oom` | Bounded 64 MiB commitment pressure plus runtime-heap consumption causes first-buffer/growth failure; table words/LastError survive; release-and-retry appends once and preserves all earlier callbacks |

Microsoft's primary table documentation mandates initialize before use and
explicit reinitialize after execute. It describes table fields as opaque and
does not specify recursive behavior, pointer encoding, slot mutation, callback
fault order or malformed-table diagnostics. These probes therefore name the
selected RAX profile: the retained MinGW three-pointer declaration is guest
visible; the old generation is detached and invalidates current admission before
callbacks; old slots are read lazily in LIFO order; explicit initialization may
publish a fresh generation; the outer receipt never invalidates or frees it.
Reentrant use without that initialization returns a negative failure. MinGW's
static implementation zeroes the old table and permits registration into those
zeroed words without a separate initialize call; that is a known source/profile
difference, not a concealed native guarantee.

The `VoidFn`/`ExitFn` casts in mutation are machine-ABI probes corresponding to
the retained header's `_PVFV` table fields and `_onexit_t` registration argument.
The callback's integer return is deliberately ignored. CONTEXT offsets come
from retained public MinGW header declarations and existing layout probes,
not engine-private context structures. Stack-preparation failure retention is
covered by root-owned engine unit tests rather than an invented alternate guest
exception stack.

`terminal` loads only its isolated `onexit.dll` dependency and calls its genuine
exported `configure` function to prepare an explicit table. The guest DLL's
custom `DllMain(DLL_PROCESS_DETACH)` executes that table and validates the one
callback sentinel, terminating with a nonzero status on failure. This is an
actual emulated guest-image notification/table lifetime boundary; it does not claim
complete ordinary compiler DLL CRT startup or global CRT exit registration.
The final callback marks shared phase 1 immediately before normal
`ExitProcess(88)`. The forbidden lower callback marks failure phase 2, and any
return from the process drain marks failure phase 3. The companion checks
phase 1 both before the drain and before deliberately invoking forced
`TerminateProcess(0)` after the table check. Earlier check failures retain
phase 0, so none of those failure paths can be masked by the status override.
If notification is skipped, status 88 fails. This normal-to-forced override is
an explicit reachability/profile witness, not a normal-exit-code preservation
oracle. Termination-status preservation is tested separately by engine/lifecycle
tests.

OOM checks use actual guest VirtualAlloc/HeapAlloc services, not an injected
test-only engine API. Private table buffers share the runtime heap exposed by
`_get_heap_handle`, but are tracked separately from ordinary malloc blocks.
The selected heap's initial committed page is 4096 bytes and its reserved header
is 0x100 = 256 bytes, so HeapAlloc consumes exactly 4096 - 256 = 3840 payload
bytes before pressure. No errno/PTD allocation is performed before that fill.
This arithmetic is a RAX heap-layout profile, not a native UCRT size claim.
The heap retains reusable commitment/capacity; no decommit/native heap-geometry
claim follows from draining a table. Table failures do not assert errno because
the primary table contract specifies no errno value. Preserved Win32 LastError
is an explicit CRT admission profile.

## Reproduction and evidence

Run `bash build.sh` with the pinned installed Clang/LLD/llvm-dlltool recorded in
the manifest. Zig 0.16.0 is recorded for installed-source provenance, not used
as a replacement CRT startup. Two consecutive builds must reproduce all
artifact and manifest bytes. `bash baseline.sh /absolute/preserved/rax-user`
records the old-RAX failures of each final image at slices 1 and 4096. Each run
maps only an isolated copied PE (plus its one companion DLL for terminal) and
verifies every copied byte afterward. Timeout,
signal and a missing receipt cannot be success. The Rust runner validates the
entire source/artifact/matrix/IAT/provenance/baseline input set.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| O1 | The named table triple exists on all three UCRT/API-runtime guest ABIs | Retained import DEF/IAT evidence; not measured native exports | Six admitted bindings | Exact named IAT validation | Native PE export/import inventory contradicts the retained binding | confirmed installed evidence; native inventory unknown |
| O2 | Three public pointer-width words and unencoded owned slots define this guest profile | Retained MinGW header/source; Microsoft calls native layout opaque | Mutation, detached slot fault and OOM word checks | Copied/misaligned fields and late edits | Native UCRT layout/encoding probe differs | retained profile; native unknown |
| O3 | Reinitialization starts a fresh generation and outer completion cannot damage it | Public invalid-until-reinit lifecycle plus root-selected epoch profile | Nested generation tests | Two nested epochs and a surviving pending epoch | Native reentrant table probe differs | retained profile; native reentrancy unknown |
| O4 | Terminal callback abandonment cancels only its active drain, preserving explicit reinitialization | Root continuation cleanup profile | ExitThread/ExitProcess sentinels and reuse | Peer observes exit status before reuse | Native terminal-callback cleanup probe differs | retained profile; native nonreturn cleanup unknown |
| O5 | Finite guest commitment, shared private heap and initial 4096-byte page minus 256-byte header expose allocation failure | Root VM/heap profile; genuine allocation services | OOM tests | Exact3840-byte payload fill, growth, prior-callback preservation, retry | OOM fails to occur within fixed bounds or mutates old state | revised payload arithmetic; native capacity unknown |
| O6 | A repaired pending slot uses captured input/frontier after volatile formal clobber | Root HLE retry contract; public CONTEXT declarations | VEH repair tests | NOACCESS and one-shot guard fault after one callback | Replayed callback, wrong pending target or wrong table | retained HLE profile; native fault order unknown |
| O7 | Normal DLL detach can deliberately replace pending status88 with forced status0 only after the expected phase and successful table drain | Selected scheduler termination profile; genuine kernel TerminateProcess | Observable companion notification witness | Missing detach remains88; phases0/2/3 and failed table drain terminate192 | Native shutdown/forced-override experiment differs | revised phase guard; native nested termination details unknown |

## Bounded scope

High, outside this group: ordinary CRT exit requires real stream cleanup and
thread-local C++ destruction; registering explicit table callbacks alone does
not provide those services. Medium, outside this group: native UCRT private
encoding, recursive ordering and OOM geometry remain unknown. No unsupported
native guarantee is inferred from successful emulator execution.
