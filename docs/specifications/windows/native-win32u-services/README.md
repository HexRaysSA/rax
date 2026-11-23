# Selected installed Win32u service identities

The observations below record the initial service-identity implementation and
its original `NtGdiInit2` frontier. Subsequent
[GUI conversion work](../native-gui-bootstrap/README.md) implements the measured
entry effects, callback 84 and return restoration, together with the remote
connection, assigned desktop, LPK registration and process UI-context queries
needed by that callback. The selected installed USER32 now returns from the
callback; ordinary `whoami` next stops at
`NtUserSetProcessDpiAwarenessContext`. This does not establish full USER/GDI or
whole-program support. The historical measurements and original boundaries
below remain attributed to their original source state.

This change identifies Win32k services from the selected installed `win32u.dll`.
It does not implement USER/GDI kernel initialization. The ordinary ARM64
`whoami.exe` frontier remains an explicit failure; its diagnostic can now name
`NtGdiInit2` instead of reporting a number absent from the NTDLL table.

The parent RAX revision is `2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b`.
The frozen compiler frame is
`6140e8121129bbd12c871dac8525834b68aacff0b9484b027054ec0b58e45a62`:
29,182 inputs and six Rust overlays. The retained Assist consumer ledger has
3,983 source inputs. Those consumers use ABI184; current-root ABI274 plugin,
GUI and package CI is a separate boundary.

## Windows Server 2022 legacy GDI initialization

Two fresh native AMD64 `findstr.exe` children on build 20348 each made one
USER callback at index 84 with a zero-byte payload. Each returned `1` from
`NtGdiInit` and populated the previously zero GDI table, desktop view, process
marker and thread marker. The GDI view committed 1,576,960 bytes. The desktop
view had 167,936 committed bytes followed by 20,807,680 reserved bytes. A
separate call to the documented `GetStockObject(WHITE_BRUSH)` API in the
disposable observer produced the same mapping geometry.
[Native observations](https://github.com/HexRaysSA/rax/actions/runs/44766099612)

The selected installed AMD64 server profile uses those views and the guest's
own callback table to perform thread conversion. The host metadata helper
initializes GDI through the fixed stock-brush query. The guest leaf returns
`1` after callback completion. The `NtGdiInit2` service retains its process-value
return ABI.

The released WoW64 observer launches an owned x86 process and synchronizes
companion reads around its installed stock-brush call. It repeats the
parameterless `NtGdiInit2` leaf where available, or `NtGdiInit` on systems
that expose only the legacy entry. The receipt records whether the repeated
return is stable, equals the companion PEB value, or equals one. The probe
checks the x86 transition shape before either call.

## Admission and dispatch

`loader::load_image` admits a Win32u table only when the loaded DLL's host path
equals `NativeRuntime::dll("win32u.dll")`, the confined canonical selection.
A supplied or application DLL named `win32u.dll` does not satisfy that check.
The common parser reads complete recognized leaves from the immutable input PE;
it does not learn a service name from guest-modified export bytes.

The existing bounds remain 65,536 exports and 64 inspected bytes per leaf.
ARM64 requires SVC followed by RET; x64 requires the recognized SYSCALL leaf;
x86 requires the complete CALL/RET form and its exact exported
`Wow64Transition` slot. Encoded x86 service numbers retain all bits. The Win32u
slot uses the existing private guest transition transport, independently of
NTDLL's slot. No service number is copied from a Windows-build table.

The dispatcher requires live NTDLL and, for Win32u identities, a live selected
Win32u module. A number present in both namespaces fails before any modeled
kernel operation. A Win32u name cannot select an NTDLL HLE implementation.
Unimplemented Win32u services fail by name and number; none return fabricated
kernel status, handles, buffers or guest process completion.

Table lookup costs O(log N + log W) time for N NTDLL and W Win32u services;
the retained additional table occupies O(W) space. Existing NTDLL implementations,
synthetic DLL exports, ordinals and trap RVAs are unchanged.

## Native observations and rejected return-only model

The observation host is one Windows ARM64 kernel, version 10.0.29683.1000.
ARM64, x64/ARM64EC, x86 and large-address-aware x86 are four execution views of
that kernel. They are not four independent kernel profiles. Independent native
x64-kernel observations remain unknown.

| Observation | Direct evidence |
|---|---|
| ARM64 service 0x12FD corresponds to `NtGdiInit2`, RVA 0xBFD0 | Selected Win32u export/stub capture and ordinary guest caller diagnostics |
| Zero stack arguments on x86 | Complete installed x86 leaf ends with RET, without an immediate cleanup count |
| Full pointer-width return consumed on ARM64 | Installed `gdi32full.dll` caller stores X0 and tests X0 for zero |
| Stable process value, shared by two threads | 32 calls per view before/after GDI load; four original and four independent repeat processes |
| Last-error unchanged in that cohort | All 256 recorded calls preserve 0x12345678 |
| Calling before USER initialization can fail before returning | Instrumented uninitialized control exits 0xC000041D in every view |
| First ordinary call maps GDI state | ARM64 first-entry observer records table zero before SVC, nonzero afterward |

The installed `win32kbase.sys` export reads process state, updates a flag word
and returns a process value. That leaf body does not establish the complete
kernel-entry contract. The first-entry observer additionally measures:

| Native ARM64 field or view | Before first SVC | After first SVC |
|---|---|---|
| PEB + 0x58 callback-table pointer | Nonzero | Same pointer |
| PEB + 0xF8 GDI table pointer | Zero | New mapped address |
| GDI table region | Absent | MEM_COMMIT 0x1000, PAGE_READONLY 0x02, MEM_MAPPED 0x40000 |
| GDI table region size | Absent | 1,576,960 bytes |
| PEB + 0x108 and several TEB words | Captured in raw record | Changed in raw record |

The measured view size is 385 * 4,096 bytes = 1,576,960 bytes. The relationship
to a complete table schema is unknown; this arithmetic is not a layout claim.
Offsets and observations are scoped to the captured native profile. No captured
host pointer or process value is imported into the guest.

The observer changes only its own process's private instruction pages, executes
the real SVC, restores the exact SVC/RET bytes, removes its exception observer
and closes its module references. The failed first observer used an unsupported
breakpoint immediate and exited 0xC000001D; that receipt is retained. The working
version uses the ARM64 BRK immediate documented for MSVC `__debugbreak`.

A prototype that returned a private opaque value without these entry effects
was rejected before publication. Production source contains no such GDI state
or return implementation. The next implementation boundary is GUI process and
thread initialization, including shared mappings and USER callbacks.

## Verification boundaries

The regression suite exercises canonical-path admission, a complete spoof DLL,
namespace separation, live-module checks, number collisions, untouched
last-error/random/object state on failure and continued NTDLL dispatch. On
Windows it executes the installed native and x86 instruction leaves and requires
the named unsupported outcome rather than a return to the caller. A separate
actual-owning-core native probe also enables installed-library mode, loads
complete supplied and file-backed forged DLLs, and mutates the guest stub.
All six ARM64/x86 cases preserve the selected table and reject the forged
service 0x1FEF. The first version omitted the guest drive mapping for its file
fixture; its failed receipt is retained, and version 2 corrects that fixture
without changing production source.
| Surface | Validation evidence |
|---|---|
| macOS standalone | 8,207 passed, 0 failed, 2 existing ignores; 183 C API tests; 544 integration tests; all targets checked |
| Linux x86-64 container | 8,202 passed, 0 failed, 2 existing ignores; 183 C API tests; 544 integration tests; all targets checked |
| Native Windows ARM64 standalone | 7,684 passed, five exact pre-existing lowerer failures, two existing ignores; six focused and four ordinal tests passed; 183 C API tests; four integration tests; all targets checked |
| Retained macOS owning consumers | Eight targets built; seven CTest checks passed; actual core/carrier archive identities stable |
| Retained Linux owning consumers | Five C++ consumers linked and ran; actual core/carrier archive identities stable |
| Retained Windows owning consumers and ordinary C API | Five C++ consumers linked and ran; owning archives stable; smoke guest reason 4 (EXITED), code 0; whoami reason 5 (FAILED; Internal diagnostic), named NtGdiInit2 frontier |
| Quality | Rustfmt 1.95.0, strict library Clippy and all-target Clippy passed |

The initial Linux attempt could not reach Docker because OrbStack was stopped.
After runtime recovery the unchanged-source full rerun passed. The initial
macOS full run used an overlong validation temporary path and failed two Unix
socket tests. Its generated abstract socket pathname was 115 bytes plus NUL,
exceeding Darwin's 104-byte field. The short in-worktree path yields 85 bytes
plus NUL. Both exact tests passed with the same executable hash, followed by
the full unchanged-source rerun. Original failed receipts remain evidence.

Linux runs in a Linux/amd64 container under OrbStack/Rosetta on an ARM Mac.
It is Linux runtime evidence, not an independent physical x64 instruction oracle.
The unchanged five native Windows lowerer failures must remain explicit in the
full result; neither test skipping nor assertion weakening is permitted here.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The observed service corresponds to selected Win32u `NtGdiInit2` | Export RVA, complete stub and caller capture | Named frontier | Multiple architecture views and exact encoded numbers | Different selected export or opcode | Confirmed for captured profile |
| A2 | The six-file candidate is the source tested | Frozen frame, input hashes and actual Cargo artifacts | Validation attribution | Before/after source and archive checks | Any input or artifact mismatch | Confirmed for the frozen compiler and consumer cohorts |
| A3 | Pointer-width process-value behavior is relevant to the leaf | Caller instructions and 256 native calls | Rejection of a Boolean return | Two threads, repeat processes, x86 width | Varying within-process result or different cleanup | Confirmed for captured cohort |
| A4 | Returning the private process value alone implements the service | Initial leaf-body hypothesis | Return-only prototype | First real SVC with USER initialized | Additional PEB/TEB or mapping effects | Falsified; prototype removed |

## Change surface and bounded findings

| Plane | Disposition and evidence |
|---|---|
| Windows loader, dispatch, tests | Affected: the six frozen Rust files own table admission and diagnostics |
| Windows/macOS/Linux targets | Shared code compiles in all three configurations; installed leaves are exercised on native Windows |
| Plugin lifecycle, UI, conversation, agent backend, prompt/context, tool schema, approvals, mesh/transport/crypto | Unaffected: no changed file consumes or changes those contracts |
| Persistence, SDK/C ABI, optional engine defaults, update/release/package layout | Unaffected: no public header, schema, dependency, feature default or package definition changes |
| Assist consumers | Relink and runtime checks use the actual retained ABI184 carrier; no current-root GUI/package claim |

| Impact | Finding | Evidence | Blocking boundary |
|---|---|---|---|
| High | GUI kernel-entry effects exceed the cookie leaf | First-SVC PEB/TEB/mapping deltas | Blocks full USER/GDI support; named unsupported result retained |
| Medium | Independent x64-kernel profile unknown | All four native views share one ARM64 kernel | Limits native-profile claims |
| Medium | Host-folder transfer interruption | Native disk and command channel respond; VM host-folder sharing disabled | Resolved with framed stdin/stdout transfer and native local receipt files; Home sharing stays disabled |

Primary native inputs and executable receipts are recorded with byte counts and
SHA-256 identities. The final proof inventory binds `check_evidence.py` and the
selected receipts. An observer process exiting zero is never treated as proof
that its emulated guest completed.

`python3 -B check_evidence.py --source-root /path/to/rax` verifies the frozen
compiler frame and evidence. `python3 -B validation/check_validation.py` binds
the completed macOS, Linux and Windows verifier receipts to that exact proof
and checker. Both checks ran on all three hosts. The evidence controls include
eleven reindexed corruptions, rejection under Python `-O` and `-OO`, and two
unmodified successful controls.

Finished native producer trees, transfer packets, socket temporary directories
and the group-specific Linux temporary volume were removed after checking for
active users. The compatible standalone and retained ABI184 consumer build
caches, ordinary Rust/C API probes, admission probe and native local recovery
inputs remain for the next GUI initialization implementation and regression.
