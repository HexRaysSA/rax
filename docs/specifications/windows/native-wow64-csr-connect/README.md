# Pure x86 CSR BASE connection on ARM64 Windows

The installed `NtWow64CsrClientConnectToServer` leaf takes five 32-bit
arguments: `PWSTR`, `ULONG`, `PVOID`, scalar `ULONG`, `PBOOLEAN`. Its own
`RET20` removes 20 argument bytes after the WoW64 transition returns.
On build 29695 the pure-x86 export RVA is `0x77490`; the CHPE export RVA is
`0x1BCEB0`. The historical six-argument Dr. Memory declaration in
`references/drmemory-ntwow64.h` does not describe this installed ABI.

This ARM64 profile admits the measured BASE server1 on independently
captured kernels `10.0.29695` and `10.0.29698`, session0, and `10.0.29704`,
session1. Both immutable selected CSR
metadata and process-owned WoW64 metadata must match. Guest-visible version
fields cannot select a native kernel profile. Other servers, kernels,
unbound sessions and captures exceeding 80 bytes produce an explicit unsupported
result. This is a bounded startup bridge, not complete CSR or Windows
process emulation.

## Primary evidence

`initial-raw-v4.json` preserves a native ARM64 debugger observing the
unchanged original x86 hardware-fault executable. The debugger selects
`PS_ATTRIBUTE_CHPE=0`, discovers the remote pure-x86 NTDLL export, verifies
the leaf bytes, and observes actual entry and return. It temporarily patches
only the owned child's entry/return bytes, restores protections and bytes,
and leaves the API result unchanged. The original native executable
completes its access violation, vectored handler, saved-context continuation
and exit0. Its bytes and both installed NTDLL files are hashed before and
after the run.

`initial-29695-v8.json` contains 26 fresh/retry cases and 32 API returns.
`initial-29695-v9.json` adds five cases and six returns. The corresponding
`initial-raw-v8.json` and `initial-raw-v9.json` retain complete receipts and
base64-encoded stdout bytes. These controls use the separate minimal
`initial-child-v1.cpp`; after each matched return and state snapshot, the
debugger terminates only that owned diagnostic child with exit70. Exit70
means observation completion, not application success.

`family-raw-v2.json` preserves 336 repeated calls across default,
CHPE-enabled and pure-x86 child processes: two exports, 56 cases, three
processes. The pure and CHPE repeated-call matrices agree on the tested
status, guard and copyback cases. Repeated calls do not establish the
first-call contract; the fresh-process controls are necessary.

`artifact-identities.json` binds the exact executed sources, drivers and
raw captures. `initial-v4.cpp`, `initial-v8.cpp`, `initial-v9.cpp`,
`family-v4.cpp` and their drivers are preserved byte-for-byte. Failed
predecessor versions remain immutable in the task evidence archive and
are not treated as successful controls. PHNT declarations provide debug
object and process-attribute layouts; native observations own behavior.

## State and copy order

| Reached phase | Retained client state | Next caller access |
|---|---|---|
| Non-NULL buffer, length0 | No new handles, mappings or PEB writes | Return `STATUS_INVALID_PARAMETER` |
| NULL buffer before connection | No connection or PEB writes | Optional Boolean store0; success |
| First root lookup fails | No new handles, mappings or PEB writes | Return native lookup/capture status |
| First caller-buffer capture faults | Two unmapped Section handles | Return access/guard status; Boolean untouched |
| First capture completes | Port, writable view, readonly selected view; native PEB published | Optional Boolean store0 |
| Boolean store faults | Connection and native PEB survive; PEB32 untouched | Return access/guard status |
| Boolean store completes | Publish PEB32, including on a server-size rejection | Return server status |
| Connected call, successful 8-byte reply | Existing connection reused | Write captured bytes back before Boolean |
| Connected call, rejected size | Existing connection reused | Skip buffer writeback; then Boolean and PEB32 |

The two handles retained by an initial buffer fault are the selected
`\Windows\SharedSection` with access `0x00000004` and an unnamed
65536-byte committed Section with access `0x000F001F`. A failed retry retains
another pair. There are no mapped views at that frontier. Completing a
connection closes its provisional Section handles and retains one ALPC
Port handle with access `0x001F0001`. Prior failed attempts' handles remain.

The connected process has a 65536-byte writable shared view and a
1048576-byte readonly section reservation. The readonly reservation commits
five 4096-byte pages and leaves its tail reserved:

```text
committed = 5 * 4096 bytes = 20480 bytes
reserved tail = 1048576 - 20480 bytes = 1028096 bytes
new committed client bytes = 65536 + 20480 bytes = 86016 bytes
```

The model uses owned virtual objects and private address spaces. Port views
share real guest backing with the modeled peer. The readonly mapping retains
the selected section identity; server pointers remain protocol values and
are never dereferenced in a host process. A retired/replaced port or view
cannot borrow the stored connection record to return success.

| PEB | Offset | Width | Published value |
|---|---|---|---|
| Native64 | `0x88` | 8 bytes | Local readonly base |
| Native64 | `0x98` | 8 bytes | Local readonly base + `0x750` |
| Native64 | `0x380` | 8 bytes | Selected server readonly base |
| x86 | `0x4C` | 4 bytes | Same local readonly base |
| x86 | `0x54` | 4 bytes | Same local statics pointer |
| x86 | `0x248` | 8 bytes | Same 64-bit server readonly base |

A readonly buffer succeeds on the first connection and faults on a later
successful-size call because the latter performs writeback. A writable
guarded Boolean consumes its guard; a readonly guarded Boolean returns
access violation without consuming the guard. A retry with NULL buffer
after a Boolean fault still publishes the pending x86 PEB fields.
Root lookup is case-sensitive: `\windows` and `\WINDOWS` fail before
resource creation. A trailing separator introduces an empty appended-name
component and returns `STATUS_OBJECT_NAME_INVALID`. Later connected calls
do not visit the root pointer.

The three modeled native64 CSR PEB fields must match the owned connection,
or initial zeros before it exists. A changed field produces an explicit
unsupported result. This is checked again after the Boolean store, so a
Boolean alias into those source fields cannot fabricate a successful PEB32
copy. The alias test validates this model boundary; it does not claim a new
native observation for arbitrary native64 RTL mutations.

## Validation surfaces and assumptions

Shared Rust tests replay all 31 captured cases and 38 returns, checking
statuses, retained handle counts, committed mapped bytes and both PEB
publication phases. Strategic tests also exercise backing coherence, the
reserved readonly tail, readonly first/late calls, Boolean guard priority,
retired port identity, native PEB pointer consistency, Boolean source aliases,
architecture filtering and native-profile rejection.
The Windows ARM64 installed-leaf test executes the actual pure-x86 leaf and
its `RET20`; other kernels exercise its explicit unavailable result.
The original hardware-fault fixture, source, assertions and budgets remain
unchanged. Complete process-emulation qualification is a separate gate.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| WC1 | Installed leaf has five arguments and a scalar count; owns bridge transport | Native entry frame, wrapper bytes, actual calls and installed `RET20`; a sixth consumed slot would falsify it | Confirmed; historical six-slot declaration falsified |
| WC2 | Repeated calls describe first-call resource/copy behavior | Fresh readonly buffer, Boolean faults and repeated failed captures | Falsified; separate first/connected phases implemented |
| WC3 | Only independently captured ARM64 29695/session0 metadata admits this profile | Spoof guest version, mismatch private kernel, retire port/view; admission from guest fields would falsify it | Confirmed for the measured profile |
| WC4 | Private transport state retains the bridge-established contents and protections; response semantics depend on that profile | Unmap/replace the transport view or close its port (identity checks reject reuse); arbitrary same-owner private-view mutations require a new native/model comparison | Retained; not generalized beyond the captured startup calls |

| Impact | Remaining boundary | Effect on this changeset |
|---|---|---|
| High | Overall Linux/macOS/Windows installed-library and original fault-fixture completion require independent evidence | No full-goal completion claim |
| Medium | Other native kernels, sessions, CSR servers, larger captures and native64 RTL state beyond the three owned CSR fields are unqualified | Explicit profile boundary; not generalized from these controls |
| High | The Windows volume-device replay has 24 disk-row mismatches: its recorded flags are `0x00020020`, while a direct native29695 query now returns `0x00220020` with the same device7/status0/position7 | Does not block this CSR group; blocks a full-green Windows qualification claim. `volume-control-v1.py` and its hash-bound result preserve the observation. |
| Medium | Native probe success and shared Rust checks do not prove a shipping plugin or current-root package runtime | Root owning check and paired gitlink publication recorded separately |

No public C ABI, ISA/SMIR/JIT behavior, persisted schema, default feature,
package layout or host-directed IPC contract changes. Shared implementation
and replay tests compile on Windows, macOS and Linux; host-native leaf
execution is a distinct Windows gate.

Run `python3 verify.py` (or `python verify.py` on Windows) from this directory
to check producer identities, the 31/38 fresh/retry projection, cross-family
336-call equality, original native exit0 and the separate volume observation.
The verifier is read-only and uses the Python standard library.

## Historical 29695 validation results

| Host | Final CSR filter | Tail ordinal check | Complete C API | Evidence verifier |
|---|---:|---:|---:|---|
| macOS ARM64 | 10 passed | 1 passed | 191 passed | Passed |
| Linux x86-64 configuration under ARM64-hosted Docker | 10 passed | 1 passed | 191 passed | Passed |
| Native Windows ARM64, including installed pure-x86 leaf | 11 passed | 1 passed | 191 passed | Passed |

Every listed selected suite has zero failures and zero ignored cases. The
final CSR/C API source frame contains 17 changed-source/corpus identities and
56 retained identities. The additional native-entry draft and five existing
tracked changes remain outside this changeset. Native probe sources and the
original hardware-fault fixture are unchanged.

The first broad Windows-personality runs reported 1476 passed/1 failed on
macOS, 1470 passed/1 failed on Linux, and 1602 passed/3 failed on native
Windows. The old tail-ordinal test expected the preceding service to be last;
its corrected test checks both appended families against each complete prior
symbol list and passes independently on all three hosts. The broad filters
were not repeated after that test-only correction and final private-native-PEB
consistency guard. Their original verdicts remain recorded.

The other two native-Windows broad failures remain separate: the volume
corpus flag difference above and the unchanged hardware-fault fixture.
That fixture passes its ARM64 case and the x86 CSR call, then stops at
unimplemented `NtQueryInformationProcess` class26 (`ProcessWow64Information`).
Its final explicit rerun reports 0 passed/1 failed/0 ignored at the same
frontier. Neither overall Windows qualification nor the full host-library
process objective is complete.

## ARM64 kernel 29698 qualification

`profile-29698-v1.json` adds a separately measured Windows 10.0.29698,
ARM64, session0 profile. The installed CLI reached the existing explicit
`NtWow64CsrClientConnectToServer` unavailable result before this amendment.
The private captured kernel, machine, session and selected server metadata
continue to own admission. The existing native AMD64 profiles retain their
independent contracts.

Six frozen C++ sources and the original x86 fault executable were reused
without editing their bytes. The compiler adapter uses the archived CMake
project, C++20, static CRT, `/Od /EHsc /utf-8 /W4 /WX` and Windows SDK
10.0.26100.0. The minimal diagnostic child retains `/GS- /Zl`, its explicit
entry point and kernel32 imports. All build outputs remain in the
selected task tree.

| Fresh observation | Count | Comparison with the retained controls |
|---|---:|---|
| First-call/retry cases | 31 | All 38 statuses, handle deltas, new handle grants/types/names and mapping geometries agree |
| Publication phases | 38 | Native64 and PEB32 publication/nonpublication agree at each return |
| Repeated calls | 336 | All semantic rows agree exactly across default, CHPE-enabled and pure-x86 children and with the older capture |
| Original native fault executable | 1 | Completes with exit0 |

The pure-x86 export now has RVA `0x77030`; its five-argument ABI and own
`RET20` cleanup remain unchanged. Captured process addresses and the number
of changed pointer bytes vary with ASLR. Raw logs retain them; the typed
comparison checks publication state rather than treating pointer-byte
counts as a new service policy. The controlled first/retry children still
end with exit70 after observation.

The canonical archive is `wow64-csr-29698-native-artifacts-v1.zip`, 7163538
bytes, SHA-256
`60a3deccd08004edcb3b19259f37ee0d7a0088b458b9494707d5a47135057c5b`.
Its 403 payloads retain the six actual observer/child images, compiler and
source identities, raw output, actual NTDLL providers, CMake input and the
original fault executable. Provider hashes and all source/image hashes
were checked before and after native execution.

Check the byte-bound projection and its frozen local source inputs:

```sh
python3 -I -B docs/specifications/windows/native-wow64-csr-connect/check-29698.py
```

With the retained archive available, regenerate the projection:

```sh
python3 -I -B docs/specifications/windows/native-wow64-csr-connect/check-29698.py \
  path/to/wow64-csr-29698-native-artifacts-v1.zip > profile-29698-rebuilt.json
```

The output must equal `profile-29698-v1.json` byte for byte. On Windows,
use `python` for the interpreter command. The archive verifier first
reproduces every old typed step with its parser, checks every archive
payload, then compares the fresh native semantics. Its no-argument mode
checks the local frozen sources and projection; it does not check the
separately retained raw archive.

The shared regression replays all 31 fresh cases and 38 returns with
matching 29698 process and selected-server metadata. An additional
regression verifies that changing guest-facing version fields cannot
override the captured identity, and that adjacent/foreign kernel,
architecture and session mutations preserve caller bytes, native CSR
fields, handle counts and commitment. The existing Windows installed-leaf
test now exercises this exact profile. The pre-fix regression fails at
the explicit unmeasured-profile boundary; full platform qualification of
the amendment is recorded separately.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| WC5 | The measured 29698 ARM64/session0 BASE bridge retains the selected first/connected contract. | Frozen first/retry and family controls, original native fault completion and exact typed comparison. | Admit exactly 29698 with matching captured metadata. | Readonly/guarded buffers, Boolean faults, failed retries, root syntax and partial publication. | Any differing status, resource geometry, publication phase or leaf cleanup. | Confirmed for recorded native controls; shared and installed-runtime qualification are separate gates. |

High-impact remaining scope includes complete installed-process startup,
other native kernels/sessions, larger captures and other CSR servers.
The independent mapped-filename profile currently blocks another installed
CLI fixture on 29698. These native observations do not establish completion
of the full Linux/macOS/Windows process-emulation objective.

## ARM64 kernel 29704 qualification

`profile-29704-v1.json` records a fresh Windows `10.0.29704` ARM64/session1
capture. It contains 31 first-call/retry cases and 38 measured returns,
plus the identities and comparison results for 336 repeated calls across
three separately created default/enabled/disabled CHPE children. Every
original native invocation completes with exit status 0 and empty stderr.
After observing each first-call/retry sequence, the debugger removes its
breakpoints and restores the original call frame. That cleanup call runs
to natural child exit; it is excluded from the 38 measured returns.

The three executed source derivatives are preserved unchanged under
`captured-29704-v1/`. The archive also retains their original predecessors,
strict compiler/linker commands, exact executed PE images, launch bindings,
complete native output, receipts and all three captured NTDLL providers.
The archive is `wow64-29704-native-artifacts-v1.zip`, 18897725 bytes, SHA-256
`4cedec9326b946cd15e7216f226dda0cecd3a00d728cad9e083dbe0f3d95bd1f`.
It has 83 payloads plus its manifest.

All measured statuses, new handle grants/types, mapped geometry, per-step
handle deltas and publication phases agree with the retained controls.
For the named readonly section, only the independently captured session
component changes from `\Windows\SharedSection` to
`\Sessions\1\Windows\SharedSection`. Actual names, process addresses and
changed-byte counts remain in the raw logs; ASLR-dependent byte counts are
compared as publication booleans. All 336 repeated-call semantic rows
match exactly. These comparisons do not claim full emulated replay of
the separate 336-row family matrix.

Provider identity comes from each running child. Default creation and
explicitly disabled CHPE map `SysWOW64\ntdll.dll`; explicitly enabled CHPE
maps `SyChpe32\ntdll.dll`. A creation-mode label alone does not identify
the executing provider. Each captured leaf retains its own five-argument
`RET20` cleanup.

Verify published source bytes and the frozen projection:

```sh
python3 -I -B docs/specifications/windows/native-wow64-csr-connect/project-29704-v1.py
```

Rebuild it from the retained archive:

```sh
python3 -I -B docs/specifications/windows/native-wow64-csr-connect/project-29704-v1.py \
  path/to/wow64-29704-native-artifacts-v1.zip > profile-29704-rebuilt.json
```

The output must equal `profile-29704-v1.json` byte for byte. On Windows use
`python`. No-argument verification checks published sources and the frozen
projection; it does not verify the separately retained raw archive. Archive
projection verifies all payloads, exact launch/source/image bindings,
original process verdicts, held provider identities and raw observations.
It takes O(B + R) time and space, where B is archive size and R is projected
rows; it does not rerun native controls.

The shared regression reproduces the 31 cases and 38 returns with matching
29704 process and session1 server metadata. Before admitting this exact
kernel, it fails at the explicit unmeasured-profile boundary. Additional
tests exercise guest-facing version changes, adjacent/foreign captured
identities, mismatched native/WoW64 PEB sessions, owned view publication and
retired port rejection. Production admission changes only the measured
ARM64 build set; existing ownership and guest/host permission boundaries
remain in force. Windows installed-leaf execution and complete owning
binary results remain separate qualification gates.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| WC6 | Exact 29704 ARM64/session1 retains the measured BASE first/connected contract. | 31 cases, 38 returns and 336 repeated native rows, with original natural-exit verdicts. | Exact native-kernel admission. | Root syntax, caller faults, retries, both publication phases and owned identity retirement. | Any differing status/resource/publication or installed-leaf result. | Native comparison confirmed; emulator qualification recorded separately. |
| WC7 | Creation-mode names uniquely identify the executing provider. | Initial expectation before mapped-provider capture. | No implementation depends on it. | Default/enabled/disabled creation. | Actual mapped path differs from the inferred path. | Falsified; default/disabled use SysWOW64 and enabled uses SyChpe32. |

High-impact remaining scope includes ordinary x86 startup beyond this
bridge, AMD64 exception-dispatch qualification and the full installed-library
process objective. Compatibility callers on this ARM64 kernel do not
establish native AMD64 kernel support. The original startup/fault fixtures
and their assertions and budgets remain unchanged.
