# Pure x86 CSR BASE connection on ARM64 Windows 29695

The installed `NtWow64CsrClientConnectToServer` leaf takes five 32-bit
arguments: `PWSTR`, `ULONG`, `PVOID`, scalar `ULONG`, `PBOOLEAN`. Its own
`RET20` removes 20 argument bytes after the WoW64 transition returns.
The observed pure-x86 export RVA is `0x77490`; the CHPE export RVA is
`0x1BCEB0`. The historical six-argument Dr. Memory declaration in
`references/drmemory-ntwow64.h` does not describe this installed ABI.

This implementation admits the measured BASE server1 on independently
captured ARM64 kernel `10.0.29695`, session0. Both immutable selected CSR
metadata and process-owned WoW64 metadata must match. Guest-visible version
fields cannot select a native kernel profile. Other servers, kernels,
sessions and captures exceeding 80 bytes produce an explicit unsupported
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

## Validation results

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
