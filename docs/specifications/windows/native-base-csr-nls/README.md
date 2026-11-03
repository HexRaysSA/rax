# ARM64 BASE per-user NLS exchange

This corpus measures BASE CSR API `0x0001001b` on native ARM64 Windows
10.0.29698. A fresh ordinary-user child first invokes
`GetUserDefaultLocaleName` and `GetLocaleInfoEx`; its real ALPC exchange is
observed at entry and return. A separate fixed query through NTDLL's capture
helpers returns the same 1660 information bytes twice. The private native API
symbol name is unknown; the NLS classification follows the public caller and
measured locale, subject and formatting data.

The controller debugs only its own child, restores each intercepted instruction,
resumes the original native call, and checks entry/return pairing. Successful
controls require the child to exit 41 naturally. Source/image/output identities,
native NTDLL identity and subject SID are retained in the build and raw receipt
files. This is host compilation followed by native execution, not a native
compiler qualification.

| Field | Measured value |
|---|---|
| Native profile | ARM64, Windows 10.0.29698 |
| Ordinary-user session | 1 |
| API number | `0x0001001b` |
| PORT_MESSAGE data / total | 40 / 80 bytes |
| Information pointer slot | Message+64 bytes |
| Information size slot | Message+72 bytes,1660 bytes |
| Capture size | 1704 bytes = 40 + 1660 + 4 |
| Capture pointer count / offset | 1 / 64 bytes |
| Information relative to capture | +40 bytes |
| Received message size | 80 bytes |

## SYSTEM counterexample and later observations

The earlier SYSTEM/session0 control (`native-receipt-v3-system.json`) reports
successful ALPC transport and `STATUS_UNSUCCESSFUL` in the service reply. Its
1660 information bytes remain unchanged; the child exits48 and the controller
exits 22. This is a retained counterexample, not a passing control.

Later SYSTEM controls return successful service replies containing 1660 zero
bytes. V4 uses distinct A5/5A input patterns; V5 uses six inputs including repeated
BAADF00D and zero patterns. All eight successful payload observations agree.
The cause of the transition from failure to success is unknown. No permanent
SYSTEM-specific failure rule is inferred.

V5's child stdio can interleave with controller debug records. The complete
payloads dumped by the controller while its child is stopped remain the byte
oracle. The native child also compares successful results and checks that a
failed request leaves its input unchanged before exiting41.

## Implementation contract

The installed adapter performs only a fixed current-process query during native
runtime acquisition, after matching the independently captured kernel,
architecture, session, readonly section and server identity. It registers the
information pointer in the message itself and frees the exact native capture
allocation with RAII. ReadProcessMemory validates bounded returned bytes. Two
native samples must agree; an inconsistent snapshot is rejected.

The snapshot represents either immutable information bytes or the measured
unsuccessful service result. It is attached to the selected server and each
owned peer. Guest calls validate the exact packet, capture size, pointer count,
pointer slot, shared-view ownership and bounds before publishing outputs. A
successful reply copies the selected bytes through the server's shared view.
An unsuccessful service reply preserves caller information bytes while keeping
ALPC transport success distinct from the service status.

Each connection reuses one private 4096-byte server capture page and increasing
modeled message identifiers. USER's existing 584-byte exchange and readonly view
mapping retain their own schema. The BASE payload has no added client mapping.
Snapshot acquisition and reply copying take O(B) time and space, B=1660 bytes.
Guest packets, addresses, handles, strings and requests never reach host IPC.

Admission for this new BASE snapshot is ARM64 Windows 10.0.29698. Existing other
CSR profiles retain their earlier behavior. Shared reply semantics compile on
Windows, macOS and Linux; installed acquisition uses the native Windows adapter.
No public C ABI, default feature, dependency pin or persisted format changes.

## Verification

Run from the RAX checkout:

```text
python3 -B docs/specifications/windows/native-base-csr-nls/verify.py
```

Expected output begins `verified: public/fixed user NLS identity`. The verifier
checks source/build/image/output bindings, subject/session identity, exact
packet/capture geometry, public-versus-fixed payload agreement, SYSTEM's failed
reply and its later blank successful replies. `native-user-information-v1.bin`
and `native-system-information-v1.bin` retain the distinct complete payloads.

Shared regressions exercise repeat replies, private capture lifetime, missing
snapshots, malformed capture fields, foreign views/profiles, subject-specific
payloads and unsuccessful service replies. The native installed-NTDLL test also
executes NtAlpcSendWaitReceivePort against the captured host snapshot after
establishing a real owned section-backed guest connection.

## Assumptions and bounds

| ID | Assumption / basis | Stress test / falsification probe | Status |
|---|---|---|---|
| A1 | Startup alone reaches this API. | A fresh native child connects but exits41 without an ALPC exchange. | Falsified; public locale queries supply the positive control. |
| A2 | The fixed current-process query matches the public locale operation. | User V2/V3 independent public/fixed observations must have identical complete bytes. | Confirmed for the measured profile. |
| A3 | One immutable native acquisition snapshot can supply the selected peer. | Two capture samples must agree; subject data and failed replies remain distinct. | Retained; later host locale/cache changes require a new snapshot. |

High impact, outside this exchange: full file-backed command execution remains a
separate acceptance criterion. A diagnostic wrapper exit 0 does not establish
successful guest-program completion. The unmeasured cause of SYSTEM's earlier
service failure also remains unknown. Other native kernel/architecture profiles
require their own measured reply contracts before this adapter admits them.

## Runtime and build qualification

`python3 -B docs/specifications/windows/native-base-csr-nls/verify_runtime.py`
checks the retained 58 native core case-runs (51 unique cases), source bindings,
installed NTDLL exchange and actual file-backed CMD boundary. The latter remains
incomplete at NtQuerySystemInformation class 134; its wrapper exit 0 is not guest
success. `qualification-v1.json` records the compiled/observed scopes.

The six new cases and 53 selected owning cases pass on macOS, as do 244 CAPI tests.
Thirteen focused cases pass on Linux under x86-64 translation on AArch64. All
workspace targets compile for macOS, Windows ARM64, Windows x64 and Linux x64;
strict library lint passes on macOS and Windows ARM64.

The Windows CAPI executable built and linked. Its runtime collection remains
pending after Parallels RPC failures; no native CAPI pass is claimed. The optional
`--capi` receipt verification requires both complete subject-specific receipt
files and fails if they are absent. It does not execute or replace those tests.
