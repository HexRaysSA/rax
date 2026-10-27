# Independent AMD64 image-extension availability

`run-v1.py` records `NtQueryVirtualMemory` class 14 for independently owned
NTDLL image sections on native AMD64 Windows. It observes both `KnownDlls`
and `KnownDlls32`, and sections created from the matching installed files.
Ordinary mapping, explicit image-machine mapping, and explicit machine mapping
with the image-rebase flag are separate observations.

Each mapped view records valid types 0 and 1, invalid type 2, nonzero reserved
flags, and a 23 B short output. Complete 24 B before/after buffers, NTSTATUS,
and native `SIZE_T` ReturnLength are retained. The probe records up to eight
metadata-only tail regions, each bounded to 4 MiB, without dereferencing or
executing the mapped image. All maps and handles are released. Input hashes and
the process handle count must match before and after the campaign.

The existing Windows 2022 and Windows 2025 observation jobs run the producer;
it adds no CI jobs. `target/native-image-extension-amd64-v1.json` is created
exclusively so an observation cannot overwrite a completed or active run.
Unsupported map/query statuses are retained as observations, not converted to
successful absent-extension results. This campaign does not change runtime
behavior or establish full process-emulation completion.

Assumption A1 is revised: the observed build-26100 `STATUS_NOT_SUPPORTED`
is specific to extension type 1 across the captured image architectures and
mapping modes, while type 0 retains its independently observed payload result.
Both availability observations and the version-2 query matrices have completed;
their measured distinctions and the implementation are recorded below.

High-impact boundary: the existing guest class-14 absence semantics were
measured on native ARM64 kernels. Independent AMD64 availability and fault
precedence are separate evidence requirements; this observation does not
silently extend the ARM64 contract to every AMD64 kernel.


`run-query-matrix-v1.py` additionally compiles the unchanged original query
matrix plus new, separately named type-1 boundary and SIZE_T-limit producers.
The latter change the valid requested type from 0 to 1; every original producer
is preserved. Native x64 and WoW64 x86 processes each record 4200 query cases,
15480 boundary/alias/guard/rights cases, and 1092 length-limit cases. The wrapper
retains raw stdout, stderr, complete reports, source/compiler/executable/runtime
identities and terminal results. Its native producer deadline is 90 s, matching
the existing observation controller; original emulator fixture budgets do not
change. These measurements qualify validation order before guest policy changes.


The first matrix-controller attempt rejected Windows checkout CRLF bytes before
compiling or executing a producer. The failed v1 report is preserved separately.
`run-query-matrix-v2.py` accepts exactly the pinned LF form or its uniform CRLF
checkout form and records both expected forms and the actual raw SHA-256.
Mixed or otherwise changed source bytes still fail. Native producer sources,
query axes, assertions, and deadlines are unchanged. V1 remains frozen.

## Captured availability and query order

The [availability run](https://github.com/HexRaysSA/rax/actions/runs/40588153275)
records 12 complete owned views per kernel. `profiles-v1.json` retains both
full captures, artifact identifiers, ZIP digests, raw JSON digests, source and
runtime identities, exact output bytes, returned lengths, and region metadata.

| Native kernel | Valid type 0 | Valid type 1 | Native x64 NTDLL tail |
| --- | --- | --- | --- |
| 10.0.20348 | `STATUS_INVALID_INFO_CLASS` | `STATUS_INVALID_INFO_CLASS` | No captured same-owner tail |
| 10.0.26100 | `STATUS_SUCCESS` | `STATUS_NOT_SUPPORTED` | One 4096 B executable extension, then 16384 B reserved |

Build 26100's x86 NTDLL type 0 succeeds with zero RVA/size. Its same-owner
reserved tail is 20480 B. Native type-1 failure leaves all output bytes and
ReturnLength unchanged. An unsupported type is not evidence that type 0 is
absent: discarding the first result would lose actual executable backing.

The [query-order run](https://github.com/HexRaysSA/rax/actions/runs/40589099085)
has six completed producer executions per kernel: native x64 and WoW64 x86,
each with the query, type-1 boundary, and type-1 SIZE_T-limit matrices.
Each kernel has 2 * (4200 + 15480 + 1092) = 41544 cases; both have 83088.
All twelve producers exit 0 with stable inputs; boundary/limit handle counts
are restored. The 2520 x64 NTDLL present-state query controls remain separate
from absent-image replay, leaving 80568 exact portable query replays.

For native build 26100, short length precedes NULL BaseAddress; destination
probes precede rejection of an out-of-user-range BaseAddress. Probe, handle,
flags, image-owner, and valid-type validation precede type-1 rejection. The
previous ARM64 profile retains its observed NULL/range ordering. WoW64 retains
its optional ReturnLength preprobe and class rejection. Build 20348 rejects
the unavailable class before native output probes. Status, complete copied
bytes, returned lengths, guard consumption, page protection and handle counts
are compared with the captured records, without replacing native statuses.

## Runtime ownership

The native image adapter classifies query availability per kind. A measured
native AMD64 type-1 `STATUS_NOT_SUPPORTED` retains the captured type-0 mapping.
Foreign-machine rejections and other statuses still fail. A rejected type may
not modify the initialized capture outputs. Existing image, extension, copy,
page-policy, rebase, and reserved-tail bounds remain unchanged.

The immutable image template separately retains query capability. Two rebase
views must agree on it and on their payloads. Namespace acquisition captures
the native NTDLL capability before guest execution and caches its image through
the existing selected section. Guest queries read this captured fact, never
call the host, and distinguish absent payload from unavailable API/type.
The installed-leaf test selects AMD64 expectations from the independent native
kernel captures rather than deriving them from the implementation's policy.

The extra capability classification is O(1) time/storage. Snapshot copying and
existing query probing retain their previous byte/page bounds and complexity.
The native NTDLL template is acquired eagerly for the captured capability and
then reused by the existing section cache; its lifetime is the namespace's.

| Plane | Scope |
| --- | --- |
| Windows installed libraries | Fixed owned NTDLL image capture, retained extension capability, guest query ordering and installed leaf tests |
| Shared macOS/Linux model | Same immutable state and 80568 native-corpus replays, with the original ARM64 corpus retained |
| Permissions/tools/UI/transport | No guest-directed host query, tool schema, capability grant, UI, or IPC change |
| ABI/persistence/dependencies | No public C layout, persisted format, dependency pin, optional feature, or package-layout change; existing zstd dependency decodes test data |
| CI | Existing two native Windows jobs additionally execute image-query tests and the whole unchanged original hardware-fault fixture; no new job or execution-budget change |

## Corpus reproduction and validation boundaries

`pack-query-corpus-v1.py` pins the original raw JSON digests and verifies
producer completion, raw stdout digests,
case ordinals/counts, exceptions, process ABI, profile inventory and restored
handles. It replaces base64 stdout with its exact ASCII text, retaining every
byte and all other capture fields, and compresses the result with zstd:

```text
python3 pack-query-corpus-v1.py native-image-extension-amd64-query-matrix-2022-raw-v2.json native-image-extension-amd64-query-matrix-2025-raw-v2.json query-corpus-v1.json.zst
```

The decoded corpus is 57148124 B; the compressed artifact is 304969 B,
SHA-256 `3feac47950d4d9d10191b36a3886d6148b3a66b3906afe21f6002f85b387eaa5`.
Rust tests decode it through the existing portable zstd crate with a 96 MiB
decoded-output bound. The raw artifacts and failed v1 controller reports remain separate.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| IX1 | Type availability is independent of payload absence. | All 24 owned-view captures and the independent query matrices. | Retaining native type-0 backing when type 1 is unavailable. | Named/created, native/x86, ordinary/machine/rebase views; conflicting payload/profile tests. | Raw capture comparison, snapshot classification and rebase tests. | Confirmed for the captured profiles. |
| IX2 | Selected native NTDLL capability supplies the same kernel API/type availability for guest-owned images. | Independent main-image and NTDLL queries on both kernels. | Immutable namespace capability and guest query results. | Both guest ABIs, absent/retired/non-image owners, malformed flags/types, lengths, guards and handle rights. | Complete native corpus replay and installed leaves on native kernels. | Portable replay confirmed; new native runtime gates pending. |

The first model replay retained 18 passes and three new failures: native AMD64
NULL/short-length ordering and late upper-address validation differed from the
older ARM64 profile. Correcting those branches preserved every raw record,
existing assertion and original fixture. The subsequent macOS selection passes
21 image-extension tests with zero failed or ignored tests, including all
80568 new exact replays. macOS and Linux additionally pass three availability,
103 CSR, 55 WoW64, nine exception-entry model and all 191 C API tests, with no
failed or ignored tests in these selections. Linux ran in the task's x86-64
container on the ARM64 host; this is not Windows native execution.

The first Windows ARM64 unit build failed before running tests: the installed
leaf test referenced a WNF query field that is not exposed. The corrected test
uses the existing independent `RtlGetVersion` host control. That failed source
frame and its logs are retained. Corrected Windows compilation, installed-leaf,
and unchanged whole original-fixture qualification were then repeated. The
corrected native ARM64 frame passes 23 image-extension tests, three availability
tests, 105 CSR tests, 61 WoW64 tests, all 191 C API tests and the whole original
hardware-fault test, with no failed or ignored tests in those selections.

The AMD64 [candidate run](https://github.com/HexRaysSA/rax/actions/runs/40591957315)
passes the whole unchanged original hardware-fault test on both builds 20348
and 26100. Both also pass all 15 selected CSR tests. Each image-query suite
retains 22 passes and one owner-test failure: its prior success assertion ran
before its native oracle, so it expected success where the native kernel
returns `STATUS_INVALID_INFO_CLASS` or `STATUS_NOT_SUPPORTED`.
The corrected owner test compares actual native status and unchanged outputs
first, then applies successful RVA/size/backing-byte assertions only to actual
native successes. Its class-6 extension flag is independently queried from the
loaded native NTDLL, including reserved-only owner tails. No production code or
original fixture changes accompany this test correction. Its new native gates
remain pending.

High impact, outside this query change and blocking full-goal completion:
complete native 64-bit RTL heap/loader equivalence, broader CSR messages,
full Linux/macOS/Windows host-library process coverage, and the complete owning
Assist runtime/package qualification remain incomplete. The unchanged original
fault fixture and its execution budgets are preserved. This source group does
not claim full process-emulation completion or unmeasured kernel equivalence.
