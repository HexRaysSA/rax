# Native event opening

`NtOpenEvent` opens an existing guest Event through the captured object-manager
directories. Win32 `CreateEventW` and native opens share one object identity,
signal state and final-handle lifetime. Each open has its own access grant and
inheritance flag. Closing the creator handle or replacing the current directory
catalog does not invalidate another handle or a retained directory route.
Guest names never reach a host object-opening API.

## Reproduce the controls

From the repository root, verify the retained producer, primary-source and raw
observation hashes on Windows, macOS or Linux:

```text
python tools/ci/windows_open_event.py --verify-corpus
cargo test --locked --no-default-features --lib native_open_event_ -- --test-threads=1
```

The verifier reports two producer inputs, three process ABIs and 1,521 native
records. The Rust selection runs four tests: native dispatch and lifetime,
prior export ordinal/trap preservation, independent observation replay, and
Win32/native state sharing across namespace replacement. The separate
`native_named_objects_distinguish_missing_parent_from_private_leaf` test checks
missing intermediate directories in sessions 0 and 42.

On native Windows with MSVC and CMake available, capture fresh observations and
replay them immediately using an already-prepared Rust test executable:

```text
python tools/ci/windows_open_event.py
```

The output directory must be new. To retain multiple deliberate campaigns, pass
`--output target/native-open-event-next`. All compiler scratch and Cargo build
outputs must remain inside this checkout. The helper builds x64 and x86
observers; on an ARM64 host it also builds an ARM64 observer. It retains the
executables, JSONL observations, provider identities, hashes and test logs under
the output directory, and removes completed CMake build trees. A failed command
leaves its evidence available for diagnosis. The existing Windows C API CI lane
runs this helper and uploads its artifacts even after failure.

Each observer creates its own Event and Semaphore, opens its own directory,
queries the actual native object name, and releases all handles. It additionally
queries the fixed `HookSwitchHookEnabledEvent` name without mutating that event.
The latter is diagnostic host state: fresh replay checks that the independent
guest namespace still reports absence. It does not import a host Event.

## Retained evidence and boundaries

`controls-v1.json` binds the producer source hashes, process image hashes,
pointer widths, kernel versions, balanced handle counts and raw output hashes.
Each ABI contains 507 cases:

| Group | Cases per ABI |
|---|---:|
| 17 access requests against Event, missing name and wrong type | 51 |
| Object-attribute flags | 16 |
| 10 output placements × 43 attribute/name arrangements | 430 |
| Absolute, relative, missing, intermediate and fixed names | 6 |
| Manual/automatic reset × initial signal state | 4 |

The retained campaign ran ARM64, x64 and x86 processes on one ARM64 Windows
kernel, version 10.0.29695. These are three process ABIs, not three kernel
architectures. Successful opaque HANDLE bytes alone are normalized to `0x42`;
NTSTATUS values, output sentinels, access grants, handle attributes, event
type/state and page-protection transitions are retained exactly.

The retained replay makes 1,518 native comparisons and three explicit unsupported
privilege checks. Fresh replay additionally makes 505 native comparisons per
process ABI, one unsupported privilege check and one independent-namespace
check for the fixed foreign host Event. The original retained replay still runs
when fresh observations are supplied through `RAX_OPEN_EVENT_CORPUS`.

The producer resolves `NtOpenEvent` from NTDLL and records both
`GetModuleFileNameW` and `GetMappedFileNameW` output. The helper translates the
mapped device path through `QueryDosDeviceW`, then hashes that actual backing
file before and after the campaign. In this capture the ARM64 and x64 providers
resolve to `System32\ntdll.dll`; the x86 provider resolves to
`SyChpe32\ntdll.dll` despite a logical `System32` path. A provider mapping or
hash change rejects the campaign. Primary Microsoft documentation is retained
in the HTML files and indexed with URLs, retrieval times and hashes in
`sources.json`.

## Measured semantics

Native64 probes the output HANDLE before attributes; the WoW64 conversion
captures its input first. WoW64 reads a declared name length below 65,534 bytes
before kernel alignment/length validation. At or above that limit it omits the
conversion-buffer read. Kernel name failures follow the output probe and copy a
zero four-byte HANDLE; conversion faults leave the output sentinel untouched.
The page-boundary cases distinguish an odd three-byte read from a rounded
two-byte read. Reached guards are consumed exactly as recorded.

The opening-specific rejection of `OBJ_EXCLUSIVE` follows name capture.
Missing names and wrong object types precede access checks. Generic requests map
to Event rights; zero and unrecognized rights are denied. A missing intermediate
directory returns `STATUS_OBJECT_PATH_NOT_FOUND`; an absent private final name
returns `STATUS_OBJECT_NAME_NOT_FOUND`. Unsupported custom security descriptors,
QoS and `ACCESS_SYSTEM_SECURITY` remain explicit boundaries. In particular, the
guest does not fabricate a native privilege result without captured privilege
state. Named `NtCreateEvent` remains a separate unsupported creation service;
the positive opening tests use the existing Win32 creator contract.

The service is appended as a separate export family. Prior NTDLL export
ordinals and synthetic trap addresses remain unchanged. No public C ABI layout
changes. Shared guest behavior and all three process-ABI replays run on Windows,
macOS and Linux; the independent C observer itself requires Windows and MSVC.
The opening sequence uses the build 29695 observations here. Existing creator
and state operations retain their separately measured profiles.

Capture requires O(n) time and temporary storage for n input bytes; a bounded
WoW64 conversion reads fewer than 65,534 bytes. The existing named-object lookup
scans m object bodies and compares at most l UTF-16 units per name, O(m l).
Existing handle allocation scans h handles, O(h). This service reuses those
algorithms; throughput and alternative indexes were not evaluated.

## Complete local qualification

| Host operating system | Full library | C API | Windows CLI | All targets |
|---|---:|---:|---:|---|
| macOS ARM64 | 8,879 passed | 192 passed | 8 passed | Compiled |
| Linux container, reporting x86-64 | 8,869 passed | 192 passed | 8 passed | Compiled |
| Windows ARM64 VM | 8,192 passed | 191 passed | 10 passed | Compiled |

All full-library rows have zero failures, zero filtered tests and two existing
ignored tests: `test_lift_lower_full_microkernel` and
`test_roundtrip_exact_bytes_microkernel` in `smir::lower::validation::tests`.
The Linux container is not evidence of a physical x86-64 host. The Windows row
and all three native observer ABIs use an ARM64 kernel. macOS Clippy, formatting
and all twelve workflow-pinning checks pass. Each platform's final source audit
covers the same 7,254 inputs. The public C API remains 1.15.0; its 73,534-byte
header retains SHA-256
`baaf643f62c525d923529ccbf75a97505a31831592a8aa91ab9be71f5ec144b5`.
This qualification prose and the raw-reference Git whitespace attributes were
finalized afterward. Only this README and `.gitattributes` change from that
audited frame; compiled inputs and the tested library/CLI image hashes remain
unchanged on all three hosts. Native JSONL keeps its original CRLF bytes, and
the HTML references keep their original whitespace and hashes.

The first macOS full run failed two existing socket tests because its generated
absolute socket addresses occupied 114–115 bytes, exceeding Linux's 108-byte
`sun_path` field. The same executable passes both with a shorter in-checkout
temporary path. That first run also observed an updated 2 ms timer completing
before the test's immediate reap expected it. The unchanged test passes in
isolation and in the complete rerun. All 8,879 tests then pass with the same
executable SHA-256; original failures and successful rerun remain archived. No
assertion or product source was changed for these runner conditions.

Native Windows additionally runs the fresh observer and the four-test replay
selection after preparing the exact Rust test image. All three process ABIs
produce 507 fresh records with balanced handles and stable mapped-provider
hashes. The complete library then runs with its ordinary environment, preserving
the retained corpus replay independently of the fresh checkpoint.

Installed `cmd.exe /d /c "echo RAX_COMMAND_PROCESSOR_SNAPSHOT"` exits zero
natively. The qualified emulator advances beyond `NtOpenEvent`, then exits 125
at unsupported `NtQuerySystemInformation` class 164. The compared CLI is
27,337,728 bytes with SHA-256
`9d2fc4d1fe87ab75697d79a35ec75f2130c38d294617ec039c2c58e485a03b46`;
the CMD image has SHA-256
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`.
Both execution and final source/image checks pass; the emulator does not yet
match complete CMD execution.

## Assumption register and scope

| ID | Assumption and dependent result | Basis and stress test | Falsification probe | Status |
|---|---|---|---|---|
| E1 | Captured selected directories and private Event identities define native opening routes. | Win32/native shared-state tests include sessions 0/42, wrong types, independent grants, creator closure and catalog replacement. | A native/private-name comparison or retained-route lifetime test disagrees. | Retained, tested for these profiles. |
| E2 | Opening-specific flag rejection precedes name capture. | Initial adaptation; tested with `OBJ_EXCLUSIVE` plus invalid/guarded input. | Native observations returned access/guard faults first. | Falsified; implementation validates this flag after capture. |
| E3 | The logical loader path identifies the mapped x86 provider. | Initial path-based binding; tested with mapped-file resolution. | The mapped path resolves to `SyChpe32` while the logical path says `System32`. | Falsified; actual mapped-file binding replaces it. |
| E4 | Final prose and raw-reference Git attributes do not change compiled or tested inputs. | Only this README and `.gitattributes` change after the 7,254-input gates; dependency lists and library/CLI hashes are checked on all three hosts. | A dependency list includes these files, an image hash changes, or another source differs from the audited frame. | Confirmed for the qualified images. |

High impact, separate scope: full process startup still requires the remaining
NT/Win32 services and fixed-subject acquisition paths. This finite Event-opening
campaign does not establish complete Windows process support or equivalence on
unmeasured kernels. Full object security and named native Event creation remain
explicit unsupported contracts. Medium impact: each future kernel profile must
retain fresh provider-bound observations; a process architecture label alone is
insufficient provenance. These limits do not block private Event opening under
the measured contract.
