# Selected native MUI query data

The query implementation uses a bounded copy of the installed runtime's
`NtGetMUIRegistryInfo` data. Acquisition invokes only flags `0`, with native
outputs allocated by the adapter. Guest flags, pointers and lengths never reach
that host call. Two captures at different live output addresses must agree;
the adapter allows three attempts and at most 1 MiB of MUI data within the
existing 64 MiB combined NLS budget.

The original measurements are from Windows 10.0.29683.1000 on an ARM64
kernel. The three executable views contain 1,680 rows each, for 5,040 native
rows. Build 29695 is independently qualified in
[the later kernel record](../native-nls-build-29695/README.md), including x86
large-address-awareness controls and fresh generation observations. Other
Windows builds are admitted by their own observations.

The installed-process workflow's `measure_startup_queries` input runs the
existing 1,680-case producer on AMD64 Server 2022 and Server 2025. It records
the query rows, payload length and hash, and the producer, executable and
NTDLL identities. The producer uses flags 0 and 1 and the invalid bit 4.

The AMD64 builds publish the required size before checking the complete
destination extent. If the extent reaches an inaccessible page, the call
returns `STATUS_ACCESS_VIOLATION` without clearing the accessible prefix.
When the destination aliases the size word, the published size survives
that fault. Both AMD64 runs reproduced this ordering over the 1,680-case
matrix. The emulator binds the results to the x64 process view of native
builds 20348 and 26100. [Capture identities](amd64-inputs.json) bind the runs.

The workflow's `measure_arm64_mui_registry` input runs the same producer as
an ARM64 executable on Windows build 26200. Its 1,680 rows and 1,232-byte
payload have the same hashes as both AMD64 captures. Forty rows differ from
the original ARM64 profile in output clearing or the size word after an
aliasing fault. The replay shares the byte-identical AMD64 log. The
[ARM64 capture identity](arm64-26200-inputs.json) binds its own NTDLL,
producer executable and hosted artifact. Admission requires Windows 10.0
build 26200, a native ARM64 machine and an ARM64 guest.

## Query behavior

Flags `0` and `1` select the measured query behavior. Recognized cache clear or
commit combinations containing flags `2` or `8` report explicit unavailability
before query-specific pointer checks. These cache mutations remain
unimplemented; no host clear or commit operation is invoked.

| Query input | Measured result and ordering |
| --- | --- |
| NULL size pointer | `STATUS_INVALID_PARAMETER`, `0xC000000D` |
| Non-NULL size pointer | Capture the unaligned `ULONG` before validating query flags or the buffer/length relationship |
| Invalid size address | `STATUS_ACCESS_VIOLATION`, `0xC0000005` |
| NULL buffer with nonzero capacity, or non-NULL buffer with zero capacity | `STATUS_INVALID_PARAMETER`; size unchanged |
| NULL buffer with zero capacity | Success; publish the required size |
| Non-NULL buffer shorter than required | `STATUS_BUFFER_TOO_SMALL`, `0xC0000023`; required size published, buffer untouched |
| Sufficient capacity | Publish required size, zero the entire supplied capacity, then copy the payload |
| Destination crosses an inaccessible page on the original ARM64 kernels | Zero the accessible prefix and return a fault before copying the payload |
| Destination crosses an inaccessible page on AMD64 builds 20348 or 26100, or native ARM64 build 26200 | Retain the published required size and return a fault before clearing destination bytes |

The observed payload is 1,232 bytes. The tests use a synthetic payload of that
size; the native rows determine status, publication order, alias effects and
fault effects. They do not substitute a captured host payload for the model's
ordinary runtime acquisition. All recorded query rows preserve last-error
`0x12345678`.

For capacity L and payload size P, publication takes O(L + P) time until the
first inaccessible page and O(4,096 bytes) scratch space, in addition to the
shared O(P) snapshot. Page-bounded writes retain the measured partial-zero
behavior without allocating L bytes of temporary memory.

## Language generation

The selected payload's `ULONG` at offset `0xC` initializes guest
`KUSER_SHARED_DATA.LangGenerationCount` at offset `0x3A4`. The shared guest page
remains read-only. Matching installed kernel symbols identify the field, and
three independent query-only controls observe shared count 1, payload count 1,
and shared count 1 afterward. The installed kernel and symbol identities,
including distinct RSDS/DBI and Info ages, are in `generation-inputs.json`.

AMD64 builds 20348 and 26100 and native ARM64 build 26200 check this
relationship during acquisition. The fixed native shared word before and after
the two payload copies must agree with the payload's language-generation field.

The earlier ordinary guest observer measured shared count 0 and payload count
1. After the initializer correction, the native read-only-page regression test
passes and the ordinary guest observer reports shared count 1 and payload count
1. Its returned 1,232-byte payload matches fresh native queries before and
after execution. The USER32 callback then reaches the next registry snapshot
boundary; these controls do not establish completion of that callback or the
full process-emulation objective.

## Assumptions and evidence boundaries

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| MUI-A1 | Query bytes are self-relative for this selected profile | Different live native allocations and identical payload hashes in three process views | Immutable shared payload | Repeated captures at distinct addresses | Address-dependent bytes or inconsistent captures | Confirmed for recorded profile |
| MUI-A2 | Payload generation and guest shared generation must agree | Matching kernel symbols and query-only native controls; earlier guest mismatch | Guest RTL cache coherence | Native shared-page test and ordinary guest observation | A differing counter or later guest writer | Confirmed for recorded native and ordinary guest observations |
| MUI-A3 | The AMD64 payload language generation corresponds to the same shared-page field | The selected native profile and bounded startup payload are independently identified | AMD64 shared-page initialization | Read the fixed native word before and after two captures into distinct allocations | A differing payload generation, shared word, or pair of payloads rejects acquisition | Checked on every AMD64 acquisition |
| MUI-A4 | Native ARM64 build 26200 uses the same query ordering and shared generation field | Independent 1,680-case capture and payload are byte-identical to both AMD64 captures | ARM64 build 26200 query dispatch and shared-page initialization | Replay unaligned pointers, aliases and inaccessible pages, and compare the host shared word before and after capture | A changed query outcome fails replay, and a differing counter or payload rejects acquisition | Query ordering confirmed, generation checked on every acquisition |

`inputs.json` binds the original producer source, driver, native logs and
receipt by byte count and SHA-256. `generation-inputs.json` binds the independent
counter control. The logs retain their original bytes; scoped Git attributes
disable line-ending conversion. Native adapter coverage, shared replay
coverage, owning C API/Assist coverage and full-product coverage are separate
evidence boundaries.

| Impact | Remaining boundary | Effect |
| --- | --- | --- |
| High | Guest MUI cache clear and commit | Full MUI capability remains incomplete |
| High | Ordinary USER32 callback and owning consumers | Targeted query checks do not establish their completion |
| Medium | WoW64 on physical AMD64 and other unmeasured builds | The captures qualify the two native x64 process profiles |

## WoW64 UI-language commitment

Installed SysWOW64 CMD on Windows ARM64 build 29708 calls the zero-argument
`NtIsUILanguageComitted` service twice during startup. Both calls returned
success and CMD exited with code zero. The installed native ARM64 entry
returned the same NTSTATUS in three independent queries. The
[observation](commitment-29708-arm64.json) binds both provider identities.

For this WoW64 profile, RAX records the stable host NTSTATUS during NLS
acquisition. The guest reads that captured value without calling the host
again. The service takes no input and has no guest output buffer.

## WoW64 installed UI-language query

On the same Windows ARM64 build, installed SysWOW64 CMD calls
`NtQueryInstallUILanguage` through service `0x4015c`. Its x86 NTDLL leaf
uses `RET 4` and writes one little-endian `LANGID`. The observed result
`0x0409` matched two native ARM64 NTDLL queries and the independent
`GetSystemDefaultUILanguage` control on that host.

RAX captures two agreeing native results during NLS acquisition and serves
the captured word to the guest. The [native pointer cases](installed-language-29708-arm64.json)
record unaligned success, an unchanged word prefix on a cross-page failure,
and the different guard effects on writable and read-only pages. The guest
call leaves the caller's last error unchanged.

## MUI registry enumeration

After the installed UI-language query, SysWOW64 CMD on Windows ARM64 build
29708 requests `KeyBasicInformation` for ordinal zero under
`HKLM\SYSTEM\CurrentControlSet\Control\MUI\UILanguages`, with a 512-byte
buffer. RAX captures native child names and FILETIMEs during selection of
the fixed MUI SYSTEM subtree. Snapshot acquisition preserves ordinal order
separately from case-folded lookup and uses the same bounded registry value
and enumeration budgets. The native acquisition test compares both registry
views with independent `NtEnumerateKey` queries before and after the snapshot.
