# Selected native MUI query data

The query implementation uses a bounded copy of the installed runtime's
`NtGetMUIRegistryInfo` data. Acquisition invokes only flags `0`, with native
outputs allocated by the adapter. Guest flags, pointers and lengths never reach
that host call. Two captures at different live output addresses must agree;
the adapter allows three attempts and at most 1 MiB of MUI data within the
existing 64 MiB combined NLS budget.

The measured profile is Windows 10.0.29683.1000 on an ARM64 kernel. ARM64,
x64 and x86 executable controls each contain 1,680 rows, for 5,040 native rows.
Those are three process views of one kernel. An independent x64 kernel profile
remains unknown. Build 29695 is independently qualified in
[the later kernel record](../native-nls-build-29695/README.md), including x86
large-address-awareness controls and fresh generation observations. Other
Windows builds remain unmeasured.

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
| Fault while zeroing capacity | Preserve the zeroed accessible prefix; do not copy the payload |

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
| Medium | Independent x64 kernel and other Windows builds | Limits the measured profile's portability claim |
