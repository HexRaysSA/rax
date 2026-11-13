# Windows 10.0.29704 ARM64 mapped-filename profile

This profile qualifies `NtQueryVirtualMemory` information class 2 for native
kernel `(10, 0, 29704)` and native machine `0xaa64`. Guest ARM64, x64 and x86
callers use the ARM64 kernel-copy model with byte-counted short MUP names. Local
NTFS names retain whole-UTF-16-unit truncation. It admits no other kernel or
native-machine identity. Guest-visible version spoofing cannot qualify a host.
The public ABI, selected file family and host access policy are unchanged.
The shared registry-copy callers are qualified separately below.

## Independent native acquisition

The retained projection contains 1,359 native query observations: 453 per ABI.
Eight immutable producers cover image/data/pagefile mappings, rights, short and
zero buffers, aliases, rename/close/delete, 1-128-byte writable prefixes, guards,
read-only/no-access boundaries, partial copies and optional-return-slot faults.
The replay version for source version 7 is 1; other versions retain their number.

| Source version | Native case IDs, inclusive | Cases per ABI |
| --- | --- | ---: |
| 7 | 0-47 | 48 |
| 2 | 48-65 | 18 |
| 3 | 66-76 | 11 |
| 4 | 77-95 | 19 |
| 5 | 96-123 | 28 |
| 6 | 124-132 | 9 |
| 8 | 133-196 | 64 |
| 9 | 133-388 | 256 |

Calculation: `(48 + 18 + 11 + 19 + 28 + 9 + 64 + 256) * 3 = 1,359` queries.
Twenty-four separate baseline executions capture complete UTF-16LE names:
21 executable names and three selected KERNEL32 names for version 9. They are
not reconstructed from a DOS path or from emulator output. All 1,383 executions
have distinct `(PID, creation_filetime)` identities, observed child exit 0 and
no raised exception. Empty stderr is checked against its captured SHA-256.

The exact 24 previously compiled images were reused for the final physical-file
identity acquisition. `compile-29704-v1.json` retains their native compiler
commands, child identities, exits, stdout and stderr. The projection binds each
image, source, compiler and provider identity; the archive retains executable
bytes. No probe source changed after execution. The projection's historical
`status` string records acquisition before replay; it is not a current test result.

| Retained artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `profile-29704-v1.json` | 2595362 | `064a26c925497bc045c51458863cb7ae2d4442b6ba540fa2ba15cbf6e05ddb35` |
| `compile-29704-v1.json` | 462760 | `3e4f6269658048d7f039654b992c399a8fe30d60e9f93486666f542e87a1b45e` |
| `native-artifacts-v3.zip` | 8604234 | `af6bc9e687b02811167ee61a4cd87ea7bcda267a56d447ee68f2faf3c2b41d38` |

The archive is retained in acquisition evidence rather than redistributed in
source. Its manifest covers 4,226 payloads, including raw native output, child
receipts, probe images, frozen sources and physical providers.

## Physical provider and copy-body identity

| Compiled caller ABI | Physical NTDLL family | Physical PE machine | Bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| ARM64 | System32 | `0xaa64` | 4612400 | `62f49d5ba98285e9997cc47c7710ab1d1390506c0a3fda96736783aefd42b3b1` |
| x64 compatibility | System32 | `0xaa64` | 4612400 | `62f49d5ba98285e9997cc47c7710ab1d1390506c0a3fda96736783aefd42b3b1` |
| x86 compatibility | SyChpe32 | `0x014c` | 2534824 | `0c8ad1faabdc67afad52c037897a1edbe8c69733aede303c0fa9d1dd6ccde0f7` |

The physical path is obtained from the actual loaded mapping and reopened through
`GLOBALROOT`; a projected module's machine does not identify its physical file.
In particular, the x64 compatibility caller loads an x64 projection of the ARM64
System32 file. The native x86 control uses SyChpe32. These facts do not change
the emulator's explicit pure-x86 library selection.

The ARM64 memcpy observer follows the export's branch to the implementation,
then captures 2,048 body bytes. Their SHA-256 is
`5a1f552ac1ebecd7137d4c593d9966f4743960fe6298f930115d4e9428aa2ff1`.
This differs from the 29698 body hash. Admission therefore depends on a fresh
complete behavioral replay, not on a matching thunk or a nearby build number.

## Paired filesystem controls

The initial replay matched 1,327 rows and exposed 32 odd-byte short-buffer
differences in native64 network-backed executable names. Applying one byte-copy
rule to every 29704 mapping would incorrectly change local-file behavior.
Paired controls execute the same frozen v7/v5 images from local storage and the
network share on the same kernel. The native control checkout's unrelated
emulator HEAD is recorded; only probe source blobs and executable bytes bind
these syscall observations. Git checkout CRLF conversion is not an executed
producer-source change: canonical source blobs and original compiled images are
checked byte for byte.

`paired-29704-v1.json` retains 414 executions: 402 queries and 12 independent
names across two locations, three ABIs and two source versions. Version 7 queries
the required size minus one byte; version 5 sweeps every caller length from
16 through 81 bytes, inclusive. Each location/ABI has one v7 query, 66 v5 queries
and two separate baselines: `(1 + 66 + 2) * 2 * 3 = 414` executions.
The raw archive retains all 1,259 payloads, including the executed acquisition
source, original compiler receipts, images, raw streams and child identities.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `paired-29704-v1.json` | 621358 | `41bd761c479d79ae1012a1d1af6b773b50a6f3f6a1c0081b6df1fc60686525e3` |
| `paired-native-artifacts-v1.zip` | 1334435 | `e44c13d7d5f1c0f0f9168ee71f880a32b30e2cdf5608c17d3210e7cf8f68d3ef` |

`paired-volume-29704-v1.json` retains the independent `GetVolumeInformationW`
measurement confirming local C: uses NTFS. Its observer records native PID 9204,
creation FILETIME 134390396779992941 and exit 0. All three physical NTDLL hashes
still match the original acquisition. The network mapping names use the actual
`\Device\Mup\` identity; no DOS/UNC path is synthesized by the emulator.

For native64 short MUP buffers, `copied_bytes = caller_bytes - 16 - 2`;
`Length = copied_bytes`, `MaximumLength = copied_bytes + 2`, and two zero bytes
follow the copied bytes, including when the count is odd. The device-prefix
result is `STATUS_OBJECT_PATH_INVALID` only at the exact byte boundary. One
additional byte returns `STATUS_BUFFER_OVERFLOW`. WoW64's corresponding short
request preserves this byte-sensitive status distinction without publishing a
converted record. Local NTFS keeps the previously captured even-length rule.
Existing 29695/29698 and native AMD64 profiles are unchanged.

## Shared registry-copy callers

The same finite profile selector gates `copy_thunk_bytes`, consumed by
`NtQueryKey` and the class-zero copy path of `NtEnumerateKey`. Admission therefore
also requires independent registry-copy qualification. The runtime does not add
a host registry forwarder or change registry access policy.

Four original `probe-v5.cpp` images capture 3,312 later-page query cases each
for ARM64, x64, x86 and x86 LAA: `4 * 3,312 = 13,248` observations. Six enumeration
images capture basic and fault campaigns for ARM64, x64 and x86:
`3 * (4,872 + 5,676) = 31,644` observations. All qualified native children have
observed exit 0, stable `(PID, creation_filetime)` identity, matching executable
hashes before/after, and no caller-visible exception. Enumeration retains its
original equality assertion for process handle counts before/after the campaign.

The enumeration wrapper includes each immutable original C producer. It performs
two read-only HKLM opens/closes and requires 20 consecutive unchanged handle-count
samples at 50 ms intervals before calling the original main function. Failure to
stabilize within 100 samples fails the precondition. This isolates late process
initialization from campaign cleanup; the exact ownership of the late-created
handles remains unknown. Failed cold captures remain evidence with their actual
nonzero exits and are not counted as qualified executions. Cold/warm comparisons
preserve every status, monitor byte and protection. The x86 basic wrapper changes
the measured `ResultLength` alignment from 4 to 0 modulo 8; both remain aligned
modulo 4. Each fixture records its actual alignment rather than normalizing API
output bytes.

| Retained artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `registry-query-29704-v1.json` | 2747770 | `31d47745e1762510628dbfbb9d28e386a2692947d032b6ba9137db3c0856254c` |
| `registry-enumeration-29704-v1.json` | 833031 | `87ed6cca739cd813569b3a8934c2f70e798f8f127e4a961738821a129988298c` |
| `registry-copy-native-artifacts-v1.zip` | 2358931 | `5576e1cecb01169b13b2372b2362fc0c1e31c65111bee667e27bff891c68d79f` |

`registry-copy-29704-v1.json` binds producer sources, compile/native receipts,
executable identities, raw archive and defined-field projections. The archive
retains 142 payloads and is kept in acquisition evidence. The wrapper source is
`registry-enumeration-precondition-v2.c`; its bytes, including CRLF line endings,
match the archived native compiler input.

Query fixtures retain only the four-byte defined tag and the fields consumed by
the existing later-page replay. Undefined scratch bytes beyond that record are
excluded. Enumeration fixtures exclude information classes 1 and 2, which the
existing replay already excludes: `3 * 12 = 36` captured rows. Thus 31,608
enumeration cases are replayed, and the fresh modeled count is
`13,248 + 31,608 = 44,856` per host configuration. The native captured count is
44,892. These counts are not interchangeable.

`check-registry-29704.py` uses Python 3.9 or newer and the standard library. With
the optional archive it verifies all payload hashes, native identities/exits,
producer sources, PE machines, x86 LAA flags, image hashes and exact projection.
It reconstructs every monitor byte from its compact prefix and fill value.
Its time and space complexity are O(B + R), where B is the total fixture and
expanded artifact byte count and R is the decoded row count.
It executes no native probe or emulator code.

```text
python docs/specifications/windows/native-mapped-filename/check-registry-29704.py
python docs/specifications/windows/native-mapped-filename/check-registry-29704.py <registry-copy-native-artifacts-v1.zip>
```

To exercise the existing Rust hooks, set `RAX_NATIVE_QUERY_KEY_CORPUS` to the query
fixture and `RAX_KEY_ENUMERATION_CORPUS` to the enumeration fixture, using absolute
native paths. Pass both names below to the owning library test binary, followed by
`--test-threads=1 --nocapture`:

```text
native_query_key_replays_later_page_copies_across_captured_kernels
native_enumerate_key_replays_explicitly_requested_fresh_controls
```

The query hook also replays 19,872 retained cases. Enumeration must report three
process ABIs, 14,580 class-zero/invalid-selector rows and 17,028 fault/rights rows;
a test that reports zero fresh rows does not qualify this profile.

## Verification

`check-29704.py` requires Python 3.9 or newer and only the standard library:

```text
python docs/specifications/windows/native-mapped-filename/check-29704.py
python docs/specifications/windows/native-mapped-filename/check-29704.py <native-artifacts-v3.zip>
python docs/specifications/windows/native-mapped-filename/check-29704.py <native-artifacts-v3.zip> <paired-native-artifacts-v1.zip>
cargo test --locked --no-default-features --features x86_64-suite,smir-jit --lib mapped_filename -- --test-threads=1
```

The first command verifies immutable data, all ten captured source inputs,
compiler receipts, complete case coverage and independent baseline names. The
optional archive check also verifies every manifest payload, raw output/child
identity, image PE machine, physical provider and memcpy body. It executes no
native or emulator code. Complexity is O(B) time for B input bytes and
O(P + M + N) space for projection P, largest payload M and manifest N.

The shared Rust replay executes all 1,359 original and 402 paired query rows on
Windows, macOS and Linux.
It checks NT status, full output bytes, exact `ReturnLength`, LastError and page
protections. ASLR pointer fields are compared separately against the expected
guest buffer or retired temporary allocation; no other bytes are normalized.
The existing 29698 and older physical-AMD64/ARM64 replay corpora remain intact.
The new rejection regression covers eight unsupported native identities for
each of the three guest ABIs and verifies unchanged output, handle count and
committed-byte count, even when the guest advertises build 29704.

The Windows-only installed-leaf test executes the selected NTDLL entry and its
actual return for each available caller ABI, comparing the name with an
independent query of the selected file. Compilation alone does not run this
test. Native child identity and exit must be observed for Windows execution.

## Assumption register and bounded scope

| ID | Assumption / dependent result | Basis | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| MF104-1 | The existing ARM64 copy model applies unchanged to 29704 / finite profile admission | Fresh 1,359 queries and independent names | Full replay exposed 32 MUP odd-byte differences | falsified; MUP short-copy behavior is modeled separately |
| MF104-2 | Native kernel and native machine qualify the profile / admission predicate | Native provider and kernel identity, independent of guest configuration | Neighbor builds, wrong major/minor, absent/x86/x64 native machine plus guest spoofing must reject without publication | confirmed by rejection regression |
| MF104-3 | Compiled process ABI identifies physical provider machine | Initial process-identity hypothesis | Compare loaded mapping name, projected machine and independently read physical PE | falsified; physical files are bound explicitly above |
| MF104-4 | The observed short-copy difference depends on MUP backing, rather than every 29704 mapping / copy policy | 414 paired executions, frozen identical images and independent NTFS measurement | Full 402-query replay, including adjacent odd/even device-prefix boundaries and WoW64 | confirmed within the captured subjects |
| MF104-5 | The existing ARM64 store sequence applies to the shared registry-copy callers on 29704 | Fresh query/enumeration controls and six-platform replay | Every consumed status, defined byte, ReturnLength, LastError and guard must match | confirmed for the retained corpus |
| MF104-6 | Initialization preconditioning preserves measured API semantics | All six native campaigns retain their strict cleanup assertion and match cold status/byte/protection observations | Preserve actual pointer alignment; any output difference falsifies equivalence | confirmed within the captured subjects |
| MF104-7 | The compact projection preserves all fields consumed by existing replay hooks | Independent archive checker and direct projected-fixture replays | Reconstruct all monitor bytes; verify every projected query field | confirmed for the retained corpus |

High impact, outside this profile: full installed-process startup still requires
other captured services and profiles; this copy-profile admission is not full native
runtime or package qualification. Missing hardware/CI capacity does not qualify
an unexecuted platform. Unknown: behavior of other kernel builds and extreme
conversion-allocation failures, and unmeasured backing providers. The kernel
admission and conversion-allocation diagnostics remain explicit. The MUP evidence
uses the Parallels network share; it does not establish every network provider's
behavior. No additional host forwarder or filesystem mutation is introduced.
