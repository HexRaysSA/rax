# Captured native key information

The fixed `Nls\CustomLocale` subtree now retains the installed host's complete
key records for `NtQueryKey` classes 0 through 6 and 8. Class 7 continues to use
mutable key-body tags. Selection captures values, complete descendants, native
child enumeration order and timestamps, canonical names, and short-name copy
behavior. Every native HKEY closes before descendant capture; guest calls read
owned immutable data.

Logical `CurrentControlSet` opens and captured canonical `ControlSet` opens
resolve to the same key. MACHINE-relative opens retain both routes. Duplicated
handles retain their records and descendants after the registry namespace drops.
Missing fixed roots remain distinguishable from capture errors and unselected
paths.

The native adapter first obtains a bounded required length, then reads each
record under two different buffer fills. It rejects undefined record bytes,
unstable samples, contradictory counts/names/timestamps, incomplete descendants,
and aliases outside the fixed subject. For classes 0 and 1, two private
odd-length queries per class and record sample distinguish raw name prefixes from zeroed odd name tails;
visible ASCII text alone does not select that behavior.

Each native record is limited to 131,072 bytes. Record payloads share the
16,777,216-byte startup snapshot budget with values. The selected subtree has
at most 1,024 keys, relative depth 32, and 1,048,576 bytes of logical and canonical
paths. Ordered children use the existing startup enumeration budget. For K keys, V values and B captured bytes, acquisition and binding use
O(B log(K + V + 1)) time with constant bounded retry counts; retained storage
is O(B + K + V). These bounds also
apply when a host record changes while capture is in progress.

Native evidence was collected on Windows 10.0.29698 with an ARM64 kernel.
The x64 PE used the mapped ARM64 NTDLL provider; it is an x64 binary execution
control rather than a physical AMD64 kernel observation.

| PE architecture | Measured guarded calls | Handle count before/after |
|---|---:|---:|
| ARM64 | 66,110 | 52 / 52 |
| x64 | 66,110 | 74 / 74 |
| x86 | 66,110 | 89 / 89 |

Each executable first warmed the same matrix without counting those calls as
measured evidence. The matrices cover 11 selectors, 33 lengths, 14 output
layouts, 13 ResultLength layouts, guard/read-only/inaccessible pages, aliases,
and four opposite-fill controls per selector. Own-process handle entries also
match before and after each measured run. The source reserves 196,608 bytes and
commits the middle 65,536 bytes, keeping every declared variable span inside its
private reservation. Fixed invalid pointer values are deliberate fault cases.

Separate owned volatile HKCU fixtures supply 123,816 native calls with Unicode
and Latin1 names, nonempty class strings, short records and ResultLength aliases.
The immutable-record replay checks 122,136 of those calls; 1,680 class-7 calls
belong to the separate mutable key-body implementation. The guarded guest replay
checks all 198,330 calls. Native undefined WoW64 conversion tails are retained in
the corpus and excluded from byte assertions; statuses, last-error values and
page effects remain checked for every call.

A separate tag-mutation control in `tags-v4/` performs 24 own-handle tag
changes and 243 queries across the three ABIs. Only class 7 changes; every
other full record remains byte-identical. Its archive SHA-256 is
`aa0009702a422d83a75b42eef75d9436d0c727283532bc4654d5887c779540fb`.
The guest regression follows the same sequence through a duplicate handle and
checks that an independently opened body retains its original tags.

`frozen-inputs-v1.json` identifies the exact sources, PE images, native receipt,
and compressed raw observations. The guard archive SHA-256 is
`9f43ae1666ac8acf9350f14fd4cbf09589a383aa74838944dfc8dec6443e54b0`;
the volatile-fixture archive SHA-256 is
`5f01da0971a38b40b1f996c9cb68a7ee8bdd6d8a0b578aa09459938ae99da582`.
The task evidence preserves an earlier failed guard-probe epoch and the distinct
180-second idle handle control. The failed epoch is excluded from qualification.

From the repository root, verify the frozen input files and replay the library
checks with:

```text
python3 docs/specifications/windows/native-query-key/metadata/verify-v1.py
cargo test --locked --no-default-features --lib key_information -- --test-threads=1
```

The verifier also accepts `--guards-native-archive PATH` and
`--fixture-native-archive PATH`, and `--tags-native-archive PATH` to verify every payload of the original archives.
Rust tests decompress the frozen JSONL directly with the existing zstd dependency.
The Windows-only acquisition tests compare captured records against independently
opened native keys in all three SYSTEM views.

To rebuild the guard producer on native Windows with Visual Studio and CMake,
use in-repository build directories and select `ARM64`, `x64`, or `Win32`:

```text
cmake -S docs/specifications/windows/native-query-key/metadata -B target/native-key-metadata-arm64 -A ARM64
cmake --build target/native-key-metadata-arm64 --config Release -- /m:1 /nr:false
```

CMake writes the executable's exact path to `probe-paths-Release.txt` in the build
directory. Running that executable emits JSONL; `--identity` emits the actual
mapped provider identity, and `--handles-idle` captures seven own-process handle
snapshots 30 seconds apart without querying a key. The fixture producer's source
and CMake project are under `fixture/`; it creates only uniquely named volatile
HKCU test subjects and removes them before successful completion. `capture-v3.py`
is the retained original machine-specific capture controller; its paths and
compiler environment belong to the recorded native evidence epoch.

Assumptions KM1 and KM2 remain finite native evidence bounds: the two calibrated
copy plans and the caller-probe order are established by the retained matrices
for the recorded kernel. Acquisition rejects an unrecognized short-copy result.
Other kernels and specially constructed hive storage require native observation.

High-impact remaining work includes metadata for other selected registry roots,
ordinary-token protected-child acquisition, and later Windows startup services.
The full host-library process-emulation objective remains incomplete.

Primary layout declarations are retained in [phnt-ntregapi.h](../../native-nls-registry/phnt-ntregapi.h); native capture determines the observed copy and fault behavior.
