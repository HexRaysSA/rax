# Captured primary-user hive

The installed Windows profile captures the creator's primary SID hive through
one fixed, query-only `RegOpenKeyExW` open under `HKEY_USERS`. It retains the
canonical name from host `NtQueryKey(KeyNameInformation)`, child count and all
bounded root values. The native HKEY closes before guest execution. Guest
names, handles and access masks never reach a host registry call.

The requested SID name and captured canonical name reference one immutable
guest key. On native ARM64 Windows build 29695, `S-1-5-18` resolves to
`\REGISTRY\USER\.DEFAULT`. The model retains the already selected per-user
policy route through that key. Handles keep those records alive after catalog
replacement and parent-handle closure. Uncaptured descendants of a present,
nonempty hive remain explicit frontiers. A captured absent hive establishes
absence for the root and its descendants, without admitting a different alias.

## Native evidence and scope

`probe-v1.py`, `probe-v2.py`, `probe-v3.py` and `probe-v4.py` are immutable executed
producers. Their corresponding `arm64-29695-vN.json` files retain every recorded
field. Native machine `0xAA64` and process machine zero establish a native ARM64
observer. v4 also records `RtlGetVersion` and independent Win32 absence results.
The directory-local Git attributes disable checkout newline conversion for the
frozen producers, preserving their measured bytes on Windows as well.

| Version | Observations | Result |
| --- | ---: | --- |
| v1 | 24 | Opens and key metadata complete; the object-basic query used 65,537 bytes and returned `STATUS_INFO_LENGTH_MISMATCH`. |
| v2 | 24 | Opens and key metadata complete; the attempted 56-byte object-basic buffer allocated 57 bytes because of a ctypes terminator. |
| v3 | 24 | Exact 56-byte object-basic buffers establish native grants. |
| v4 | 56 | Correct buffers, portable native-64 observer, exact kernel version, plus four absent paths and independent Win32 controls. |

The v4 absent SID `S-1-0-4275878552`, its trailing separator, child and nested
child return Win32 `ERROR_FILE_NOT_FOUND` (2) and native
`STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`). Other capture errors propagate.
No test substitutes absence for access denial or an incomplete snapshot.

The replay checks 12 read-mode observations from v3 and 44 from v4 across
ARM64, x64 and x86 guest ABIs. It compares open status, zeroed failed outputs,
valid successful handles and granted read rights. Opaque native handle numbers
are retained but are not guest handle identities. Actual root values are
checked against live Win32 acquisition separately. An optional fresh corpus
is supplied through `RAX_NATIVE_PRIMARY_USER_HIVE_CORPUS`.

Two limitations remain explicit:

- Native `MAXIMUM_ALLOWED` grants `0x000F003F` on this measured hive. The existing
  selected-registry read model caps grants at `0x00020019`. Those four successful
  primary-hive MAXIMUM_ALLOWED rows are retained but excluded from read-grant
  replay. This change does not establish full registry access-mask parity.
- Guest `NtQueryKey` is not implemented. Native Basic/Full/Name information is
  retained as acquisition evidence, not advertised as guest service support.
  In particular, native Basic information names the hive `ROOT`, while Name
  information reports its canonical object path; deriving one from the other
  would be incorrect.

The `\REGISTRY\USER` parent is observational control data and is not selected
as another guest registry root.

## Bounds and ownership

Root values share the existing limits: 4,096 values, 16 MiB aggregate value/name
bytes, 1 MiB per value and 16,383 UTF-16 units per value name. Shared key records
are charged once, including aliases and policy references. The capture budget
walk costs O(K log K + V) time and O(K) temporary space for K distinct key
records and V values. Relative-route lookup costs O(N) time and space for N
UTF-16 input units. No guest key retains a native handle or host callback.

The canonical-name buffer has a four-byte header and capacity for 16,383
two-byte UTF-16 units: 4 + 2 × 16,383 = 32,770 bytes, rounded to 8,193 ULONGs
(32,772 bytes). Returned lengths, even name length, the native HKU prefix,
one hive component and embedded NULs are checked before selection.

## Validation ledger

The final implementation passes 8/8/10 targeted tests on macOS/Linux/native
Windows ARM64, 103/103/151 registry regressions, 8/8/10 CLI tests and 191 C API
tests per host. All-target compilation passes on all three; strict production
Clippy passes on macOS. Linux execution uses a translated x86-64 container.
Native Windows replays the additional 44 fresh read/absence observations as
well as the 56 retained observations. Four provenance tests and five existing
CI-runner tests pass. Independent native AMD64 source qualification on
Windows2022 and Windows2025 remains pending before master publication.

The unchanged ARM64 system CMD has SHA-256
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`.
With the final local implementation, native CMD exits zero and prints its marker;
emulation passes the hive open, exits 125 before stdout and reports unsupported
`NtQueryKey` (`0x16`). The qualified local CLI for that run has SHA-256
`b2d990dfcb5eccbb139a46bd394e20db5516ebaf1bbfa27353db485ad46f5b42`.
This is progress toward process compatibility, not full CMD support.

## Assumption register

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| UR1 | The stopped program requests the captured primary subject; stopped-state inspection and native TokenUser both identify `S-1-5-18`. | Select only the creator hive. | Other SIDs must remain unselected unless they are its captured native alias; inspect subsequent stopped calls. | Confirmed on build 29695. |
| UR2 | Captured aliases share key identity; native SID and `.DEFAULT` opens return the same canonical path. | Alias lookup and handle ownership. | Case folding, catalog replacement, parent closure and selected policy routing must retain identity and values. | Shared-model, retained/fresh replay and native ARM64 acquisition tests pass; independent AMD64 qualification pending. |
| UR3 | An absent selected hive makes its descendants absent; v4 measures all four paths through native and Win32 APIs. | Known-absence lookup. | A non-NAME_NOT_FOUND native row or non-file-not-found Win32 row disproves the mapping. | Confirmed on build 29695; fresh AMD64 observations pending. |

The existing AMD64 qualification jobs retain the entire original hardware-fault
fixture. The existing three-host C API lanes also run the shared registry tests.
No new CI job is introduced. These gates do not establish installed Assist,
GUI, real-IDB or package behavior, or complete Linux/macOS/Windows process support.

To reproduce v1-v3, copy the unmodified producer into a fresh task-owned target
directory inside the checkout before running it. v4 provides an in-tree output
argument and refuses to overwrite an existing directory:

```text
python -B docs/specifications/windows/native-primary-user-hive/probe-v4.py --require-native-machine 0x8664 --output target/native-primary-user-hive-v4
python -B -m unittest discover -s docs/specifications/windows/native-primary-user-hive
cargo test --locked --no-default-features --lib primary_hive -- --nocapture
```
