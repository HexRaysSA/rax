# Selected native-loader registry metadata

Baseline RAX 9bc58e434469d286ba51051f310b789d029e14c0 and
Assist c01ea005b1b55169d36a66e5b5779e82fb987c22; both clean. The current
owning-archive isolated loader stops opening Session Manager at slice 3237:
NtOpenKey, service 0x12, PC 0x180001130, key
\Registry\MACHINE\System\CurrentControlSet\Control\Session Manager. The
existing NLS-only snapshot refuses it explicitly.

Acceptance: native selection captures immutable, bounded read-only metadata
for two fixed SYSTEM keys (NLS CodePage and Session Manager); shared lookup,
raw value serialization, collation and lifetime are correct for all guest ABIs
on all hosts. Native HKEYs close before selection returns; guest names never
reach host registry calls. Codepage enumeration remains scoped to NLS. Unknown
keys/subkeys remain explicit unsupported frontiers. Discovery describes actual
captured scope. No new option, stable ABI, default or permission grant.

Owned RAX scope: registry.rs, registry/installed.rs, registry/tests.rs,
registry/installed_tests.rs, dll/native/registry.rs, registry leaf/shared tests,
native-runtime.md and this evidence directory. Root scope: pin, engineering
README/ledger, encrypted process-tool metadata and generated manifest.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Session Manager is an existing shared SYSTEM loader-config key on this native profile | Original ARM64/x86/x64 query captures and Microsoft shared-key rules | Second fixed selection entry and view handling | Missing values, WOW view flags, unavailable key | Retained native source plus independent installed selection/queries | confirmed for build 29683; retained elsewhere |
| S2 | Captured UTF-16 upcase/value data can be shared immutably across selected keys and guest handles | Existing immutable Arc<Key> ownership, no host callback/HKEY in records | Namespace lookup and lifetime | Namespace collisions, raw types/surrogates, drop registry with live handles | Shared constructor/bounds/lifetime tests and actual installed NT leaves | confirmed by shared tests on all hosts and installed native leaves |
| S3 | Bounded per-key stable double-enumeration suffices for this captured runtime profile | Existing before/after metadata and two byte-identical value enumerations | Acquisition retries/failure behavior | Key changes during capture, aggregate 16 MiB exhaustion | Capture source bounds plus repeated independent native queries; concurrent mutation fault injection remains unknown | retained; cross-key transactional atomicity is not claimed |

## Change-surface map and bounded scope

| Plane | Status and reason |
|---|---|
| Native Windows selection | Affected: fixed allowlist gains one system key; bounded capture, native-handle teardown |
| Guest NT registry/objects | Affected namespace consumer; existing typed rights, read-only values and serializers preserved |
| NLS | Affected consumer audit: numeric codepage discovery must use only its own key |
| Windows/macOS/Linux | Portable namespace compiles/runs all hosts/guest ABIs; Windows capture and selected NTDLL leaves run natively; other-host mismatch remains explicit |
| C API/Assist | Internal behavior through existing native_runtime option; owning archive rebuild/adapter/factory/ABI checks plus discovery regeneration |
| CPU/SMIR/JIT/backends/devices/other guest personalities | Unaffected: no instruction, IR, kernel adapter or guest ownership change |
| UI/persistence/routes/SDK/update/packages | No schema/layout/option/default/grant change; existing native selection capability gate and target wiring remain |
| Tests/docs | Native red/green regression, shared namespace/bounds/lifetime tests, actual installed metadata/leaves, source checksums and evidence ledger |

High impact: native production bootstrap/RTL heap/CRT and wider NT/registry,
POSIX process/symlink and native IDA/application/package matrices remain open
for the overall goal. Medium: snapshot is immutable, not a live registry or a
cross-key transaction; unknown subkeys retain explicit frontiers. Existing
BZHI/FP16 and historical timing suite failures require separate attribution.

## Capture, storage and lookup contract

The constructor admits at most two fixed keys, 4,096 values in aggregate,
16,383 UTF-16 units per name, 1,048,576 bytes per value and 16,777,216 bytes
(16 MiB) of raw names plus payloads across the completed namespace. It rejects
unknown paths, duplicate folded keys, duplicate folded names within a key,
invalid collation tables and aggregate exhaustion. Equal names in different
keys remain distinct. Numeric codepage discovery reads only the NLS key.
One 65,536-entry immutable upcase table occupies 131,072 bytes and survives
through any remaining guest key reference.

Native capture uses one query-only HKEY at a time. It retries at most three
metadata-before/two-enumerations/metadata-after sequences for each key. Success
requires identical metadata and byte-identical, name-sorted enumerations.
This detects the observed inconsistency patterns; it is not an atomic registry
transaction and cannot exclude a change that restores the same sampled bytes.
The two keys are acquired sequentially. No native HKEY or operation callback
is retained in Registry, Key or a guest handle.

The inherited enumeration loop truncated independently maximum-sized buffers
without releasing their capacities. The native regression observes a five-unit
name retaining 18 units. With 4,096 values and a 1 MiB maximum data buffer, the
old per-enumeration requested data storage could reach 4 GiB despite the raw
payload bound. The corrected loop reuses scratch and copies only returned
units/bytes after enforcing the byte budget. Native regression assertions check
retained capacities as well as independent raw value fidelity.

Scratch requested bytes are at most 2*(16,383+1)+1,048,576 = 1,081,344 bytes.
The maximum acquisition payload overlap is one completed key plus two current
key enumerations: 3*16,777,216 = 50,331,648 bytes (48 MiB), plus scratch and
O(N) metadata; aggregate validation can reject an oversized two-key capture.
After construction, raw payload is at most 16 MiB, folded name copies add at
most 16 MiB, and the shared table adds 128 KiB. Allocator bookkeeping/slack is
outside these requested-storage bounds. For total raw bytes B, value count N,
maximum name length L and U=65,536 collation entries, capture/construction use
O(U+B+N*L*log(N+1)) work plus host registry calls and O(U+B+N) storage. Lookup
uses O(L*log(N+1)) comparison work and O(L) temporary folded-name storage.

Native observations are Windows 10.0.29683.1000 ARM64 plus x86/x64 compatibility
processes. Three opens and 150 value queries yield 153 observations. The
independent checker verifies all status/length/header/payload/tail records.
The captured DWORD CriticalSectionTimeout is 2,592,000; other present DWORDs
in the oracle are zero. These are profile observations, not guest defaults.
Absent values return STATUS_OBJECT_NAME_NOT_FOUND. Unknown selected-namespace
keys/subkeys retain the explicit unsupported frontier.

## Final source validation and remaining frontier

| Gate | Result |
|---|---|
| Unfiltered macOS library | 7,528 passed, 0 failed, 2 ignored, 0 filtered; selection 7,530 |
| Unfiltered Linux library | 7,520 passed, 2 failed, 2 ignored, 0 filtered; selection 7,524 |
| Unfiltered native Windows library | 6,910 passed, 5 failed, 2 ignored, 0 filtered; selection 6,917 |
| Complete C API | 168 passed on each OS, no failed/ignored/filtered |
| All-target builds | Pass on Windows, macOS and Linux |
| Registered user_windows | 544 passed on macOS/Linux; Windows cfg(unix) selects 0, excluded from native coverage |
| Registered user_windows_memory | 4 passed on native Windows; macOS/Linux cfg(windows) select 0, excluded from memory runtime coverage |
| Current owning Assist archives | RAX recompiled on all three; five production adapter/factory/disabled/ABI/archive checks pass on each |
| Compiled discovery | Manifest regenerated by CLI; 7/7 macOS CTest checks include both manifest checks; final CLI/MCP rebuild and protected plaintext scans pass |
| Ordinary native Windows programs | Four controlled probes still return STATUS_ACCESS_VIOLATION |

The final Windows-only scratch/test correction does not change portable source
compiled on macOS/Linux. Its native full-library, C API, archive and all-target
runs recompile the corrected adapter; exact seven-file transfer hashes match
current source. S2 is confirmed for tested ownership/collation/serialization
cases. S1 remains release/profile bounded. S3 is retained with its explicit
sampling/transaction limitation and no claim of concurrent-mutation injection.

Linux retains a_timeout_is_removed_or_updated and finite_empty_and_expired_waits
failures. Windows retains four BZHI assertions and host-unavailable FP16. An
earlier Windows source run also fails the thread-clock strict inequality at
15,625,000*4 = 62,500,000 ns versus worker 62,500,000 ns; its later absence is
not remediation. No lowerer, clock, timing assertion or skip was modified.
Those causes remain unresolved. The initial old NLS-diagnostic assertion was
updated to the intentional runtime-namespace diagnostic; initial Windows
Parallels result retrieval and missing private MCP directory were excluded.
Final exact source and result/log SHA-256 values are in validation-summary.json.

Two portable constructor tests cover scope, collisions, aggregate bounds,
NLS-only codepage selection and shared table/key lifetimes. One shared NT case
runs all three guest ABIs on every host, opens both keys under each view flag,
drops the selection namespace, queries raw values and closes/rejects stale
handles. The native acquisition case independently compares actual raw values
and checks retained capacity, and the installed NTDLL case runs ARM64/x86
open/query/close leaves with stack cleanup and handle counts. Native selection's
missing-Session-Manager regression and native retained-capacity regression have
observed failures before their corresponding corrections and pass afterwards.

The final owning-archive diagnostic opens Session Manager at turn 3,237,
service 0x12, PC 0x180001130, access 1. It queries
RaiseExceptionOnPossibleDeadlock at turn 3,248, returning
STATUS_OBJECT_NAME_NOT_FOUND, then closes the key. It stops at turn 3,405,
service 0x12, the same PC, access 9, opening
\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
outside the selected namespace. The 168-turn advance counts scheduler calls,
not retired instructions. The source/log are retained; cleared PEB.ProcessHeap
and saved-context LdrInitializeThunk remain private diagnostic conditions.
Production loader/RTL heap/CRT bootstrap is incomplete.

Stable C API 1.11.0 and layouts, options/schema/defaults/dependencies/locks,
permissions, package wiring and ISA/SMIR/JIT/other guest personalities are
unchanged. Assist's protected description and generated discovery disclose the
two fixed registry keys. Complete native IDA/package/application matrices,
wider NT/registry and POSIX/process semantics remain high-impact work blocking
the overall goal. Medium limits are sampled acquisition, other-build fidelity,
and unresolved suite failures. Low impact: shared captures between independent
processes could reduce repeated selection work; not implemented.

Increment self-review covers the assumption register, all fixed-key consumers,
bounds/arithmetic/UTF-16/raw bytes, provenance hashes, runtime availability,
three-host source membership, compiled discovery, explicit failed/excluded gates
and exact worktree ownership. This does not declare the full-process goal complete.
