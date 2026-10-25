# ProcessDebugPort native observations

The installed WoW64 NTDLL queries `ProcessDebugPort` (class 7) during startup of
the unchanged hardware-exception fixture. These controls measure the owned
current process without attaching a debugger, changing host settings, or
executing guest requests on the host. No runtime implementation is supplied by
this observation changeset.

`native-debug-port-v3.cpp` records 601 ARM64 queries, 601 x64 queries and 597
WoW64 queries on the local Windows 10.0.29683 ARM64 kernel: 1,799 in total.
Each query owns 16 KiB of scratch storage. The matrix covers lengths, unaligned,
null, read-only, inaccessible and guard destinations, overlapping output and
return-length stores, pseudo-handles, owned event and process handles, and
seven access masks. Upper-address controls query classes 7, 34 and 36 with
aligned all-ones destinations, two handle choices, six lengths and four
return-length roles. Class 36 output is always invalid in these additional
controls; no process cookie is disclosed. Output contains scalar identities,
NTSTATUS, protection flags and fixed 16-byte scratch projections. It contains
no native addresses or library contents.

The driver verifies executable machine, source/compiler/binary SHA-256,
complete ordered input identity, exact scalar fields, native/Win32 debugger
agreement, unchanged executable bytes and cleanup. `local-29683-v3.json`
retains all three observations. Earlier executed source versions and receipts
are preserved in the task's private evidence archive; v3 extends their matrix.
Capture time and retained data are O(n), n queries; live scratch space is O(1).

| Observation | Native ARM64 and x64 views | WoW64 view |
|---|---|---|
| Successful output | Eight zero bytes, return length 8 | Four zero bytes, return length 4 |
| Output alignment | Four bytes when length is nonzero | Unaligned output accepted |
| Exact accepted length | 8 bytes | 4 bytes |
| Real process handle right | `PROCESS_QUERY_INFORMATION` (`0x0400`) | Same; `0x1000` alone denied |
| Return-length ordering | Probed before length and handle validation | Copied after converted query/output |
| Query failure return length | Unchanged | `0xFFFFFFFC`, except allocation or copy faults |
| Read-only output guard | Access violation; guard retained | Same |
| Read-only return-length guard | Guard visited during early probe | Access violation; guard retained |

All captured headers report no debugger through both Win32 queries. Successful
class-7 values agree. Native output range checks precede return-length probes
for nonzero length; length zero does not check the output range. The same
ordering is observed for native classes 34 and 36. Their WoW64 direct queries
instead probe return length first. WoW64 class 7 has a distinct conversion:
NULL output at valid length returns access violation and publishes
`0xFFFFFFFC`; wrong length returns information-length mismatch and publishes
that same converted failure length. A bad non-null output can fault before
return-length publication. Length `0xFFFFFFFF` in the converted class-7 path
returns `STATUS_NO_MEMORY` without destination writes. This observation does
not establish the conversion allocator's general failure threshold.

The parser tests reject incomplete/reordered matrices, changed input identity,
extra fields, malformed scalar/hex projections, incompatible machine/view,
missing cleanup and disagreement with the independent Win32 query. Separate
checks retain the observed NULL and upper-address fault ordering. All six parser tests pass on native Windows, macOS and Linux. The existing
Windows profile workflow runs the observer on Windows 2022 and 2025 without
adding jobs; hosted results are not yet available for this changeset.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| DP1 | Each matrix belongs to the owned executable view. | PE machine and pointer-width checks plus producer hashes. | Local observation attribution. | Alter executable/view or row identity; the driver rejects mismatch. | Confirmed for capture |
| DP2 | This capture describes a process with no debugger. | Both independent Win32 debugger queries report false. | Zero-value interpretation only. | Attach a debugger to a separate owned control and repeat. | Confirmed; debugger-attached behavior remains unqualified |
| DP3 | Cross-kernel fault ordering is not established by one kernel. | Only build 29683 is captured here. | Runtime profile bounds. | Compare complete hosted 20348/26100 matrices. | Retained pending hosted controls |

High impact, blocking full process qualification: the runtime class-7 query,
complete exception entry and debugger-attached state remain unfinished. Medium
impact: the converted allocation failure boundary is unknown beyond the tested
lengths. Neither limitation changes the validity of the retained observations.
The controls affect tests and documentation only; no C API, private ABI,
packaging, guest permission or installed-library selection policy changes.

Primary contracts:
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
and
[CheckRemoteDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent).
The detailed probe/copy order and private class-34/36 cases are measured
behavior, beyond the public SDK contract.
