# ProcessDebugPort native observations

The installed WoW64 NTDLL queries `ProcessDebugPort` (class 7) during startup of
the unchanged hardware-exception fixture. These controls measure the owned
current process without attaching a debugger, changing host settings, or
executing guest requests on the host. The runtime query now models the existing
no-debugger guest profile.

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
checks retain the observed NULL and upper-address fault ordering. All six
parser tests pass on native Windows, macOS and Linux. The existing
Windows profile workflow runs the observer on Windows 2022 and 2025 without
adding jobs. Both hosted controls pass: each contributes 601 x64 and 597 WoW64
queries. Every complete query row is identical to its local executable view.
The three kernels provide seven views and 4,195 queries. Hosted checkout uses
CRLF source bytes (SHA-256 `78211d7b062ef128c84d7555227510efa014fc75b3bcbe7f340036ed8325a0b1`);
the local source uses LF (`e96b84fef29f6f9c63e2fe2325fb02e9f2624cd11eb780370423e3309db22fb8`).
Those hashes are verified against the same committed source with the respective
line endings. Compiler and binary identities remain independently recorded.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| DP1 | Each matrix belongs to the owned executable view. | PE machine and pointer-width checks plus producer hashes. | Local observation attribution. | Alter executable/view or row identity; the driver rejects mismatch. | Confirmed for capture |
| DP2 | This capture describes a process with no debugger. | Both independent Win32 debugger queries report false. | Zero-value interpretation only. | Attach a debugger to a separate owned control and repeat. | Confirmed; debugger-attached behavior remains unqualified |
| DP3 | Captured native/WoW64 query ordering applies to the admitted no-debugger profile. | All complete rows agree across local 29683 and hosted 20348/26100. | Shared query adapter across guest ABIs. | Repeat the full guard/alias/handle matrix on another kernel. | Confirmed for seven captured views |

High impact, blocking full process qualification: complete exception entry and
debugger-attached state remain unfinished. Medium impact: the converted native
allocation failure boundary is unknown beyond the tested lengths. The runtime
uses the existing guest memory budget for temporary capture; it does not claim
to reproduce a host heap threshold. No C API, private ABI, packaging, guest
permission or installed-library selection policy changes are made.

Primary contracts:
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
and
[CheckRemoteDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent).
The detailed probe/copy order and private class-34/36 cases are measured
behavior, beyond the public SDK contract.

## Existing guest profile

The guest has no debugger object and its existing `IsDebuggerPresent` returns
false. Class 7 reports a zero pointer for that profile. It neither imports host
debugger state nor reports another process's state. A real handle requires the
measured `0x0400` grant; an unmodeled peer is explicitly unsupported after
length, type and grant validation.

Native64 uses the common four-byte output alignment, upper-user-span rejection
and early optional ReturnLength probe, then exact length, typed handle, output
probe, zero pointer store and final length store. The measured range check also
repairs native classes 34/36; their WoW64 direct paths keep their own order.
WoW64 class 7 bypasses the common probes, validates through private native
backing, copies just four converted output bytes on success, then publishes the
converted return length. Copy faults preserve earlier writes and guard visits.
It publishes `0xFFFFFFFC` on query failures, including NULL output, but does not
publish it after a non-null output-copy fault or capture-budget refusal.

For a non-null WoW64 capture, the guest bounds the minimum expanded extent:
`capture = u64(length) + 4` bytes and
`charge = ceil(capture / 4096) * 4096` bytes. It rejects a charge exceeding the
remaining no-paging-file commit budget or guest virtual span with
`STATUS_NO_MEMORY`, before either caller destination is touched. Widening before
addition avoids 32-bit wrap at length `0xFFFFFFFF`: capture is 4,294,967,299
bytes and charge 4,294,971,392 bytes. No proportional host allocation occurs.
Native allocator metadata/inline scratch and its exact failure threshold remain
unknown; this bound belongs to guest resource policy.

The dispatcher regression replays every one of the 1,799 local native rows,
checking status, fixed output/return projections, guard protection, PC, SP and
frame cleanup. Separate regressions check peer refusal and native upper-span
priority over an early return guard. A Windows-only leaf executes the selected
installed NTDLL query in native and WoW64 views with exact output and stack
cleanup checks. These builds also include the separate exception-entry draft;
query coverage does not qualify complete exception dispatch.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| DM1 | No guest debugger is represented in the existing personality. | Existing `IsDebuggerPresent` and absence of a debug-object model. | Class-7 zero pointer for this profile. | Introduce a successful debugger attachment; the query and Win32 state must change together. | Confirmed for current profile; attached state unqualified |
| DM2 | A minimum native-width capture can be bounded by the guest's existing no-paging-file budget. | Converted pointer width, measured huge-length refusal and existing guest memory accounting. | Bounded temporary capture without host allocation. | Query near a constrained guest budget; compare native allocator behavior separately before claiming its threshold. | Retained guest policy; native allocator threshold unknown |

The query performs expected O(log h + log r) lookup/probe work for h handles
and r mapping runs, plus O(o) worst-case object hashing for o objects. Added
storage is O(1); stores are fixed four/eight-byte values. No output size controls
a host allocation or loop.

Hosted evidence:
[Windows 2022 job 121316335957](https://github.com/HexRaysSA/rax/actions/runs/40242248049/job/121316335957)
and [Windows 2025 job 121316335843](https://github.com/HexRaysSA/rax/actions/runs/40242248049/job/121316335843).

The corrected baseline fails all three new portable regressions: class 7 is
unimplemented and the upper-output check visits ReturnLength's guard too early.
After the change, all 16 process-query tests pass on macOS and Linux, and all
19 pass on native Windows, including the installed native/WoW64 leaf. All 191
C API tests pass on every host. The complete current macOS library run passes
8,408 tests with two deliberate ignores and no failures. The complete Linux
library run passes 8,401 tests with two deliberate ignores and no failures; it
uses a native container filesystem for exact permission checks.

The unchanged hardware-exception fixture completes the native ARM64 iteration,
then advances beyond class 7 and fails in x86 initialization at unimplemented
class 37 (`ProcessImageInformation`). That failed verdict remains separate from
the passing query/C API gates. Full native exception startup remains unfinished.
