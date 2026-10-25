# ProcessExecuteFlags native observations

The installed WoW64 NTDLL reaches `NtQueryInformationProcess` class 34 while
initializing the hardware-exception fixture. The read-only query now describes
the model's existing fixed-NX profile. These controls measure the native
contract; they do not change host DEP policy or execute a guest request on the
host. Mutable DEP and default no-NX policy remain separate unfinished work.

`native-execute-flags-v1.cpp` performs 239 queries per executable: seven lengths,
100 destination pairs, 120 handle/length/destination combinations, seven access
masks and five overlapping destinations. Each query owns 16 KiB of scratch
storage. Destinations cover null, address 1, unaligned, read-only, inaccessible,
writable and read-only guard pages, and page boundaries. Handle cases include
the current process, invalid values, current thread, an owned event, and real
current-process handles. Output contains fixed 16-byte projections, scalar
statuses, guard protection and input identities; no native addresses or DLL
contents are published. Capture time is O(n) and retained data O(n), where
n = 239 per executable; per-query scratch space is O(1).

The driver requests ARM64, x64 and x86 images with and without `NX_COMPAT`.
On the local Windows 10.0.29683 ARM64 kernel, five profiles completed all
1,195 queries. The ARM64 no-NX image was rejected by `CreateProcess` with
Windows error 193 before entry. The original `run.py` failure is preserved;
`run-v2.py` records this specific loader rejection separately and continues
other profiles. A loader rejection contributes zero query coverage. All other
launch errors and any rejection of an NX-enabled image still fail the control.

All five measured query matrices agree on status, guard visitation and write
order. The four NX-enforced profiles return `0x0000000D`; x86 without
`NX_COMPAT` returns `0x00000032`. Successful queries require length exactly
4 bytes, report `ReturnLength = 4`, and write flags before return length.
`ReturnLength` may be unaligned and omitted. Output alignment is four bytes
when length is nonzero. A real process handle requires
`PROCESS_QUERY_INFORMATION` (`0x0400`); `PROCESS_QUERY_LIMITED_INFORMATION`
(`0x1000`) alone returns access denied. These are native observations for the
captured profiles, not a general promise for every Windows kernel or policy.

The header independently records PE `NX_COMPAT`, native kernel identity,
`GetSystemDEPPolicy` and `GetProcessDEPPolicy`. On this host, the system policy
is 2; the NX-enforced profiles report Win32 DEP flags 3 and permanence, while
the no-NX x86 profile reports flags 0 and no permanence. The raw private mask
is not the Win32 mask and must not be substituted for it. The observation
includes source, compiler and executable SHA-256 identities and cleanup
receipts. Parser tests reject incomplete matrices, changed input identities,
extra fields, malformed scalars and false availability records.
All five parser tests pass on macOS, Linux and native Windows. Microsoft's
documented `GetProcessDEPPolicy` contract covers 32-bit processes only; the
successful 64-bit calls in this build are observations beyond that contract.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| PE1 | The output describes the owned executable and current process. | PE machine checks, native header and source/binary hashes. | Attribution of the five matrices. | Change a binary or declared view; reject identity or width mismatch. | Confirmed for this capture |
| PE2 | Observed default masks do not establish all DEP policy states. | Queries only; no policy setter or policy override tested. | Limits of any future model selection. | Repeat with an owned process under independently configured DEP policy and query setters. | Retained boundary |

## Fixed-NX guest query

The adapter returns `0x0000000D` for the existing guest profile:
`MEM_EXECUTE_OPTION_DISABLE (1) | DISABLE_THUNK_EMULATION (4) | PERMANENT (8)`.
The virtual-memory manager enforces page execution permissions; no ATL thunk
emulator or mutable DEP policy exists. This reports that guest policy rather
than importing the host's default flags. A later policy implementation must
coordinate the query with effective page execution and exception-handler
policy. Changing the returned mask alone would not establish those semantics.

The existing common entry checks output alignment and probes `ReturnLength`.
The class adapter then checks exact length, handle type and the `0x0400` grant,
probes output, writes the four-byte flags, and publishes the four-byte return
length last. A read-only output guard fails without consuming its guard;
the earlier `ReturnLength` probe can consume a read-only guard. Other-process
state remains explicitly unsupported after type and access validation.
Object lookup and reached-page metadata checks take expected O(log h + log r)
time for h handles and r mapping runs; the existing object hash table adds an
O(o) worst case for o objects. Additional space is O(1), with fixed-size
four-byte stores.

The regression replays all 956 queries from the four local fixed-NX profiles
through the real service dispatcher for x86, x64 and ARM64 guests. It checks
status, output bytes, overlapping return-length stores, guard visitation,
return PC and stack cleanup. A separate check verifies that the existing RW
mapping cannot be fetched and that an unmodeled process does not publish data.
The Windows-only leaf check executes the selected installed NTDLL entry in
the native and WoW64 views, with exact output and caller-stack checks.
All 13 process-query regressions pass on macOS and Linux; 15 pass on the local
native Windows host, including the new installed native/WoW64 leaf check.
All 191 C API tests pass on each host. The Unix instruction-trace CLI check
also passes on macOS and Linux across its six guest CPU fixtures. These runs
include the separate native-entry draft and do not qualify its complete
installed-library exception path.

The unchanged Windows hardware-exception fixture now advances beyond class 34
and fails at unimplemented class 7 (`ProcessDebugPort`) in x86 startup. Its
failed verdict is preserved separately from the passing query and C API gates.

Hosted controls also pass on x64 kernels 20348 and 26100. Each contributes
956 queries across four executable profiles. The ten fixed-NX profiles across
all three kernels have identical 2,390 complete query rows. All 13 profiles
(3,107 queries) agree on input identity, status and guard behavior. No-NX x86
under system policy 3 instead returns raw mask zero with Win32 DEP flag 1 and
no permanence; this differs from the local policy-2 no-NX mask `0x32`.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| EF1 | The current guest enforces fixed NX and has no ATL thunk emulation or mutable DEP policy. | Virtual-memory permissions and the existing service surface. | Reported mask `0x0D`. | Fetch an RW mapping, or add a successful policy transition; any such change requires coordinated query and mapping updates. | Confirmed for the existing profile; setters remain unfinished |
| EF2 | The captured query validation order applies to the admitted fixed-NX profile. | Identical complete rows across ten profiles on three kernels. | Common adapter across guest ABIs. | Repeat the owned native guard/alias/handle matrix on another kernel or process policy. | Confirmed for captured profiles; broader policy states remain unqualified |

High impact, blocking full process qualification: default no-NX behavior and
mutable DEP require their own state and execution-policy implementation. The
query does not establish those contracts or complete the installed-library
exception fixture. No public or private ABI changes are made by this query.

Primary contracts: Microsoft's
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess),
[GetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessdeppolicy),
and [SetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy).
The private class and bit definitions are in System Informer's
[ntpsapi.h](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h)
and [ntmmapi.h](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h).
The local receipt is `local-29683-v2.json`. Hosted observations are in
[Windows 2022 job 121277022917](https://github.com/HexRaysSA/rax/actions/runs/40229184001/job/121277022917)
and [Windows 2025 job 121277022800](https://github.com/HexRaysSA/rax/actions/runs/40229184001/job/121277022800).
Independent controls run even when a preceding observer fails; that failure
remains a failed workflow step.
