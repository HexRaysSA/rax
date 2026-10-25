# ProcessExecuteFlags native observations

The installed WoW64 NTDLL reaches `NtQueryInformationProcess` class 34 while
initializing the hardware-exception fixture. This class remains unimplemented
in the model. These controls measure its native contract before implementation;
they do not change any host DEP policy or execute a guest request on the host.

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

High impact, blocking full process qualification: guest memory currently
enforces page execution permissions, while the measured no-NX x86 process has
DEP disabled. Returning a copied native default without implementing the
corresponding guest policy would not establish compatible behavior. The query
model, policy transitions, and complete installed-library exception fixture
remain unfinished. No public or private ABI changes are made by this control.

Primary contracts: Microsoft's
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess),
[GetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessdeppolicy),
and [SetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy).
The private class and bit definitions are in System Informer's
[ntpsapi.h](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h)
and [ntmmapi.h](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h).
The native receipt is `local-29683-v2.json`. Hosted x64-kernel observations
remain pending. Independent controls run even when a preceding observer fails;
the preceding failure remains a failed workflow step.
