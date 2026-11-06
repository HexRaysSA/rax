# Native thread query observations and guest implementation

The implementation covers `NtQueryInformationThread` classes 0
(`ThreadBasicInformation`), 9 (`ThreadQuerySetWin32StartAddress`) and 12
(`ThreadAmILastThread`). Other recognized classes remain explicitly unsupported.
Guest calls use guest object identifiers, handles, addresses and scheduler state;
no guest argument becomes a host thread query.

`observations-v2.json` records 116 native rows per caller profile, comprising
113 thread queries and three independently rejected `NtOpenThread` controls.
`boundary-observations-v3.json` adds 71 rows per profile. The native callers are
ARM64 and pure x86 under the same Windows 10.0.29698.0 ARM64 kernel. The x86
observer uses raw native process creation with `PS_ATTRIBUTE_CHPE=0`, and verifies
that its mapped NTDLL is the physical SysWOW64 image. An x64 query-matrix capture
has not been collected; the shared 64-bit record is additionally exercised through
the x64 guest ABI and the separate installed-library thread witness.

| Contract | Native 64-bit caller | Selected pure WoW64 caller |
|---|---|---|
| Basic information size | Exactly 48 B | Exactly 28 B |
| Win32 start size | Exactly 8 B | Exactly 4 B |
| Last-thread size | Exactly 4 B | Exactly 4 B |
| Output alignment | 4 B | Unaligned converted classes 0/9 accepted; class12 requires 4 B |
| Basic information length mismatch | Output and return length unchanged | Return length28, output unchanged, except null output reports invalid parameter |
| Start length mismatch | Output and return length unchanged | Return length `0xFFFFFFFC`, output unchanged |
| Basic query access | `THREAD_QUERY_INFORMATION` or `THREAD_QUERY_LIMITED_INFORMATION` | Same |
| Start query access | `THREAD_QUERY_INFORMATION` | Same |
| Last-thread handle | Ignored; count belongs to caller process | Same |
| Exited TEB in basic record | Zero | `0x2000`, the observed conversion bias of a zero native TEB |
| Retained start | Survives thread exit | Same |
| Basic output crossing an inaccessible page | Earlier complete 8 B stores can be published | Probe all28 B before any publication |
| Read-only output guard | Basic consumes it; class9/12 reject write protection without consuming it | All three observed classes consume it |
| Return-length fault | Probed before class/length dispatch | Converted classes0/9 catch the fault but consume a reached guard |

Basic-information values describe the existing one-CPU virtual scheduler:
affinity1, scheduling priority8, relative base priority0. Native transient boosts
and host CPU masks are observations, not virtual state. Active records use the
guest TEB/PID/TID and pending status259; retained exited objects keep their TID,
exit status and Win32 start after TEB/stack destruction. The private start ledger
is destroyed with the final object reference, independently of numeric handle
reuse.

WoW64 basic-info kernel failures copy undefined private scratch words while
leaving the separately queried TEB destination unchanged. Captures retain those
bytes as evidence; tests do not claim value equivalence for them. The guest uses
zeroed private scratch rather than importing native stack contents.

The retained PHNT header ends before the selected kernel's newest class:
class60 is recognized natively but rejected by the selected WoW64 wrapper;
classes61,64 and65535 are rejected by both observed profiles. Recognized but
unimplemented query classes must not fabricate successful records.

Primary references:

- [Microsoft NtQueryInformationThread](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread)
- [Retained PHNT THREADINFOCLASS and THREAD_BASIC_INFORMATION](../native-test-alert/primary/phnt-ntpsapi.h)
- `native-oracle-v2.cs`: successful/failed native query and owned worker lifecycle matrix.
- `native-oracle-v3.cs`: guard, protection, crossing-page and class-range matrix.

Validation remains source-specific. Focused replay success does not establish
that the shipping CLI can complete the unchanged thread witness, that a complete
owning library passed on all native hosts, or that full guest child-process
supervision exists. Those are separate gates in the process-emulation work.
