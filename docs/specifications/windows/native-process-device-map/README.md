# ProcessDeviceMap

Class 23 of `NtQueryInformationProcess` reports the guest's mapped drive roots.
Explicit directory mappings represent fixed global guest drives. Native Windows
CLI selection snapshots the current subject's actual drive types and logon
visibility before execution. Guest queries consume those owned records without
forwarding guest handles or pointers to the host kernel.

The retained PHNT declaration is
[`PROCESS_DEVICEMAP_INFORMATION`](../native-test-alert/primary/phnt-ntpsapi.h)
and its EX variant, revision `53fbbdc5b5d2b08761db1c7b26bfa8c820924356`.
That directory's `sources.json` and license preserve provenance. Native query
lengths require independent observation: the basic record is accepted as
36 bytes on the measured ARM64 kernel, despite the 64-bit C union's nominal
40-byte size.

`native-oracle-v1.cs` through `native-oracle-v3.cs` call the real current-process
API. `observations-v2.json` contains 202 native ARM64 and x86/WoW64 query
observations, including exact buffer bytes, status, ReturnLength, input flags,
alignment and requested handle rights. It records source binding and raw receipt
checksums, the kernel version and NTDLL identity. It contains no private host
paths or subject identifiers.

Observed on Windows 11 kernel 10.0.29698.0:

| Contract | Native ARM64 | x86 under WoW64 |
|---|---|---|
| Accepted lengths | 36 and 48 bytes | 36 and 48 bytes |
| Bytes written on success | First 36 bytes | First 36 bytes |
| Successful ReturnLength | Requested length | 36 bytes |
| EX flags | Offset 40; 0 or 1 | Ignored |
| Output alignment | Four bytes | Unaligned stores accepted |
| Error ReturnLength | Existing sentinel retained | Zero when conversion reaches the final store |
| Bad ReturnLength | Probed before record publication | Successful record copied before final store faults |
| Handle right | `PROCESS_QUERY_INFORMATION` | `PROCESS_QUERY_INFORMATION` |

EX flag 1 selects logon DOS devices; on the recorded subject it excludes global
fixed/CD-ROM drives and includes the recorded session drive mappings. A custom
mapping replaces that drive's captured profile with its explicit guest mapping.
Unmapped slots in the native record are zero, distinct from `GetDriveTypeW`'s
`DRIVE_NO_ROOT_DIR` result for an unmapped letter.

`boundary-observations-v2.json` records 784 native ARM64 and x86/WoW64 calls:
both accepted lengths, 0 through 48 available bytes, and four second-page
protections. Native64 visits the starting byte before eight-byte stores; WoW64
uses sixteen-byte publication chunks. Faults retain the completed prefix, so a
whole-record write probe would change the observed behavior.

`native-x64-oracle-v1.c` and `x64-observations-v1.json` add 433 actual AMD64
caller observations on the same ARM64 Windows kernel. All 392 boundary cases
match the native64 status, ReturnLength, remaining protection and complete
before/after buffer bytes. The compiled image has no CLR directory; both its
loaded PE header and `GetProcessInformation(ProcessMachineTypeInfo)` report
AMD64. `IsWow64Process2` reports zero because x64 on Windows ARM64 has no WOW64
layer. The unchanged Microsoft references and their source/checksum records
are retained under `primary/`.

The native logon-directory observer covers both ARM64 and x86/WoW64. The exact
production Rust directory-capture module also ran on Windows ARM64 and matched
independent basic/EX queries with no increase in the process handle count.
This does not establish a Rust 32-bit host build or a physical AMD64 kernel.

These records qualify the observed kernel and ABI paths. Complete native owning
suites remain separate gates. Native thread and child-process creation remain
required features; this class advances child startup preflight without
implementing creation.
