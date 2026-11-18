# WoW64 KernelBase BASE NLS startup

Windows ARM64 build 29708.1003 uses a private WoW64 service for the x86
KernelBase per-user locale cache. Stock SysWOW64 CMD reaches this service
through the process's mapped KernelBase image. The Microsoft public PDB
`wkernelbase.pdb`, GUID `9A96D149-95FE-2BE7-58FC-B4796745EB11`, DBI
age 1, names the leaf `_NtWow64CsrBasepNlsGetUserInfo@8`. The installed
SysWOW64 KernelBase SHA-256 is
`e6d7d090b77f64c9e3a409d958510c5b80285e46d1a42a89770693f26477e37a`.

| Guest observation | Value |
| --- | --- |
| WoW64 service selector | `0x300b` |
| Leaf entry RVA | `0x1df110` |
| Transition return RVA | `0x1df11c` |
| Immediate parent return RVA | `0x163b9d` |
| Relocated transition thunk RVA | `0x27e160` |
| Destination RVA | `0x2a5eac` |
| Destination size | 1,660 bytes |

The installed ARM64 `wow64base.dll` PDB names the corresponding native
wrapper. Its implementation issues the BASE locale query `0x1001b` and
copies the result to the x86 caller on success. Public
`GetUserDefaultLocaleName` calls populated the same 1,660-byte cache on
native ARM64 and in three fresh x86 compatibility processes. The two ABI
views matched across all 1,660 bytes. The SHA-256 of the observed payload
under the measured user was
`a4b0cb61e23b1301f6e77f698760a796c0ef3b2ed3c7b04e3e70dd3bebb341d6`.

The private selector is accepted only from the selected executable section
and measured caller geometry. The handler validates the guest's existing
CSR connection and copies its selected immutable BASE NLS snapshot into
that view. The ordinary WoW64 return leaves the leaf to perform its own
`RET 8`. The service makes no guest-directed host calls.

Selection hashes the installed PE in linear time and space. Each lookup
checks fixed code and stack spans and copies one fixed 1,660-byte payload.
The guest binding regression varies the selector, return PC, parent, size,
destination and section owner, including address reuse after unmap.
