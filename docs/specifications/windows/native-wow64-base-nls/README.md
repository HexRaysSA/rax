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

## Installed released builds

Independent observations ran the shipped SysWOW64 CMD in a debugger-owned
x86 child and queried the current account through the installed native64
NTDLL. Each session-2 runner observed the same 1,660 payload bytes through
the native64 call and through the x86 KernelBase leaf. The x86 call returned
status zero with unchanged ESP before its own RET8. The destination lies in a
committed, writable image page at a fixed RVA relative to the relocated
KernelBase image. [Native measurements](https://github.com/HexRaysSA/rax/actions/runs/45161810527).

| Host kernel build | Native machine | Leaf RVA | Parent return RVA | Thunk RVA | Destination RVA |
| --- | --- | --- | --- | --- | --- |
| 20348 | AMD64 | 0x155090 | 0x12bde7 | 0x18cc30 | 0x211f2c |
| 26100 | AMD64 | 0x16b660 | 0x132c91 | 0x1d28a0 | 0x27210c |
| 26200 | ARM64 | 0x176450 | 0x16e1ed | 0x1e7fe0 | 0x28914c |

| Host kernel build | Installed SysWOW64 KernelBase SHA-256 | Observed locale payload SHA-256 |
| --- | --- | --- |
| 20348 | 47fe41e92b448ec14ed068be0c2303bcff43b668fea2ed196e19d119dba6fd3f | a11aabf3c7b48f56d12043d939f82c8a39f68b03626046a2f8a5f6b7b895b1bb |
| 26100 | 1126a361e19576a1570813e2157044ce406725029e505fe3409821cf213485f6 | a5475a6f810f3c3a689d093266889e5a2d0b1aa53dbf8f5332ff3733907b130d |
| 26200 | 06a189243165da33d22b67f0a1b22e48bb65b969848af145db3cbbf9c088240c | 391ca8eaafb6a9ca4e2d40809c1bcacf4750f6455938210486b48d4b4ce2ce39 |

These payload hashes describe the sampled accounts. Guests receive the fixed
current-session native snapshot selected at process open. The released
KernelBase profiles admit selector 0x300b. The separate 0x300e child-creation
selector remains bound to the previously measured preview profile.

The measurement source is [released-startup-v1.cpp](released-startup-v1.cpp).
Build it as native 64-bit and pass the installed SysWOW64 CMD path and exact
kernel build. Run [fixed-query.rs](../native-base-csr-nls/fixed-query.rs) in the
same session and compare its six successful samples with the observer's
NLS_AFTER record.
