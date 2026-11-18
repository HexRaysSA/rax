# Basic process information for a guest child

The native ARM64 and WoW64 x86 probes each ran 20 class 0 queries on
Windows 10.0.29708.1003. Each created a suspended child from the
architecture's installed CMD, queried it, resumed it, and waited for its
exit code of zero. The child and parent IDs in both record forms matched
the IDs from the process handles. The initial exit status was
`STATUS_PENDING` and the completed exit status was zero.

| Caller | Basic bytes | Extended bytes | Child PEB before exit | Child PEB after exit | Extended flags before and after exit |
|---|---:|---:|---|---|---|
| ARM64 | 48 | 64 | Present | Preserved | `0x0`, `0x4` |
| WoW64 x86 | 24 | 32 | Present | Zero | `0x2`, `0x6` |

The WoW64 record preserves the caller's four priority bytes in both
record forms. It accepts output addresses at byte offsets 0 through 4
from an eight-byte-aligned buffer. ARM64 accepted offsets 0 and 4
and returned `STATUS_DATATYPE_MISALIGNMENT` for offsets 1 through 3.
Each caller received `STATUS_INFO_LENGTH_MISMATCH` for the tested
lengths other than its two selected lengths. Failed alignment,
length and handle validation preserved the length destination.

The native observations are represented by the ARM64 and x86 streams
with SHA-256
`6c01b59c40faecb2b2dd999ed75b8c3f12fd7301442457e93b957083619b27f5` and
`43698496992715515d8cdd49589f7f2f3d7fe65c73e0ccd511dbaa818c8330e0`.
The [pinned PHNT declarations](../native-console-owner/phnt-ntpsapi.h)
name the extended flags `IsWow64Process` and `IsProcessDeleting`.
RAX sources the IDs and PEB from the guest child and retains the child
identity and exit status through the open process handle after reaping.
