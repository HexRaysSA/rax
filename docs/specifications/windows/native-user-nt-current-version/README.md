# Creator Windows NT CurrentVersion registry key

While processing a nested command, installed ARM64 `cmd.exe` requests
`KEY_ENUMERATE_SUB_KEYS` on
`HKCU\Software\Microsoft\Windows NT\CurrentVersion`. The installed-library
registry snapshot captures that fixed key under the process creator's SID.
Absolute and primary-hive-relative opens use the same retained view. The
snapshot retains the original child names and their last-write times in
native enumeration order, along with the key's own bounded values and access
profile. Child records describe enumeration. Opening a descendant still
requires a corresponding captured key body.

Windows 10.0.29708.1003 ARM64 produced identical canonical names and identical
`KeyBasicInformation` bytes for the default, explicit 64-bit and explicit
32-bit Win32 views. Both `KEY_ENUMERATE_SUB_KEYS` and `KEY_READ` enumerated
13 children, with zero values on this fixture key. The next index returned
`STATUS_NO_MORE_ENTRIES`. The [native enumeration API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey)
and [record layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_basic_information)
define the native access and record format.

The loader opens the two fixed host views, checks their identity and grant,
and compares their retained records. Enumeration uses the existing aggregate
value and entry budgets. Cost is linear in the captured direct entry and value
bytes per sampled view. The host keys close before guest execution.

| ID | Assumption and dependent result | Basis | Falsification probe | Status |
|---|---|---|---|---|
| U1 | Both views select one shared creator key | Six matching native captures | Compare canonical name, access and ordered complete child records between views | Confirmed on the measured host |
| U2 | Guest opens stay within the creator's fixed subject | Creator SID and canonical alias validation | Open via each spelling and attempt a different SID | Covered by portable selection tests |
| U3 | A child record describes enumeration without acquiring its key body | Native class 0 exposes child metadata | Enumerate an entry, then attempt to open its body | Covered by the portable partial-header test |

Physical AMD64 and other Windows builds are outside the retained native sample.
The private projection receipt has SHA-256
`6cf024414133b781b9dc8570a9b7582d3bfa203af22291cbbacb6a25b4842512`.
