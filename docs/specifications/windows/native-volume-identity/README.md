# Windows volume identity

`NtQueryVolumeInformationFile(FileFsVolumeInformation)` returns creation
time, serial number, label byte count, object-ID support and a UTF-16LE label
from the retained file's Windows volume. The query uses private native buffers.
For a metadata-only handle, the reopened file must match the retained identity.
On a Unix host, a mapped Windows volume uses the low 32 bits of the host device
number as its serial, with zero creation time and an empty label. This follows
the existing virtual Windows disk profile.

The syscall admits buffers of at least 24 bytes and requires 8-byte alignment
in the measured ARM64 caller. The initialized prefix is 18 bytes. When the
label exceeds the remaining capacity, the provider returns
`STATUS_BUFFER_OVERFLOW`, keeps the full label byte count in the prefix, and
copies the available bytes. The last byte can be part of a UTF-16 code unit.

| Offset in bytes | Size in bytes | Field |
|---|---|---|
| 0 | 8 | Volume creation time |
| 8 | 4 | Volume serial number |
| 12 | 4 | Full UTF-16LE label length |
| 16 | 1 | Object-ID support |
| 17 | 1 | Reserved |
| 18 | Variable | Copied label bytes |

Completion reports the initialized byte count in `IO_STATUS_BLOCK.Information`.
The query shares the existing class 5 copy and completion paths for synchronous,
asynchronous and WoW64 callers. The guest range probe is linear in the number
of output pages. The Windows adapter starts with up to 512 bytes of scratch and
grows it only on overflow, up to the smaller of the request length and 16 MiB.

Microsoft documents the [native query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile),
the [native structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_fs_volume_information)
and the [protocol representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bf691378-c34e-4a13-976e-404ea1a87738).
The lengths, native alignment, short-copy behavior and IOSB stores below come
from the user-mode syscall observations on Windows 10.0.29708.1003 ARM64.

| Native control | Result |
|---|---|
| Local NTFS files and directory | 18 initialized bytes, empty label, object-ID support set |
| Parallels share files and directory | 48 initialized bytes, 30-byte label, object-ID support clear |
| Anonymous pipe read and write ends | 36 initialized bytes, 18-byte `NamedPipe` label, object-ID support clear |
| Synchronous and overlapped local files | Synchronous completion preserves the upper IOSB status word. Overlapped completion clears it. |
| NUL | `STATUS_INVALID_DEVICE_REQUEST` with IOSB and output bytes preserved |

[profile-29708-v1.json](profile-29708-v1.json) records the 110 native calls.
Volume creation times, serials and share labels are machine-specific.

| ID | Assumption and dependent result | Basis | Falsification probe | Status |
|---|---|---|---|---|
| V1 | Class 1 uses the existing filesystem-query completion path | Native file controls and class 5 ABI replays | Compare all output and IOSB bytes for both handle modes | Confirmed for the measured ARM64 calls. Guest tests exercise all three supported ABIs. |
| V2 | The Unix device number can identify a guest virtual volume within the existing DriveMap model | The retained identity contains the device number | Compare multiple handles on one mapped device and compare distinct device numbers after truncation | Serial mapping is stable per device. Lower 32-bit collisions are possible. |
| V3 | Short labels can end inside a UTF-16 code unit | Shared-provider requests with odd lengths | Compare an odd-length output and the following sentinel byte | Confirmed for the measured shared provider. |

Native x64 and WoW64 class 1 capture is outside this sample. The tests cover the
shared RAX service on ARM64, x64 and x86 guest ABIs. The Windows retained-file
test independently queries the current fixture volume and compares the complete
record. The class 5 replay covers the pre-existing lengths, grants, modes,
guards and aliases through the shared implementation.
