# Guest-owned kernel security-device files

The installed Windows loader opens `\Device\KsecDD` as a file object. This
device is not a DOS drive file. Its handles, access grants, per-open state,
duplicates and final closure belong to the emulated process. Guest pointers,
paths and handles are never forwarded to the host device.

The selected native profile is Windows 10.0.29704, revision 1010, running on
ARM64 (`IMAGE_FILE_MACHINE_ARM64`, `0xaa64`). Acquisition reads the installed
revision and opens only the fixed device with access `0x100001`, share mask 7
and synchronous option `0x20`. It captures `FileFsDeviceInformation` and closes
the host handle before guest execution. The measured device type is `0x39`
and characteristics are `0x100`. Other profiles remain unselected.

## Independent native observations

The C producers run as the original, ordinary Windows user. They open a new
result file, retain I/O buffers until completion, and issue no device-control
requests. ARM64, AMD64 and x86 images are compiled separately. Each completed
capture binds the source, compiler, linker, images and the before/after SHA-256
identities of six installed System32/SysWOW64 DLLs.

| Corpus | Native observations | Scope |
| --- | ---: | --- |
| `native-open-controls-v2.json` | 102 open/create cases | Case, access, sharing, options, file/volume information, type, duplicate and final close |
| `native-open-controls-v3.json` | 102 open/create cases | The same controls plus waits before and after queries |
| `native-query-boundaries-v1.json` | 864 queries | Eight information classes, six length selections, three output layouts, two access/mode configurations, three caller ABIs |
| `native-query-iosb-faults-v1.json` | 288 queries | Six IOSB prefixes at a no-access page boundary, eight classes, two access/mode configurations, three caller ABIs |

Every failed open retains its caller handle/IOSB canaries. Query observations
include the complete IOSB and destination canaries. The boundary corpus also
records all 256 bytes of the combined caller region, so overlapping output and
IOSB publication can be compared exactly. The minimum-length selections are
0, 1, minimum minus one, minimum, minimum plus one and 64 bytes; repeated
lengths for a one-byte record are retained as distinct captured cases.

WoW64 output/Information aliasing copies the caller's requested span, including
untouched bytes beyond the returned record. Short caller buffers therefore
preserve a different prefix from larger buffers. Native64 queries retain
success and previously published data after a late IOSB store fault; the
WoW64 copyback reports access violation. The fault corpus records the exact
writable IOSB prefix and output bytes for each case.

The model selects the measured access grants `0x1`, `0x80`, `0x100000`,
`0x100001` and `0x20000`; share masks 0 and 7; and options 0, `0x20`, `0x21`,
`0x60` and `0x61`. `NtCreateFile` is selected only for `FILE_OPEN`, without
allocation, attributes or extended attributes. Other operations report an
explicit unsupported result instead of acquiring a host device handle.

Queries cover standard, access, position, mode, alignment, completion
notification, I/O priority and remote-device information. Access checks and
native64/WoW64 publication use the existing common file-query boundary code.
Idle files with `SYNCHRONIZE` are signaled; waits without that grant fail with
access denied. Same-process, same-access `NtDuplicateObject` uses the existing
guest object table and preserves the object identity and access grant.

Native `ObjectBasicInformation.PointerCount` includes kernel lookup-cache
bias: repeated observations can decrease while the device remains open.
These raw counts are retained for provenance; the guest table maintains its
own actual ownership counts.

## Evidence boundaries

These captures do not establish device-control, random-number generation,
relative device-name, arbitrary creation, foreign-process duplication or
memory-fault cases beyond the captured boundaries. They do not prove a complete installed-DLL
program run. A separate diagnostic on the updated DLLs stopped at an
unqualified AMD64 exception-dispatch frame before establishing a new device
execution frontier.

Portable replay runs the real service dispatcher for each guest ABI and checks
all captured output bytes. Native Windows controls and portable replay are
different evidence: compiling an ARM64 Windows image on another host is not a
native Windows test.

Primary SDK references are stored unmodified under `reference/`, with URLs and
SHA-256 provenance in `reference/provenance-v1.json`: Microsoft Learn
`NtOpenFile`, `IO_STATUS_BLOCK` and `NtQueryObject`.
