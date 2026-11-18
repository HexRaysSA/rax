# WoW64 child creation on Windows ARM64 build 29708

The installed SysWOW64 CMD pipeline invoked service `0xd1` twice. It supplied
a counted `\??\C:\WINDOWS\system32\cmd.exe` image name both times, with
`MAXIMUM_ALLOWED` for both handles, process flags `0x204`, thread flags
`0x1`, zero object attributes, `InitFlags=0x20000003`, and
`AdditionalFileAccess=0x81`. The caller supplied normalized 32-bit process
parameters with an inherited console and redirected standard streams. Both
calls returned success and the pipeline wrote `rax pipe\r\n`.

| Record | WoW64 caller | Analyzed native dispatch |
| --- | --- | --- |
| Creation record | 72 bytes, original size retained on success | 88 bytes, size cleared on success |
| Attribute list | 68 bytes, four 16-byte attributes | 136 bytes, four 32-byte attributes |
| Client ID output | 8 bytes | 16 bytes |
| Image information output | 48 bytes | 64 bytes |

The image-name attribute uses a 62-byte UTF-16 path. The other attributes
request the client ID, image information and CHPE creation. The emulator
loads the mapped SysWOW64 image into its own pure x86 guest. The child
starts suspended. The parent receives process and thread handles for its
object table, along with the optional file and Image Section handles.

The success record uses state 6 and sets manifest flag `0x8` when the
child has the selected embedded manifest. Native CMD reported parameter
flags `0x6001` and a manifest size of `0x426` bytes. The WoW64 offsets
are byte offsets from the start of the 72-byte record.

| Field | Offset | Width in bytes |
| --- | ---: | ---: |
| State | `0x04` | 4 |
| Output flags | `0x08` | 4 |
| File, section handles | `0x0c`, `0x10` | 4 each |
| Native, WoW64 process parameters | `0x18`, `0x20` | 8, 4 |
| Current parameter flags | `0x24` | 4 |
| Native, WoW64 PEB | `0x28`, `0x30` | 8, 4 |
| Manifest address, size | `0x38`, `0x40` | 8, 4 |

Both parameter records belong to the emulated child. Each record contains
its own counted UTF-16 strings. They share that child's environment
allocation and handle table. The native-layout record is attached to the
existing companion PEB. The supported file redirect covers the captured
stock CMD alias on this Windows build. The existing native64 path retains
its established creation and copy-back rules.

The [ARM64 CDB command file](capture-wow64-create-29708.txt) observes the
32-bit argument array at the WoW64 dispatcher before conversion and after
return. It runs the current-user stock SysWOW64 CMD command
`/d /c "echo rax pipe|cmd /d /v:on /c (set /p value=^&echo !value!)"`.
The installed CMD SHA-256 is
`e44c6777f63982211eb0ac7d6a2a6d53b46bff1928e5005c84b2847a25761002`.
The raw x86 dispatcher trace SHA-256 is
`98c95ffd79c1775c0b725862dd903371cfc8135ca1b0a4cb667ed6b31078423e`.
The corresponding native64 dispatch trace SHA-256 is
`0f73f318b2f800bad1452f605f642b2f267e7dfce8401e1162ca82f1e3bc0b6c`.
