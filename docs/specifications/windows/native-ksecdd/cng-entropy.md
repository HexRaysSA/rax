# Installed ARM64 CNG entropy request

On Windows 10.0.29708.1003 ARM64, the installed ARM64 `certutil -hashfile`
loads `bcryptprimitives.dll`, which opens `\Device\CNG` through
`NtOpenFile` and requests fresh bytes through `NtDeviceIoControlFile`.
The stock caller opens the exact device name with `OBJ_CASE_INSENSITIVE`,
access `0x100001`, share mask `7`, and synchronous nonalert option `0x20`.

| Operation | Input | Output | IOSB Information |
| --- | --- | --- | ---: |
| Open | Counted absolute device name | Synchronous file handle | 0 bytes |
| FileFsDeviceInformation | Class 4 | Device type `0x3f`, characteristics `0x100` | 8 bytes |
| Device control `0x390008` | Null pointer, 0 bytes | 48 fresh bytes | 48 bytes |

The [native observation](cng-entropy-arm64.json) records three independent
opens and successful synchronous requests with null Event, APC routine,
and APC context. The caller's 16-byte guard after the declared output stayed
unchanged. The original request and native repeat runs establish the selected
shape. They do not establish the generator algorithm or entropy quality.
The documented `bcryptprimitives.dll` export `ProcessPrng` is public
context, separate from the privately observed kernel control.

The installed profile captures device metadata once using a fixed absolute
path and releases the native handle. If that profile is unavailable, the
guest open reports an unsupported CNG device. The selected guest request
validates both destinations and fills a local 48-byte buffer using the
host entropy API. It publishes the bytes and successful IOSB only after
that source succeeds. The guest's startup seed does not supply these bytes.
Every guest handle belongs to the guest namespace and never refers to a
native device handle. Other guest architectures, control shapes,
asynchronous delivery and alias-dependent native behavior are unmeasured.

- [NtDeviceIoControlFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile)
- [ProcessPrng](https://learn.microsoft.com/en-us/windows/win32/seccng/processprng)
