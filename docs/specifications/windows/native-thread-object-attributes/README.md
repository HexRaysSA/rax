# Unnamed native thread object attributes

The independent probe calls installed `NtCreateThreadEx` for suspended threads
in its own process, using `RtlExitUserThread` as the start routine. Every created
thread is resumed, awaited, checked for exit code zero and closed. It never
creates a thread in another process.

On Windows kernel 10.0.29704.0, all three caller ABIs (ARM64, AMD64, WoW64 x86)
accept the unnamed-object attribute mask `0x00011f42`. The corpus tests all 256
combinations of accepted bits, all 32 individual flag bits and three invalid
combinations: 291 cases per ABI, 873 total. Attributes have null root, name,
security descriptor and security QoS pointers.

Only `OBJ_INHERIT` (`0x2`) changes handle inheritance. In particular, a user-mode
`OBJ_KERNEL_HANDLE` (`0x200`) request returns an ordinary, usable user handle.
The other accepted hints do not introduce kernel privilege into the emulated
process. Unaccepted bits return `STATUS_INVALID_PARAMETER`. On this kernel,
64-bit callers retain the initial output word on rejection; WoW64 writes zero.

The retained `.txt` files contain exact native output, including native handle
values. Replay compares statuses, output on rejection, user visibility and
inheritance; successful handle numbers are local identities and are not
compared. The emulator creates only guest scheduler threads and checks normal
thread access rights. Named threads and non-null security/QoS descriptors
retain their explicit unsupported result.

`native-thread-object-flags.cpp` is the independent native source.
`qualification-29704.json` records source, executable and installed-library
identities and the validation scope. The separate thread creation flags
parameter, including native XTA's `0x27` request, is outside this change.

The official [OBJECT_ATTRIBUTES documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wudfwdm/ns-wudfwdm-_object_attributes)
defines the structure and flag names. Exact user-mode acceptance and output
behavior here are measured results from the retained native profile.
