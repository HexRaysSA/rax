# Native synchronous file writes

`NtWriteFile` is dispatched using service numbers decoded from the selected
NTDLL. It writes through guest-owned synchronous file handles, standard-stream
console handles, and NUL. Installed KERNEL32/KernelBase code therefore retains
its real user-mode implementation when writing CLI output. No guest request is
forwarded as an unrestricted host NT call.

The [Microsoft NtWriteFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile)
defines nine arguments, write/append grants, current/explicit/end offsets and
completion events. [IO_STATUS_BLOCK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block)
contains a pointer-sized union followed by a pointer-sized byte count: 8 bytes
for x86 and 16 bytes for x64/ARM64. Sources were checked on 2026-10-28.

`probe-v3.c` and `run-v3.py` produced `observations-v3.json` on Windows ARM64
10.0.29695. The 54 rows cover 18 cases for ARM64, x86 and x64. x86/x64 ran through
Windows compatibility support on that host; this does not establish independent
native AMD64 kernel fault-order equivalence. The replay executes the production
service dispatch on all three guest ABIs and compares status, complete IOSB
bytes, output bytes, partial publication and unchanged LastError.

Measured behavior includes invalid-handle priority over inaccessible IOSB,
offset and key arguments; zero-length NULL-buffer success; byte-unaligned IOSB
success; native64 early Status probing; and WoW64's late IOSB copyback. An x86
write with IOSB address 1 reaches stdout before returning access violation.
When only the status union is accessible, the write and status store complete
before the Information store faults on all three ABIs. These effects are not
rolled back or silently retried.

`probe-v1.c` captures the original 12 cases. Version 2 retained that source
without successfully adding the six new controls; its additional case labels
are repeated default calls and provide no evidence for those controls.
`observations-v2.json` is retained as excluded history. Version 3 contains the
actual additional controls. Executed probes and controllers remain unchanged.

Run a new capture in an unused in-tree output directory on Windows:

```text
python docs/specifications/windows/native-file-write/run-v3.py --compiler-env <saved-VS-environment.json> --output <repository>/target/native-file-write-new
```

The implementation bounds one write at 16 MiB, using O(N) time and O(N) scratch
for N bytes. File writes support explicit offsets, current position and append
access; completion events signal after the synchronous operation. Unit tests
also exercise file holes, append-only grants and denied writes on all ABIs.
Asynchronous file handles, guest pipe objects, APC/completion-context delivery
and requests above the bound remain explicit unsupported results. Partial host
I/O errors, guard-order permutations and additional kernel versions are outside
the measured equivalence claim. This feature does not implement NtReadFile or
NtCreateFile and does not establish general Windows process completeness.

The additional `module-v1.c` / `module-run-v1.py` capture records loaded KERNEL32
identities. On build 29695, the native x86 control reports the logical path
`C:\WINDOWS\System32\KERNEL32.DLL`, timestamp `0x1DA80894` and image size
`0x00121000`. The selected installed pure-x86 SysWOW64 file has timestamp
`0x5D3D41A1`, image size `0x000F0000`, and SHA-256
`0c917a264acf2790720f9b1f4b2ba6e003e09b5d9731f66d108937cc7e283450`.
The capture does not resolve the physical backing file behind the native logical
path. The existing [pure-x86/CHPE profile](../native-x86-chpe-profile/README.md)
owns that selection policy. The CLI test compares pure-x86 metadata with the
installed pure-x86 file rather than treating a different image family as an
identical PE-header oracle. Native host-ABI output remains an exact native
comparison, and all process exit-code bits remain exact in both cases.
