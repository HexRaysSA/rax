# WoW64 BASE child registration on build 29708

On Windows ARM64 10.0.29708.1003, native execution of the installed x86
CMD pipeline registered two suspended x86 children before resuming them. CDB
observed the CHPE KernelBase wrapper submitting the native CSR
`NtAlpcSendWaitReceivePort` request with API `0x1001d` and a 600-byte message.
Both calls returned success. The direct subprocess emitted
`rax pipe\r\n` and exited with status zero.

The selected pure-x86 KernelBase image has SHA-256
`e6d7d090b77f64c9e3a409d958510c5b80285e46d1a42a89770693f26477e37a`.
Its private leaf `NtWow64CsrBasepCreateProcess2` at RVA `0x1df140`
uses service `0x300e`, resumes at RVA `0x1df14c`, and returns with
`RET 4`. The measured direct branch in `CreateProcessInternalW` returns
to RVA `0x1a2168`. The installed x86 image under emulation reached the same
relative locations and supplied the same request layout.

| Offset | Width in bytes | Observed meaning |
| --- | ---: | --- |
| `0x00`, `0x04` | 4 each | Child process and primary thread handles |
| `0x08`, `0x0c` | 4 each | Child process and primary thread IDs |
| `0x28` | 4 | Additional live handle in the caller |
| `0x2c`, `0x34` | 8 each | DOS and NT UTF-16 path descriptors |
| `0x60`, `0x68` | 8 and 4 | Child manifest address and size |
| `0x80` | 8 | UTF-16 language descriptor |
| `0x8c` | 4 | Changed from zero to one on success |
| `0x98` | 8 | UTF-16 assembly name descriptor |

Both native requests supplied the DOS and NT forms of the System32 CMD
path and the manifest mapped in the actual x86 child. The assembly output
length changed from 118 to 64 bytes and its 120-byte capacity was preserved.
The server wrote `Microsoft.Windows.FileSystem.CMD` and a UTF-16 terminator.
Bytes beyond the terminator were preserved in both native replies.

RAX admits the private service only from the selected image and measured
call site, with an owned CSR connection and matching suspended guest child.
It derives the assembly name from that child's mapped manifest and
completes registration after probing and writing the caller's outputs.
The modeled request has no host CSR side effects.
