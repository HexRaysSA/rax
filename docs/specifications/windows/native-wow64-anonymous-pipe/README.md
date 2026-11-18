# WoW64 anonymous pipes

The installed x86 KernelBase from Windows ARM64 build 29708 uses three NTDLL
calls for `CreatePipe`. It opens the NPFS directory with `NtOpenFile`, creates a
synchronous byte-stream read end with `NtCreateNamedPipeFile`, and opens the
write end relative to the read end with `NtOpenFile`. The [capture](capture-v1.json)
identifies the installed binary and call addresses and records the x86 input
layout, access flags, default quotas, and timeout.

The [native probe](native-pipe.c) exercised the default quota and a 4-byte
inheritable pipe on ARM64, AMD64 compatibility, and x86 WoW64. It checks payload
bytes and end of file after the producer closes its endpoint. All three
processes exited zero with identical output. Microsoft documents the public
handle and lifetime contract for
[CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe).

WoW64 dispatch uses the existing ARM64 service implementation after decoding
the 14 x86 stack slots. The guest object namespace owns the pipe and handles.
The scheduler replay covers pointer-width output, partial writes and their
resumption, inherited access, and end of file. The service admits the existing
anonymous byte-stream profile.
