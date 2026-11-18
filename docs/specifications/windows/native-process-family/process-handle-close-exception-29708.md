# Process close-exception information on Windows build 29708

The x86 `cmd.exe` pipeline
`echo rax pipe|cmd /d /v:on /c (set /p value=^&echo !value!)`
completed on Windows ARM64 10.0.29708.1003 with exit code 0 and the
10 bytes `rax pipe\r\n`. The baseline installed-library replay stopped
in an owned WoW64 child at `NtSetInformationProcess` class 71.

Class 71, `ProcessRaiseUMExceptionOnInvalidHandleClose`, uses a
four-byte ULONG in both directions. Setting a nonzero value exposes 1 on
query. Setting zero exposes 0. A new process starts with 0 independently of
its parent's value. The current-process pseudo-handle is accepted. Real
process handles require `PROCESS_SET_INFORMATION` for a set and either
`PROCESS_QUERY_INFORMATION` or `PROCESS_QUERY_LIMITED_INFORMATION` for a
query. An owned child with a retained handle returns
`STATUS_PROCESS_IS_TERMINATING` once it exits.

Alignment is checked for nonzero lengths before the length check. Native64
also rejects a destination or source span above the native user limit at
this point. WoW64 reaches the class-specific length check before accessing
an aligned source or destination at the top of its address range. The
setter reads the ULONG before looking up the handle. The query probes an
optional ReturnLength destination before checking the length or handle.
It preserves that destination on success, validates the handle before
writing the ULONG, and leaves the output unchanged on handle failure.

In the standalone native probes, changing class 71 preserved the observed
invalid-handle return from `NtClose` and the invalid-handle failure from
`CloseHandle`. The RAX implementation models standalone process state and
uses only the guest handle table. The probes qualify behavior without an
attached debugger.

The independent C probe used the installed NTDLL exports from ARM64, x64,
and x86 processes on the same Windows ARM64 machine. Each process completed
270 observations, with eight little-endian DWORDs per observation and no
stderr. The x64 and x86 processes used Windows' installed compatibility
layers. A separate ARM64 process exercised set and query through real handles
to its own live and exited children.

| Probe | Output bytes | SHA-256 of output |
| --- | ---: | --- |
| ARM64 C | 8640 | `d92aebd18152df39008933457cd2948f7bb9dfe28a4284a58f1ee6f95216f557` |
| x64 C | 8640 | `d92aebd18152df39008933457cd2948f7bb9dfe28a4284a58f1ee6f95216f557` |
| x86 C | 8640 | `cd44d49f2ffd9ceedc119e4e636df8bf1a0531150714fc8fb669ff7d9f726a6f` |
| ARM64 child observations | JSON | `c9958999f3a86fc4814c7c81ce58b9b544379316907f7a86477bc76a0462a205` |
