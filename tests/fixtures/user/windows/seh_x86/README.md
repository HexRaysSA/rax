# x86 SEH unwind fixture

`build.sh` creates a freestanding PE32 i386 executable. Its only imports are
`KERNEL32!RtlUnwind` and `KERNEL32!ExitProcess`. The assembly installs two
stack registration records through `FS:[0]`, targets the outer record, and
requires the inner handler to observe `EXCEPTION_UNWINDING` exactly once. The
outer handler must not run. The continuation at `TargetIp` verifies EAX,
`FS:[0]`, and the stack pointer; a normal return takes a distinct exit path.

The target stack-pointer expectation is the saved post-`stdcall` caller ESP
(`entry ESP + 4-byte return address + 16-byte arguments`), a bounded RAX
profile. The Microsoft [`RtlUnwind` contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind)
specifies the continuation address and integer return register, but does not
define an x86 ESP restoration formula. Native Windows equivalence for that
private detail is unknown. The integration test runs the executable with
instruction slices of 1 and 4,096.
