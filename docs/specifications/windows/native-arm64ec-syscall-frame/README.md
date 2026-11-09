# Guarded ARM64EC NTDLL syscall frames

The installed NTDLL guard on Windows kernel 10.0.29698.0 around `NtCreateFile` subtracts
16 bytes from SP, stores a cookie, executes SVC, checks that cookie, and restores
SP. Its ninth through eleventh arguments remain above this private frame.

The emulator previously treated the cookie as `CreateOptions`, returning
`STATUS_INVALID_PARAMETER` while the installed loader opened `xtajit64.dll`.
The correction changes only the argument base for an exactly recognized guard
inside the selected NTDLL. The running SP and cookie remain untouched so the
real postlude executes. Bare stubs and other guest code retain their existing
argument layout. Unrecognized guarded wrappers remain explicit failures.

`observations-v1.json` records the source-bound diagnostic observation. This is
an ARM64 Windows kernel executing an AMD64 application through its ARM64EC DLL
view; it is not evidence from physical AMD64 Windows hardware. End-to-end
native witness now confirms `NtCreateFile` succeeds with arguments 9-11 equal
to `0x60, 0, 0`, while the prior build returned `STATUS_INVALID_PARAMETER`.
The native program exits zero; emulation stops at the next unimplemented
`NtGetCachedSigningLevel` service and exits 125. The paired-CPU regression also
executes the captured prelude and postlude, verifies the original cookie and
checks argument decoding without changing the running SP. Owning-library
platform gates remain required.
