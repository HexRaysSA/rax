# Native owned-thread termination

The independent C++ probe uses installed Windows APIs on owned current-process
threads only. It links no emulator implementation. Windows kernel10.0.29704.0
on ARM64 supplies378handle/lifetime rows plus18self rows for each of ARM64,
AMD64 and WoW64,1188observations total. Every probe process exits naturally0;
all six installed-library identities hold. Sources and identities are retained.
The PHNT declaration in ../native-process-tls/phnt-ntpsapi.h documents NULL as
current-thread termination; measured real/pseudo handle behavior is below.

`THREAD_TERMINATE` (0x1) is required for real thread handles, including real
handles to the caller. Type checks precede rights. Tagged low handle bits are
accepted. Repeated valid calls return success and retain the first requested
exit code; an already-retired object retains its original exit code. Invalid
and wrong-type handles remain distinct; LastError is preserved. Self calls
through NULL, the current-thread pseudo handle, or a permitted real self handle
terminate without returning. Denied self calls return before a separate raw
self-termination cleanup.

The immediate zero-time wait records timing, not a universal completion
guarantee. In this capture live targets are still unsignaled there; terminal
status is sampled after a join. Guest API return must not itself fabricate
retirement before the scheduler processes the pending forced termination.
The guest scheduler's subsequent quantum order is a separate execution choice.

After `case`,18hexadecimal fields are index, handle kind, granted access, tag,
pre-retired phase, requested exit code, first status, LastError, immediate wait,
second status, fallback cleanup status, final wait, exit-query success, final
exit code, basic-query status, basic-query bytes, basic exit code and TEB nonnull.
Kinds0/1are real thread/closed thread;2invalid;3current process pseudo;4event;
5real process. After `self`,8fields are kind, rights, reached marker, returned
marker, returned status if any, final wait, exit-query success and exit code.
Self kinds0/1are NULL/pseudo;2real;3current process;4invalid.

Native64 basic query bytes are48; WoW64 bytes are28. An exited WoW64 basic-info
conversion reports TEB0x2000; native64 reportsNULL, consistent with the existing
independent thread-query corpus. Tests normalize guest object identities and
addresses and preserve the native statuses and lifetime transitions.

This capture does not qualify foreign-process thread termination or debugger
event delivery. No guest request is forwarded to host thread handles.

The separate `installed-thread-termination.cpp` fixture and
`installed-observer.rs` reproduce eight suspended creation-flag combinations
through installed Win32 TerminateThread on each guest ABI. The observer uses
WindowsProcess with native libraries enabled and the host drive map; it does not
replace the production CHPE context exchange. `installed-provenance-v1.json`
binds the compiler/linker commands, current no-optional-features RAX rlib and
Windows DLL identities. Run the observer on Windows with the fixture executable
path as its sole argument. Its5000-turn bound reports assertion completion
separately from natural guest exit. All three direct native controls exit0.
ARM64 and WoW64 guests each complete8cases/97assertions and exit0; AMD64 completes
the same assertions and reaches the existing NativeXTA shutdown wait. Its host
observer exits0, but its guest has no natural-exit result.
