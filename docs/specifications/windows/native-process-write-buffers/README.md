# Process write-buffer barrier

`NtFlushProcessWriteBuffers` takes no arguments and returns NTSTATUS.
The Win32 `FlushProcessWriteBuffers` wrapper takes no arguments and returns
void. It makes writes visible between processors running threads of the
current process. [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushprocesswritebuffers).

The Windows guest scheduler serializes guest CPU and HLE execution on a single
host thread. The two guest entry points execute a sequentially consistent fence
on that thread before the scheduler can run another guest thread. The native
entry point returns `STATUS_SUCCESS`. Both leave the guest thread's last-error
value intact.

The [native observations](native-29704.json) record three repetitions for
each of ARM64, AMD64 compatibility, and WoW64 x86 on ARM64 Windows
10.0.29704.0. Compile [the producer](observe.cpp) against the Windows SDK
for each target and run each executable in the same session. The observations
establish return status and last-error behavior. The scheduler's serialized
execution is the basis for the emulator's fence implementation.
