# Selected bootstrap contracts and bounds

Observation date:2026-10-11; selected Windows11 ARM64 build10.0.29683.1000.

The pinned PHNT ntrtl.h at revision53fbbdc5b5d2b08761db1c7b26bfa8c820924356 declares LdrInitializeThunk(CONTEXT*,void*) and RtlUserThreadStart(startRoutine,void*) at lines10478..10489. Local ../native-process-parameters/phnt-ntrtl.h and phnt-LICENSE preserve the primary source/license identities. The second argument's meaning is established by the native ARM64 controlled-child entry capture; the declaration alone does not name it as an NTDLL base.

Primary references:

- https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntrtl.h
- https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext : architecture-specific CONTEXT and suspended-thread observation.
- https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170 : RCX/RDX integer arguments and caller-provided home space.
- https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170 : callable x64 entry stack includes a return address, making its alignment differ by8 bytes from the caller's16-byte-aligned SP. Applying this to the pure on-disk RtlUserThreadStart export is an inference; physical x64 kernel observation is unknown.
- https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent : exit-event acknowledgement closes debug-event process/thread handles; image/DLL file handles must be closed explicitly. Draining the exit event allows the original child process handle to signal.

Selected installed ARM64 loader entry preserves the CONTEXT address across its loader call, then invokes NtContinue with TRUE. Selected x86 loader entry consumes its two stack arguments and similarly invokes NtContinue with TRUE. Selected x86 RtlUserThreadStart writes EAX/EBX to its caller-stack argument positions. selected-entry-contracts.json retains only bounded entry bytes, their RVAs and exact private DLL hashes. Complete DLLs, PDBs, symbol lists and disassembly are excluded.

Scratch arithmetic, in bytes: let S be saved application SP and C=floor_align(S-CONTEXT_size,CONTEXT_alignment). Let F=floor_align(C-64,16); entrySP=F for x86/ARM64, F-8 for x64. Caller scratch below C is64..76 bytes on x86,72 on x64,64 on ARM64, all fitting the fixed80-byte zero buffer. Complete probed extent is CONTEXT_size+C-entrySP:780..792 on x86 (CONTEXT716/alignment4),1304 on x64 (1232/alignment16),976 on ARM64 (912/alignment16). x64 saved S is initialSP-8; its callable loader entrySP is8 modulo16. ARM64 loader SP is0 modulo16. All subtraction/addition and host-size conversions are checked before any context/frame or CPU publication.

Production resolves two exports once from the selected native executable module and caches them only after both validations succeed. Context/frame placement writes bounded bytes and allocates no VM scratch: O(1) time and extra space for the fixed ABI sizes. First-time entry resolution additionally uses the existing module/export lookup and bounded-forwarder validation; this group introduces no export parser. The full-stack accessibility probe traverses a bounded number of pages. The pending alertable NtContinue service must not be implemented by dropping pending APCs or reporting fabricated completion.
