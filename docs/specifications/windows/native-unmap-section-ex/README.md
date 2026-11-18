# Extended section unmap

The installed Windows ARM64 10.0.29708 NTDLL exports
`NtUnmapViewOfSectionEx(HANDLE, PVOID, ULONG)`. The
[native producer](native-unmap.c) made 96 calls and checks in each of
three fresh processes using ARM64, AMD64 compatibility and x86 WoW64 code.
The three processes exited zero with byte-identical
[records](unmap-29708-v1.txt). Each row contains the case, flags, returned
status, previous and current allocation states, an alias or private byte,
and the repeated status after successful unmapping. The
[capture metadata](capture-v1.json) binds the producer, compiled images,
installed native provider and records.

Flags 0 and 1 release the whole ordinary view containing the supplied
address. The surviving alias keeps its bytes and repeating the same call
returns `STATUS_NOT_MAPPED_VIEW`. The transient boost flag affects page
priority in Windows. Guest view state and address translation use the same
release path. Unknown flag bits return `STATUS_INVALID_PARAMETER_3` before
validating the process handle.

With the preserve flag (2), process handle validation precedes a 4096-byte
address alignment requirement. An aligned private or unmapped address
returns `STATUS_NOT_MAPPED_VIEW`. An aligned address in an ordinary view
returns `STATUS_CONFLICTING_ADDRESSES` and the view stays mapped. The
emulated VM currently represents ordinary views. Replacing and restoring
placeholder reservations requires distinct allocation and mapping state.
The recorded native cases cover ordinary views.

The service operates exclusively on the guest-owned address space. Native and
WoW64 dispatch share the existing process-handle, allocation ownership and
view retirement paths. Microsoft documents the corresponding Win32 flags for
[UnmapViewOfFile2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile2).
