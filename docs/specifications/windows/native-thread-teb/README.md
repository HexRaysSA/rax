# Native ThreadTebInformation observations

The independent C++ probe resolves NtQueryInformationThread from installed NTDLL
and queries class26 using only its own suspended worker and current thread.
It links no emulator code. All3849 cases per ABI completed with natural exit0
on Windows kernel10.0.29704.0; the six installed DLL hashes held before/after.
The provenance JSON files bind source, toolchain, executable and raw-output
hashes for the978-case boundary,1614-case combined-fault,960-case short-length
and297-case overflow sets.
ARM64 and x64 native64 status/protection behavior agrees. WoW64 is independently
captured, not inferred by truncating native64 pointers.

The primary layout is THREAD_TEB_INFORMATION in the retained PHNT
`../native-process-tls/phnt-ntpsapi.h`: destination pointer, ULONG offset, ULONG
byte count; class26 requires both THREAD_GET_CONTEXT and THREAD_SET_CONTEXT.
Microsoft documents the general API and its optional ReturnLength at
<https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread>.
The private class26 ordering and bounds below are measured for the selected
profile; they are not guarantees for every Windows release.

Native64 requires exactly16 descriptor bytes, four-byte descriptor alignment,
and probes ReturnLength before the length check. Alignment is checked only
when the supplied length is at least4bytes, before ReturnLength; smaller lengths
still probe ReturnLength before failing the descriptor-size check. Its descriptor is read-only
input, despite the API's general in/out annotation. WoW64 reads a12-byte input
descriptor without alignment or supplied-length checks, then forwards a converted
record. Adding its0x2000 native-TEB offset bias must not overflow ULONG;
offsets at or above0xffffe000 fail before caller destination probes, regardless
of byte count or handle. Both paths snapshot the descriptor before payload/ReturnLength stores,
probe the payload before handle validation, require both access bits0x18, then
validate the source range before reporting an already-retired thread.

Native64 permits nonempty spans inside[0,0x1870); WoW64 permits spans inside
[0,0x1030) of the primary32-bit TEB. These are structure extents in bytes, not
page-rounded allocation sizes. Counts0 and crossing/out-of-range spans fail
with STATUS_INVALID_PARAMETER. A valid owned retired object reports
STATUS_THREAD_IS_TERMINATING after rights/range validation. Success copies the
requested bytes and publishes that byte count through optional ReturnLength.
Page guards are visited even with read-only protection. A rejected probe leaves
payload and ReturnLength untouched. Captures include unaligned payload/return
pointers, cross-page accesses, tagged/reduced/recycled/wrong-type handles and
aliases into the descriptor or payload.

Each `case` row contains20 hexadecimal integer fields: index, handle kind,
retired phase, offset, count, descriptor length, descriptor/payload/return modes,
their three byte deltas, status, escaped exception, then before-restoration
protection of the first/second page of each allocation. Five hex byte strings
follow: descriptor-before64, descriptor-after64, payload-after96,
return-after64, source-before64. Windows virtual addresses in descriptors/source
are native observation data. Regression tests relocate only untouched descriptor
pointer bytes and seed the exact captured source into owned guest TEB memory
for successful copies, restoring it before teardown. All remaining bytes,
statuses and guard effects are compared literally.

The original source uses 4096-byte page boundaries in its selected Windows
profile. Reproduction must use the recorded ABI/toolchain and DLL identities;
this is a conformance probe, not an operating-system-version abstraction.

The bounded copy uses O(n) time and O(n) temporary memory for n requested
bytes, with n limited to the selected TEB structure extent. Descriptor, rights
and lifetime checks require O(1) work apart from guest object-map lookup.
