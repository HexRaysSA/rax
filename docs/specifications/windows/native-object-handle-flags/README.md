# Native object handle flag query

`NtQueryObject(ObjectHandleFlagInformation = 4)` supplies the two one-byte
`BOOLEAN` fields `Inherit` and `ProtectFromClose` used by installed
`GetHandleInformation`. The emulator reads these flags from its own handle
table. It does not send guest handles or memory addresses to the host kernel.

The independent `native-object-handle-flags.cpp` probe ran as ordinary user
code on Windows kernel **10.0.29704.0**, with ARM64, AMD64 and WoW64 x86
executables. Each retained output has **284 cases**, for **852 observations**.
The probe creates its own event and duplicated process/thread handles and
allocates all scratch memory it protects. Its output contains the case inputs,
returned status, any caller exception, four page protections, and both 64-byte
destination snapshots. It restores handle protection before closing handles.

The corpus establishes these results for the measured kernel:

- Class 4 permits byte-aligned output and an unaligned optional `PULONG`
  `ReturnLength`. The full declared output span and four-byte return destination
  are probed before handle validation. A reached guard is consumed, including a
  read-only guard. Probe failures leave both data snapshots intact.
- Valid queries of fewer than two bytes return `STATUS_INFO_LENGTH_MISMATCH`
  and write `ReturnLength = 2` when provided. Successful queries write exactly
  two BOOLEAN bytes, followed by the optional four-byte length. Alias cases
  establish that store order. The length parameter is a 32-bit `ULONG` on all
  three ABIs.
- A zero-access duplicate is queryable. Real process/thread handles and current
  process/thread pseudo-handles are queryable; pseudo-handles report two zero
  flags. Low two-bit handle tags preserve the underlying handle's flags.
  Invalid, closed and token pseudo-handles return `STATUS_INVALID_HANDLE` after
  caller destination probing and leave `ReturnLength` unchanged.
- For the measured unsupported query classes 5, 6, 7, 8 and `0xffffffff`, the
  WoW64 wrapper rejects the class before touching caller pointers. Native64
  instead checks four-byte output alignment, probes both destinations, and
  validates the handle before returning `STATUS_INVALID_INFO_CLASS`.

The replay test uses the original per-ABI rows and compares statuses, every
snapshot byte, guard visitation, unchanged handle flags, and handle counts.
A second test exercises the built-in DLL export, checks its ABI and shared
service implementation, and verifies that `LastError` remains unchanged.
Registration appends a family after the existing NTDLL families, preserving
their synthetic export positions.

Classes 0–3 (basic information, name, type and all types) remain explicitly
unimplemented. This change does not claim support for those variable object
records or complete Windows process shutdown. Native observations describe the
listed kernel and DLL profile; they are not a claim about every Windows build.

`references/ntobapi.h` is an unmodified, commit-pinned PHNT primary header for
the API declaration, enumeration and two-byte record. Its source identity is in
`references/provenance.json`. Runtime behavior comes from the independent
executable probe, rather than from header comments.

With H handles and P probed guest pages, the handle lookup costs O(log H) and
validation makes P address translations. Query bookkeeping uses O(1) extra space.
Existing memory translation can populate guest pages as a normal access would.
The query creates no buffer sized by ObjectInformationLength.
