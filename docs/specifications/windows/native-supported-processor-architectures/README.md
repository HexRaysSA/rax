# NtQuerySystemInformationEx class 230

The installed ARM64 Windows 10.0.29708.1003 NTDLL was observed issuing class 230
during the Win32 registry witness. Its first two calls used an 8-byte input
holding a zero handle. A zero-length output returned `STATUS_BUFFER_TOO_SMALL`
and required 16 bytes. The second call returned the 16-byte record.

The pinned [PHNT header](../native-wnf-query/primary/phnt-ntexapi.h) names the
class `SystemSupportedProcessorArchitectures2` and describes the machine
and flag bitfields. The native record contains three 4-byte entries followed
by a 4-byte zero terminator. In native order the observed machine/flag pairs
were ARM64/0x0007, x86/0x0012, and x64/0x0002. Querying the current ARM64 process
set bit 3 of its flag field. The host snapshot validates this record structure
at process selection, using both fixed selectors and oppositely poisoned
native output buffers.

Run `native-lengths.py` and `native-order.py` with native ARM64 Python on the
measured Windows build. Each writes `result.json` in its own directory.
`native-lengths-29708.json` contains 48 status, size, and byte observations.
`native-order-29708.json` contains 24 additional observations for output
probing, overlapping input and output, and current-process handle access.
The probes use process-local buffers and handles. The returned-length
sentinel is `0xA5A5A5A5`, and the destination starts filled with byte `0xA5`.

- A missing or zero-length input fails before the destination is touched.
  Nonempty input is 8-byte aligned. A nonempty output is 4-byte aligned.
  The declared destinations are probed before input capture and handle lookup.
- The handle field is exactly 8 bytes. Zero selects the system record. The
  current-process pseudo handle or a current-process handle with query access
  selects the process record. A wrong object type and a denied process handle
  produce distinct status values that preserve the returned-length sentinel.
- Short output receives the required byte count and no record. On success,
  the 16-byte record is written before the optional returned length, including
  when an alias causes that length to overwrite part of the output record.

The installed replay admits the measured ARM64 caller/host profile. Cross-ABI
thunks and queries for other processes are outside this profile. Guest handles
are resolved using the emulated handle table. Process configuration, guest
addresses, and guest selectors never enter the host capture calls.
