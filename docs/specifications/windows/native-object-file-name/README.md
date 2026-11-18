# ObjectNameInformation for a local regular file on Windows ARM64

The corpus records `NtQueryObject` class 1 on Windows 10.0.29708 ARM64.
The file is opened by the capture program in its own directory. The full
result agrees with `GetFinalPathNameByHandleW(FILE_NAME_OPENED | VOLUME_NAME_NT)`
on that handle. The captures retain sizes, status codes, and relative pointer
positions. Absolute paths and process addresses are omitted.

The native header occupies 16 bytes. It contains two 16-bit byte counts and a
64-bit pointer to the inline UTF-16 name. Its four padding bytes remain intact.
The length omits the UTF-16 terminator. The maximum length and required
capacity include it. The optional `ReturnLength` is a 32-bit byte count stored
after the record, including when the destinations overlap.

With fewer than 16 bytes the function returns `STATUS_INFO_LENGTH_MISMATCH`.
With space for at most the device prefix but no terminator, it returns
`STATUS_BUFFER_OVERFLOW` without copying a name. A buffer that accommodates
exactly the prefix and terminator receives the prefix, `STATUS_OBJECT_PATH_INVALID`,
and a zero `ReturnLength`. A larger short buffer receives as many UTF-16 units
as fit with a terminator, `STATUS_BUFFER_OVERFLOW`, and the full required size.
A closed handle leaves the destinations intact after their probes.

RAX takes the local NT device identifier from the retained guest volume root.
The rest of the name is relative to that root, including an installed-library
directory prefix where configured. The query resolves only retained regular
files inside their original projection on this measured profile.

The JSON rows contain:

- `ordinary` — open vs. closed, capacity, destination alignment or null,
  presence of `ReturnLength`, prefill byte, status, returned count, copied name bytes.
- `thresholds` — capacity, status, returned count, copied name bytes. The
  distinct four- and eight-byte-aligned controls agreed.
- `aliases` — capacity, return slot displacement, prefill byte, status. Both
  prefill values confirmed that the return count was stored last.

Run each capture with an existing scratch directory passed as its only
argument. The output counts vary with the length of that directory's
resolved name. `native_stdout_sha256` records the original captures.

Reference: [Microsoft GetFinalPathNameByHandleW documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
