# Native MACHINE hive name

On Windows 10.0.29708.1003 ARM64, a Win32 caller using
`RegOpenKeyExW` with explicit WOW64 view flags requests
`KeyNameInformation` (class 3) from the machine hive handle.
The native name is `\REGISTRY\MACHINE`. Its 17 UTF-16 code units
take 34 bytes, and a four-byte byte count precedes them.

[Independent native controls](observed-29708.json) used three view choices,
query-value access and `READ_CONTROL`, and nine buffer lengths. Every
admitted query reports a 38-byte required size. Lengths below four bytes
return `STATUS_BUFFER_TOO_SMALL` without touching the output. Lengths
from four through 37 bytes copy the available byte prefix and report
`STATUS_BUFFER_OVERFLOW`. A complete record leaves any extra tail intact.

Installed selection already reads the canonical name of the machine hive.
Its retained name supplies this record through the existing `NtQueryKey`
probe, handle validation, and copy-out path. The selected metadata for
other keys and classes continues through their existing record path.
