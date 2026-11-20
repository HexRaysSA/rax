# Installed startup license values

On Windows ARM64 build 29708, SysWOW64 CMD calls the installed x86
`NtQueryLicenseValue` leaf with an 8-byte `UNICODE_STRING` and five
32-bit arguments. The leaf removes 20 argument bytes on return. The
[stock CMD observation](wow64-cmd-29708-arm64.json) records 11 queries
for six names. Independent fixed queries on the native ARM64 host
returned the same statuses, lengths, types and successful data bytes.

The WoW64 handler reads these names from the immutable host policy catalog.
The AppServerMode and MUI language-count values are DWORDs, and the MUI
language-list values are UTF-16 strings. A capacity query reports the type
and required size. The observed missing WindowsExcludedProcs value clears
the size and leaves the type undisturbed. The guest ABI and captured
host identity select the profile. The captured values describe one host
and are evidence for replay. Each installed run captures its own values.

An AMD64 process on Windows ARM64 build 29708 uses the native64
`NtQueryLicenseValue` contract for `Kernel-OneCore-DeviceFamilyID` and
`TerminalServices-RemoteConnectionManager-AllowAppServerMode`. The
[native64 replay](native64-29708-arm64.json) records byte-identical results
from translated AMD64 and native ARM64 probes for these names at capacities of
0, 3, 4 and 16 bytes, with and without the optional type output. Successful
queries publish one DWORD from the installed host policy snapshot. Short
buffers leave the data unchanged and publish the required size.

AMD64 guest dispatch selects this contract on a measured ARM64 installation
and uses the existing read-only host policy snapshot. The ABI replay checks
the fifth parameter in the AMD64 stack argument area and the returned status,
type, size and adjacent output bytes. A physical AMD64 host remains outside
this measured profile.

The standalone AMD64 comparator produced the same 512 bytes as Windows for
the 16 replay cases. The original CRT-linked probe also matched all 144 bytes
of expected output, empty standard error and exit code 0 with the installed
Windows libraries.

The [native64 producer](probe-native64.rs) measures these two names on native
x64 and ARM64. It checks each exact and lowercase spelling with both
counted-string maximum lengths, with and without the type output, and with
capacities of 0, 3, 4, and 16 bytes. The zero-capacity cases use both a null
and a valid data pointer. Each of the 80 rows records the status, type,
required size, and guarded destination bytes. Run the installed-process
workflow with `measure_startup_queries` to record the kernel version and
hashes of the producer, executable, and NTDLL.
