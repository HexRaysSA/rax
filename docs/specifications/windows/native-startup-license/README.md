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
