# File-backed SectionImageInformation on Windows ARM64

The installed Windows ARM64 10.0.29708.1003 shell queries class 1 of
`NtQuerySection` while launching installed `cmd.exe` and `where.exe`. Each
observed request supplied a 64-byte output buffer, omitted ReturnLength, and
succeeded before the subsequent `NtCreateUserProcess` call. The shell used
`SEC_IMAGE_NO_EXECUTE` for this query section.

A separate read-only control opened the same installed files and created
whole-file `SEC_IMAGE` and `SEC_IMAGE_NO_EXECUTE` sections. It compared
both `SECTION_QUERY` grants and three buffer sizes per mode and image. The
[normalized records](image-information-29708-arm64.json) retain the
entry RVA and the fixed image fields. The returned native transfer addresses
were image-specific ASLR bases plus their entry RVAs. The records contain
no host addresses.

| Input | Native result | Copy-back |
| --- | --- | --- |
| 63 bytes with or without SECTION_QUERY | STATUS_INFO_LENGTH_MISMATCH | Both buffers preserved |
| 64 or 80 bytes without SECTION_QUERY | STATUS_ACCESS_DENIED | Both buffers preserved |
| 64 or 80 bytes with SECTION_QUERY | STATUS_SUCCESS | Exactly 64 bytes and ReturnLength 64 |

On native Windows the acquisition adapter queries its own previously
opened Section handle with locally owned buffers. The guest Section object
keeps only the checked record, with the transfer address expressed as the
modeled image base plus its entry RVA. Portable PE backing uses the same
64-bit encoding for admitted ordinary executables. Native64 guest queries
read this immutable record after the usual access and buffer checks. The
modeled record remains attached to the Section when the original file
handle closes.

Coverage is for private images of whole executable files using the native64
query layout. Named installed sections, truncated backing, and the WoW64
class 1 conversion require their own metadata qualification.
