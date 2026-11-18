# Native-width WoW64 process memory on build 29708

Native stock x86 CMD on Windows ARM64 10.0.29708.1003 makes one remote
allocation and three remote writes for each of its two suspended x86 children.
The native allocation receives a null base, requests 4568 bytes with
MEM_COMMIT and PAGE_READWRITE, and returns 8192 committed bytes. The writes
transfer 4568, 8, and 4 bytes. All eight calls succeed. The x86 guest uses
both the native-width write leaf and the ordinary x86 NtWriteVirtualMemory
leaf during child setup.

The selected x86 NTDLL image has SHA-256
ac3d1f2f491437a1143c59898b2ec1dd351291c4daaae2a6c506fb7b81372eea.

| Service | Number | Stack bytes | Native-width fields |
| --- | ---: | ---: | --- |
| NtWow64AllocateVirtualMemory64 | 0x1f7 | 28 | Base and size outputs, ZeroBits |
| NtWow64ReadVirtualMemory64 | 0x1f8 | 28 | Remote address, requested and transferred byte counts |
| NtWow64WriteVirtualMemory64 | 0x1f9 | 28 | Remote address, requested and transferred byte counts |
| NtWriteVirtualMemory | 0x3a | 20 | None. Its address and count fields are 32-bit. |

A direct x86 probe requested 4568 bytes at 0x10000f117 with MEM_RESERVE and
MEM_COMMIT. The native allocator rounded the reservation base down to
0x100000000 and rounded the exclusive end up to 0x100011000, for a span of
69632 bytes. Another direct probe wrote and read back eight bytes above
4 GiB with the native-width read and write services. Both byte counts were
eight. A write ending four bytes into an unmapped page returned
STATUS_PARTIAL_COPY and a count of four. A write to an address above the
native user limit returned STATUS_ACCESS_VIOLATION with the count untouched.
The ordinary x86 write reports STATUS_OBJECT_TYPE_MISMATCH for a thread
handle and sets the 32-bit count to zero. The two wide transfer services
report STATUS_INVALID_HANDLE for the same pseudo-handle and set the 64-bit
count to zero. The native-width allocation, read, and write reject the
current-process pseudo-handle with STATUS_INVALID_HANDLE. All three accept a
real current-process handle with the corresponding access right. The ordinary
x86 write accepts its current-process pseudo-handle.

RAX shares reservation collision checks and commitment accounting across both
pointer widths. The native-width services resolve real handles to the caller
or its owned guest children, then check the corresponding process access
right in the guest handle table.
Standard x86 allocation and placement retain their own address limit.
