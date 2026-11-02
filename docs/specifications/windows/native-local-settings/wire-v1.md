# Complete Local Settings snapshot digest

The native observer and installed Rust consumer independently encode this
stream. The observer emits SHA-256, byte length and aggregate counts. It does
not emit snapshot names, child names or raw value bodies. Separate open-control
rows retain only the fixed logical/physical root and fixed missing names.

All integers are unsigned little-endian. A blob is its byte length as u32,
followed by exactly those bytes. UTF-16 strings use the same blob encoding,
without a terminating NUL. Names, values and times are not normalized.

1. Eight bytes: ASCII RAXLS1, then two zero bytes.
2. For each view, in order 0x100 then 0x200: view u32, native root-open NTSTATUS
   u32. A successful root is followed by one complete node.
3. A node begins with ASCII KEY1, canonical name blob, maximum granted access
   u32 and ACCESS_SYSTEM_SECURITY open NTSTATUS u32.
4. Values: count u32, then each raw-name blob, type u32, raw-data blob. Values
   sort lexicographically by unsigned UTF-16 units, shorter first at a prefix.
5. Children: count u32, then each child-name blob and last-write FILETIME u64
   in native enumeration index order.
6. Complete child nodes follow recursively in raw UTF-16 name order.

The observer enforces the fixed domain across both views: 16,384 nodes, depth
32, 8 MiB canonical paths, 65,536 values and 32 MiB value names/data, 32,768
child entries and 2 MiB child names/FILETIMEs. Individual names and values
retain the existing 16,383-unit and 1 MiB limits. Components use at most 255
UTF-16 units. The complete wire buffer is bounded to 64 MiB.

SHA-256 uses Windows CryptHashCertificate2 with SHA256, flags zero, no reserved
input and a 32-byte output. The native producer and Rust test use separate
acquisition and encoding implementations. A mismatch fails validation; a
concurrently changed profile is not accepted as a match.
