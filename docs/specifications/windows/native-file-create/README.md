# Native NtCreateFile controls

These independent programs call the installed NTDLL directly. They use only
source-defined names, data, attributes, and pointers, inside their current
working directory. They do not call RAX. Each observation is a JSON line.

The captured profile is Windows 10.0.29698.1000 on ARM64. Native ARM64, translated
x64, and WoW64 x86 processes were measured separately. Native System32 NTDLL was
guarded by SHA-256
`e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd`.
That guard identifies the parent native module; it does not establish the child
WoW64 module hash. This is not evidence from a physical x86 kernel.

| Corpus | Calls per process ABI | Observations |
| --- | ---: | --- |
| scalar | 492 | Dispositions, access, options, attributes, allocation, EAs, sharing, real contents and returned grants |
| pointer | 367 | Complete 64 KiB arena changes, sixteen 4 KiB page protections, caller-store aliases and handle ownership |
| masks | 224 | Individual option/attribute bits, zero access and sharing with read-only result grants |
| identity | 24 | FileInternalInformation identity and previously retained readable handles |
| effects | 60 | Independent NtQueryEaFile readback and all eight held share masks |
| existing-ea | 12 | Independent NtSetEaFile seed and replacement/clearing readback |
| mutating-pointer | 1101 | Complete arenas for supersede, absent-file create and overwrite, including late output-copy faults |
| metadata-share | 36 | Metadata-only held handles with both sharing modes, all dispositions and three result access masks |

The eight families contain 2316 calls per ABI, or 6948 native calls in total.

The manifest binds source bytes, image hashes and raw-output hashes to each
corpus. Process-local handles are observations, not constants for RAX to return.
The owning pointer test substitutes independently checked virtual handle
identities and compares every other arena byte and page protection.

## Measured behavior

Native64 checks scalar masks before probing the output handle and the first
four IOSB bytes. Allocation capture uses four-byte alignment on all three
process ABIs. A nonempty EA list is captured before object attributes. Its native
validator initializes IOSB.Information even if later attribute capture fails;
an inconsistent list additionally writes the four-byte status field.

WoW64 captures object headers, QoS, and reachable short name buffers before
kernel validation. NtCreateFile also visits a NULL character buffer at this
stage; the measured NtOpenFile conversion has different behavior. Later kernel
failures store a zero handle. A late caller IOSB fault closes the temporary
acquired handle while preserving preceding stores. Successful overlapping
output/IOSB stores can lose the caller's handle value while retaining the live
file object.

With no EA list, a late IOSB store can fail after the file was created or
truncated. Native64 retains its published handle; WoW64 retires the temporary
handle but retains the file effect. The mutating corpus records 18 such failed
calls for each native64 ABI and 315 for WoW64. These failures cannot be modeled
as unconditional filesystem rollback.

Supersede and overwrite can truncate an existing file while returning a
read-only grant. They preserve the measured NTFS file identity, and existing
readable handles observe the truncated EOF. Sharing failures preserve the
original data. Disposition effects therefore require an authority check in
addition to checking the returned handle's access mask.

Native EA readback uppercases `One` to `ONE`. Creation, supersede and overwrite
apply the supplied list. OPEN and an existing OPEN_IF ignore it. A positive
allocation hint reserves space for creation/overwrite without extending EOF;
an existing OPEN ignores the hint. Negative allocation values still fail.

Attribute-only references do not become data-sharing reservations. The native
metadata-share controls allow data opens, supersede and overwrite while a
metadata-only handle requests no sharing. NT and Win32 paths must use the same
policy; a metadata reference still retains the shared deletion lifetime.
Microsoft also documents that attribute/EA access is unaffected by sharing
flags in the [CreateFileW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

An isolated successful WoW64 allocation-pointer case observed five additional
process handles without causal attribution. The corpus preserves that count;
it does not establish five leaked file objects.

## Reproduction

Use an MSVC-compatible native or cross toolchain selecting ARM64, x64 or x86.
Keep the build inside the RAX checkout. For example, from its root:

```text
cmake -S docs/specifications/windows/native-file-create -B target/native-file-create-controls -A ARM64
cmake --build target/native-file-create-controls --config Release
ctest --test-dir target/native-file-create-controls -C Release --output-on-failure
```

The eight executables print one profile and the table's case count. CTest gives
each program a separate in-tree working directory. Never run these programs in
a directory containing files named `case-00000.dat` and subsequent case names.
The x86 SEH import is `_except_handler3` from `msvcrt.dll`; using `ntdll.dll`
instead fails during image loading and produces no control observations.

The public API contract is Microsoft's
[NtCreateFile reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile).
Pointer priority and copyback effects above are native observations, rather
than guarantees supplied by that reference.

## Qualification status

The implementation passes 33 related owning tests on each of macOS ARM64,
Windows ARM64, and Linux x64. They include 5988 scalar, pointer, and metadata-sharing
corpus cases across all three virtual process ABIs, plus storage, lifetime,
authority, and NT/Win32 interoperability checks. All 1476 scalar cases have
passing RAX replays. The other native families qualify measured invariants;
their presence alone does not imply a case-for-case RAX replay.

| Configuration | Qualification |
| --- | --- |
| macOS ARM64 | 33 related owning tests, 244 C API tests; workspace/all-target check and Clippy |
| Windows ARM64 | 33 related owning tests; workspace/all-target check and native test-image link |
| Windows x64 | Workspace/all-target cross-check |
| Linux x64 | 33 related owning tests; workspace/all-target check and test-image link |
| Native control sources | All eight CMake targets built for ARM64, x64, and x86: 24 images |

Rust 1.95.0 was used throughout. Library Clippy treats warnings as errors;
workspace/all-target Clippy also passes. Linux runtime execution used Docker amd64
translation on ARM64, not physical x86. The Linux-only final descriptor fix leaves
the executed Windows test-image bytes unchanged. Source and image bindings are
recorded in qualification-v1.json.

The qualified Windows library passed the previous NtCreateFile frontier in installed
CMD and reached an explicitly unsupported file-backed SEC_COMMIT section in
NtCreateSection. The diagnostic wrapper returned zero; the emulated process
returned an internal failure. This is not a successful CMD run.

On POSIX, the adapter reserves space without extending EOF and stores DOS
attributes and EAs in descriptor-owned xattrs named
`user.rax.windows.attributes` and `user.rax.windows.ea`. Each starts with
`RAX\x01`; the attribute payload is one little-endian ULONG and the EA payload
is a counted native list. The currently qualified representation covers the
ordinary attributes in the scalar corpus and nonempty ASCII EA names with zero
EA flags. Additional attribute modes and EA encodings return an explicit
unavailable result before modifying an existing file. Windows uses owned native
NtCreateFile arguments and its filesystem's allocation/EA/attribute operations.

Linux metadata traversal can retain O_PATH descriptors, which reject fgetxattr.
Attribute reads then follow the still-owned /proc/self/fd link, preserving the
referenced inode across rename, replacement, and unlink. That metadata path
requires a mounted /proc/self/fd; absence is an explicit unavailable result.
Descriptor-relative directory lookup itself does not depend on /proc.
