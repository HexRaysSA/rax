# Windows synchronous file services

This is the admitted RAX file-service profile, not equivalence with an arbitrary
Windows kernel or filesystem. The feature-group baseline is
`4312bb48ec169c48c67ea8ab55bbacda702e5e93`. Primary Microsoft contracts,
immutable repository revisions, retrieval dates, SHA-256 hashes, and licenses
are retained in [the reference manifest](../../specifications/windows/services/file/sources.json).
Native Windows execution-oracle results are **unknown**.

## Surface and ownership

`src/user/windows/dll/files/` owns synchronous file exports. `open.rs` handles
admission, creation, and sharing; `io.rs` handles transfers, position, size,
flush, and final closure; `paths.rs` handles file deletion. `fs.rs` owns path
translation, stable host identity, and shared deletion lifetime. The shared
object table and the separately implemented handle API retain per-handle
grants, duplication, protection, and reference counts. Registration and
process-exit cleanup are outside the file module.

| Exports | Admitted contract | Primary reference |
|---|---|---|
| `CreateFileW/A` | Five creation dispositions, scalar pathnames, local drive mapping, access/share admission, optional inheritable handle | [CreateFileW](../../specifications/windows/services/file/createfilew.md), [CreateFileA](../../specifications/windows/services/file/createfilea.md) |
| `ReadFile`, `WriteFile` | Synchronous regular files, inherited console streams, NUL; current shared file cursor; checked transfer count | [ReadFile](../../specifications/windows/services/file/readfile.md), [WriteFile](../../specifications/windows/services/file/writefile.md) |
| `GetFileSizeEx` | Signed 64-bit representable regular-file length, including metadata-only handles | [GetFileSizeEx](../../specifications/windows/services/file/getfilesizeex.md) |
| `SetFilePointerEx` | BEGIN/CURRENT/END; optional checked 8-byte output; seek alone does not extend | [SetFilePointerEx](../../specifications/windows/services/file/setfilepointerex.md) |
| `SetEndOfFile` | Set regular-file length to current cursor with write-data grant | [SetEndOfFile](../../specifications/windows/services/file/setendoffile.md) |
| `FlushFileBuffers` | Host `sync_all` for a regular file with write-data grant; console-output failure | [FlushFileBuffers](../../specifications/windows/services/file/flushfilebuffers.md) |
| `GetFileType` | Disk, character, and existing pipe-object classification; invalid-handle error | [GetFileType](../../specifications/windows/services/file/getfiletype.md) |
| `CloseHandle` | Handle protection/validity; final object destruction and deferred-delete reporting | [CloseHandle](../../specifications/windows/services/file/closehandle.md) |
| `DeleteFileW/A` | Files only; delete sharing; pending-open exclusion; symlink itself rather than target | [DeleteFileW](../../specifications/windows/services/file/deletefilew.md), [DeleteFileA](../../specifications/windows/services/file/deletefilea.md) |

All exports use existing ABI marshalling for x86 `stdcall`, Windows x64, and
Windows ARM64. Pointer arguments and return handles are 32 bits on x86 and
64 bits on the other architectures. `SetFilePointerEx` declares its distance
as `I64`, consuming two x86 stack slots; its output remains 8 bytes on every
guest ABI. No decoder, instruction executor, SMIR operation, native lowerer,
JIT admission rule, VM backend, device, static-analysis interface, or C ABI is
changed. The affected planes are HLE CPU-ABI argument extraction, checked
guest memory, host filesystem effects, objects, tests, and documentation.

## Dispositions and access

| Disposition | Existing regular file | Missing file |
|---|---|---|
| `CREATE_NEW` (1) | `ERROR_FILE_EXISTS`; contents unchanged | Atomic host `create_new` |
| `CREATE_ALWAYS` (2) | Truncate after sharing/identity checks; `ERROR_ALREADY_EXISTS` on success | Create; last error zero on success |
| `OPEN_EXISTING` (3) | Open without truncation | `ERROR_FILE_NOT_FOUND`, or `ERROR_PATH_NOT_FOUND` for missing parent |
| `OPEN_ALWAYS` (4) | Open; `ERROR_ALREADY_EXISTS` on success | Create; last error zero on success |
| `TRUNCATE_EXISTING` (5) | Requires requested `GENERIC_WRITE`; truncate after checks | Missing-file/path error |

Supported requested rights are `GENERIC_READ`, `GENERIC_WRITE`, read/write/
append data, read/write attributes, `DELETE`, `READ_CONTROL`, and `SYNCHRONIZE`.
Generic rights expand into the corresponding standard and specific grants,
with generic bits retained for compatibility with the object-table format:

```text
FILE_GENERIC_READ  = 0x00020000 | 0x00100000 | 0x80 | 0x08 | 0x01
                   = 0x00120089
FILE_GENERIC_WRITE = 0x00020000 | 0x00100000 | 0x100 | 0x10 | 0x04 | 0x02
                   = 0x00120116
```

These mappings follow [File Security and Access Rights](../../specifications/windows/services/file/file-security-and-access-rights.md)
and [File Access Rights Constants](../../specifications/windows/services/file/file-access-rights-constants.md).
Explicit requests for execute, extended-attribute, ACL-changing,
maximum-allowed, or system-security rights are unsupported. No guest token,
DACL, SACL, privilege elevation, or backup-security bypass is synthesized.
Host filesystem permissions govern the backing operation. A host read-only
file is rejected for writes/deletion; a read-only parent is rejected before a
delete request that can be detected as inadmissible.

Every transfer, seek, truncation, and flush checks the handle's own grant, not
the original file object's access mask. A reduced duplicate cannot inherit
the source handle's write permission. Append-only handles and reduced
append-only duplicates cannot overwrite file data, truncate, or flush.
Original sharing rights remain associated with the open file object even if
its original handle is closed and only reduced duplicates remain.

Independent opens are admitted only if both conditions hold:

```text
new requested read/write/delete access  ⊆ existing share modes
existing read/write/delete access      ⊆ new share modes
```

Read/write attribute-only access does not become data access for sharing.
An existing delete-on-close request additionally requires new delete sharing.
Duplicate handles share one object and cursor; independent opens share the
deletion lifetime but have separate host descriptors and cursors. Host Unix
device/inode identity identifies hard-link aliases and symlink targets.
Sharing is process-local, not a lock held against external host processes or
other independently emulated processes.

## Memory, transfer, and arithmetic contract

RAX's scheduler runs guest HLE on one host thread. Arguments, pathnames,
security attributes, last-error storage, transfer-count outputs, and complete
buffers are checked before a host effect. Protection faults propagate through
the existing `MemFault`/guest-exception path rather than being converted into
fabricated Win32 success. The 4-byte synchronous byte-count output is mandatory
in this profile and is zeroed before work/error checking. A zero-length buffer
is not dereferenced. Unsupported overlapped requests do not perform host I/O.

The maximum transfer is `16 × 2^20 = 16,777,216` bytes. Larger requests are
explicitly unsupported. Buffer allocation uses `try_reserve_exact`; allocation
failure returns `ERROR_NOT_ENOUGH_MEMORY`. A regular-file read continues until
the requested count or EOF, retrying interrupted host reads. A successful
synchronous EOF returns TRUE with zero bytes, as specified by the dedicated
[EOF reference](../../specifications/windows/services/file/testing-for-the-end-of-a-file.md).
The broader ReadFile EOF paragraph is not applied as an asynchronous
`ERROR_HANDLE_EOF` rule to this synchronous path.

File offsets and sizes are restricted to `0 ..= 2^63 − 1` bytes. BEGIN treats
the raw 64-bit distance as unsigned; CURRENT/END sign-extend `i64` into `i128`
before adding the unsigned base. Negative targets return `ERROR_NEGATIVE_SEEK`;
targets above the admitted range return `ERROR_INVALID_PARAMETER`, with cursor
unchanged. A write beyond EOF uses the host's zero-filled hole behavior. Tests
do not infer zero-filled bytes for extension by `SetEndOfFile`, whose new-byte
contents are not established by that API's reference.

Console services route inherited input/output/error streams to host standard
streams, check stream direction and per-handle grants, and report character
type. Host input can block; native console modes, line editing, echo, control
events, code-page conversion, and asynchronous console semantics are not
implemented. NUL reads succeed with zero bytes; writes discard permitted data
and report its count. NUL flushing is explicitly unsupported. Pipe type can
be reported for an existing pipe object, but pipe I/O is unsupported.

Successful guest-output preflight does not make host I/O transactional. A host
write/read failure can have partial backing-file or cursor effects and returns
failure without claiming rollback. Object/handle allocation can also fail
after a host creation/truncation; no multi-system transaction is claimed.

## Paths and deletion lifetime

`W` pathnames accept valid UTF-16 scalar strings, bounded to 32,767 units
excluding the terminator; unpaired surrogates are unsupported. `A` pathnames
accept ASCII only; non-ASCII ANSI conversion is unsupported, not lossy UTF-8.
An unterminated bounded scan returns `ERROR_FILENAME_EXCED_RANGE`, or an
earlier checked-memory fault. No silently shortened host pathname is used.
Drive-relative/rooted paths reuse the existing Windows normalization; host
`.`, `..` components are resolved lexically before host-to-Windows drive
selection, without filesystem canonicalization or symlink traversal.

ASCII case-insensitive lookup is tested. The existing Unicode-lowercase host
fallback is not established as Windows ordinal/upcase-table equivalence.
UNC/device namespaces, alternate data streams, reparse-point-open requests,
and verbatim dot components are unsupported. Invalid pathname characters and
reserved DOS device components are rejected; reserved COM/LPT superscript
digits ¹, ², and ³ follow [Naming a File](../../specifications/windows/services/file/naming-a-file.md).
Only NUL can be newly opened as a DOS character device. Directories admit only
`OPEN_EXISTING` plus `FILE_FLAG_BACKUP_SEMANTICS`, without deletion; data I/O
on directory handles fails. No directory creation/removal, attribute mutation,
rename, or additional path API is advertised by this group.

The admitted flags are zero, `FILE_ATTRIBUTE_NORMAL`,
`FILE_FLAG_BACKUP_SEMANTICS`, and `FILE_FLAG_DELETE_ON_CLOSE`. Every other
flag/attribute, nonzero template, nonzero custom security descriptor, and
nonzero OVERLAPPED pointer is unsupported. `SECURITY_ATTRIBUTES` otherwise
requires the correct 12-byte x86 or 24-byte x64/ARM64 layout and preserves
`bInheritHandle`.

`FILE_FLAG_DELETE_ON_CLOSE` records the canonical target pathname and stable
identity; later opens remain possible only with compatible delete sharing.
`DeleteFile` with live compatible handles records deletion and excludes new
opens, including symlink aliases to that identity. Deletion occurs after the
last independent file object and duplicate/internal reference is released.
Deleting a symlink through `DeleteFile` removes the link; opening it normally
with delete-on-close affects its target, as the primary contracts specify.

Final close rechecks device/inode identity before unlink. A missing, renamed,
or replaced recorded pathname fails without deleting the replacement. This
is a fail-closed host-mutation profile, not native Windows rename/delete
equivalence. Metadata-only handles similarly reject replacement rather than
reporting a different file's size. Deferred deletion is explicitly unsupported
on non-Unix hosts lacking the admitted stable identity implementation.

The check and unlink are separate host operations: concurrent host replacement
between them is **not** prevented. This is not a sandbox or a race-free Windows
namespace transaction. Explicit final `CloseHandle` reports deletion failure
after closing the guest handle. Destructor cleanup emits a tracing diagnostic;
process-exit cleanup has no caller to receive a Win32 error. The first deletion
error is preserved and no retry/rollback claim is made.

## Algorithms and complexity

For `F` live file objects, sharing/deletion admission scans `O(F)` objects.
For a pathname of `P` code units, scanning/normalization uses `O(P)` time and
space; case fallback additionally scans each visited host directory, with
time proportional to the sum of directory entry name lengths. A transfer of
`B` bytes uses `O(B)` copy/I/O time and `O(B)` bounded scratch memory. Deferred
finalization visits `K` recorded unlink paths in `O(K)` host operations, stopping
at its first error. Cursor arithmetic uses fixed-width `i128` intermediates.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| F1 | Guest protection/object state is unchanged during one synchronous HLE call | Existing single-host-thread scheduler | Output preflight followed by copy; stable object lookup | Invalid/read-only buffer, count output, last-error slot | File tests must fault before host creation, truncation, deletion, cursor movement, or handle closure | confirmed within scheduler; external concurrent embedder excluded |
| F2 | Unix device/inode identity remains stable for an open file | Host metadata identity, independent of path spelling | Hard-link sharing and replacement detection | Hard-link alias, target symlink, rename/replacement | Owned tests must reject alias conflicts and preserve replacement contents | retained; inode reuse/concurrent external mutation not a transaction |
| F3 | One mapped host principal backs the admitted access profile | No guest token/ACL implementation | Host permissions plus handle-grant checks | Read-only file/parent and reduced duplicate | Requests must fail before forbidden write/truncation; native ACL differential behavior would disprove general equivalence | retained, not native ACL equivalence |
| F4 | ASCII is the admitted ANSI pathname subset | ACP conversion has no independent native oracle | `A` pathname admission | Byte `0xE9`; unterminated bounded input | Must return explicit unsupported/length failure, not create a decoded substitute pathname | confirmed by explicit checks; broader ACP behavior unknown |
| F5 | Host file offsets are admitted only through signed 64-bit range | Portable host file-offset profile | Seek/size arithmetic | `u64::MAX`, CURRENT −1, END overflow | Cursor must remain unchanged on checked range rejection | confirmed by checked `i128` bounds; native larger offsets unknown |
| F6 | Filesystem namespace is not externally mutated during admitted successful deletion | Stable pathname requirement, separate host metadata/unlink operations | Successful final-close unlink | Rename, replace, hard link, unlink race | Deterministic rename/replacement must fail closed; concurrent replacement between check and unlink falsifies transactionality | retained; high-impact external race documented |
| F7 | Windows Unicode case-table and native console behavior are not inferred from host behavior | No Windows execution oracle or retained upcase-table implementation | Scope limits for non-ASCII casing and console modes | Confusable Unicode names, console line editing/code pages | Native Windows differential tests would establish or refute equivalence | retained; exact behavior unknown |

## Validation and bounded scope

`files/tests.rs` contains eleven semantic tests, each exercising x86, x64, and
ARM64 argument layouts. Unix-specific deletion/identity tests are target-gated.
They use uniquely created temporary directories and files, not shared host
paths. Coverage includes every creation disposition; success last errors;
write/read/EOF; seek holes, signed limits, and optional-output preflight;
truncation and flush; both sharing directions; metadata-only opens; reduced
grants and protected handles; duplicate versus independent cursors; append;
NUL; zero-length console direction/grants; deferred deletion, symlink behavior,
hard links, rename/replacement detection; process destruction; malformed
security attributes; and invalid guest buffers/count/last-error storage.
`fs.rs` adds lexical drive-selection and superscript-device recognition checks.

Execution evidence belongs to the parent-coordinated combined-tree build and
test record, not an isolated file-group build. The compiled freestanding service
fixture and ExitProcess cleanup integration are parent-owned. Exact counts,
ignored tests, and host/feature selection must be read from that execution
record; source presence alone is not evidence of a passing runtime test.

| Impact | Item | Evidence/boundary | Blocks admitted profile? |
|---|---|---|---|
| High | External host check/unlink race and rename equivalence | Separate `symlink_metadata`/identity check/`remove_file` operations | No; excluded external-mutation transaction semantics |
| High | Cross-process shares and Windows ACLs | Object table is one emulated process; host principal backs permissions | No; explicitly not advertised |
| Medium | Unicode case tables, ANSI conversion, native console modes | Host lowercase fallback; non-ASCII A rejected; direct host streams | No; exact equivalence unknown and bounded |
| Medium | Blocking host I/O and partial host effects | Synchronous standard-file/stream operations | No; no asynchronous cancellation or rollback claimed |
| Medium | Non-Unix stable identity/deferred deletion | Canonical-path fallback lacks admitted inode identity | No; deferred mode explicitly unsupported |
| Low | Directory/attribute/rename APIs | Not registered by this semantic group | No; optional scope not expanded |

No native Windows oracle, external-host race freedom, arbitrary filesystem
semantics, guest CRT coverage, or complete Win32 file API is claimed.
