# Windows filesystem attribute queries

`NtQueryVolumeInformationFile` class 5 (`FileFsAttributeInformation`) uses the
existing native export and WoW64 route. It queries a retained Windows file's
actual owning filesystem without adding guest grants or reopening a normal
file by pathname. The legacy metadata-only fallback verifies file identity.
On Unix hosts, the Windows DriveMap retains its explicit captured NTFS model;
this does not identify APFS, ext4 or another host filesystem as NTFS. Native
Linux and Darwin process personalities are unchanged.

| Object | Attributes | Maximum component | UTF-16LE name bytes |
|---|---|---|---|
| Captured local Windows NTFS | `0x03e72eff` | 255 | `4e00540046005300` |
| Captured Windows pipe filesystem | `0x00000002` | -1 | `4e00500046005300` |
| Captured Parallels shared provider | `0x00000003` | 255 | `500072006c00530046000000` |
| Actual Windows retained file | native provider result | native provider result | native provider result |
| Unix-hosted Windows mapped disk | `0x03e72eff` | 255 | `4e00540046005300` |
| Console or NUL | `STATUS_INVALID_DEVICE_REQUEST` | no output | no output |

These numeric flags are observations, not deductions from filesystem names.
The shared-provider control opens an existing file for metadata only. It does
not read or transmit that file's contents. Event/process handles and invalid
handles retain distinct type-mismatch and invalid-handle results.

The caller record has three 4-byte fields: attributes, signed maximum
component length, and provider-defined filesystem-name byte length. Name bytes
start at offset 12. The user-mode syscall requires at least 16 bytes and 4-byte output
alignment in all three measured ABIs. Length validation precedes pointer and
handle checks. A native 64-bit entry probes only 4 bytes of IOSB Status before
probing the entire supplied output span. WoW64 instead uses private native
IOSB storage and a late caller copy; its null IOSB is rejected before output.

For the 8-byte NTFS name, lengths 16/17/18/19 return
`STATUS_BUFFER_OVERFLOW`, name lengths 4/5/6/7, and Information values
16/17/18/19. Truncation is byte-granular, including half of a UTF-16 code unit.
Length 20 succeeds with Information 20; unused output bytes remain unchanged.
NPFS instead reports the full 8-byte name length on overflow while copying
the same byte-granular prefix. Actual Windows provider records are queried
privately at a bounded length and preserved, rather than inferred from their
name or a single NTFS profile. The NTFS/PrlSF behavior differs from class9's
full required name length. It also differs from MS-FSA's protocol store routine, which uses the 12-byte header minimum and
reports full name length. The captured user-mode boundary owns this syscall
implementation; the two interfaces are not treated as interchangeable.

Publication is observable through aliases and crossing IOSBs:

| Caller | Per-open mode | Publication after output | Late IOSB fault |
|---|---|---|---|
| ARM64/x64 | synchronous | pointer-sized Information, then low 4-byte Status | consumed, original query status returned |
| ARM64/x64 | asynchronous | full pointer-sized Status union, then Information | returned after reached stores |
| WoW64 | either | 4-byte Status, then 4-byte Information | returned after reached stores |

Synchronous native64 publication preserves the upper 4-byte union word.
Asynchronous native64 publication zeros it. WoW64 output aliases use its
actual stores rather than class9's separate wrapper overlap rule. Shared query
work is O(P + N), where P is the number of output pages probed and N the copied
filesystem-name bytes, plus opaque native provider I/O. Private guest-record
storage is O(N), never O(caller length). LastError and the retained file cursor remain unchanged.

Windows host requests use stable aligned private storage and the retained
native handle. Pending completion keeps the original file, IOSB and buffer
alive. `GetOverlappedResult(FALSE)` polls without requiring an added
SYNCHRONIZE grant; an API error does not release a pending original request.
The original IOSB must be terminal before output is read or freed. Class4
uses this same ownership helper while keeping its separate caller contract.
Class5 host scratch starts at min(caller length, 512 bytes) and doubles on
native overflow only while it remains shorter than the caller length, up to
16 MiB. A larger provider name produces an explicit unsupported diagnostic;
no synthetic NTFS answer replaces an unavailable native provider. None of the
captured native requests returned `STATUS_PENDING`, so pending kernel execution
is an ownership design boundary, not an exercised native result.

## Independent controls

| Producer | Views | Queries | Scope |
|---|---|---|---|
| `native-volume-attributes-v2.rs` | ARM64 and x64 | 7,616 | regular/directory, two modes, four verified grants, 34 lengths, seven offsets |
| `native-volume-attributes-v3.cs` | x86 | 3,808 | same matrix through Framework32 caller |
| `native-volume-attributes-faults-v3.cpp` | ARM64, x64, x86, x86 LAA | 12,584 | 11 roles, 22 guard/pointer/alias cases, 13 lengths |
| `native-volume-attributes-shared-v1.cs` | x86 | 1,904 | actual shared filesystem, two modes and four verified grants |

The normal matrix is 2 objects x 2 modes x 4 grants x 34 lengths x 7 offsets
x 3 ABIs = 11,424 queries. The fault matrix is 11 x 22 x 13 x 4 = 12,584.
Native actual grants are independently inspected using the exact 56-byte
ObjectBasicInformation structure after downscoping with DuplicateHandle:
zero, `0x00100000`, `0x00000080`, and mapped generic-read `0x00120089`.
All normal controls record zero skips and zero pending results. Each final
fault view closes all nine owned handles and releases both allocations.

JSON profiles retain individual observations; raw fault logs retain every
memory/protection window. `faults-provenance-v1.json` binds final source,
executable, receipt, stdout and filesystem module-context hashes. Those module
hashes do not attest the loaded child's module set. The kernel is Windows
10.0.29698 ARM64. x64 and x86 are compatibility views, not physical AMD64
kernel evidence. Earlier C# versions failed grant instrumentation before any
class5 calls; Rust V1 failed compilation. Intermediate fault versions retain
their evidence separately and do not supply the final replay corpus.

Pinned Microsoft primary sources and licenses are under `primary/` with exact
commit/blob/hash provenance. The owning references are the
[native query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile),
[attribute structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_fs_attribute_information),
[protocol store routine](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/431745d0-93af-4663-a0dd-1936feaec4c5),
and [completion API](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult).

## Assumption register and bounded scope

| ID | Assumption and dependent result | Basis | Stress test and falsification probe | Status |
|---|---|---|---|---|
| VA1 | retained files need no extra guest grant for class5 | independently verified normal grants | zero/SYNCHRONIZE/READ_ATTRIBUTES, async and shared provider; native access error falsifies | confirmed within captured matrix |
| VA2 | protocol minimum describes syscall minimum | MS-FSA 12-byte store header | native lengths12-15; early length mismatch falsifies | falsified; syscall minimum16 |
| VA3 | class9 full-required-name length applies here | related variable-name service | native lengths16-19; copied lengths4-7 falsify | falsified for NTFS/PrlSF; NPFS reports full name length |
| VA4 | shared publication preserves measured mode/caller behavior | final normal/fault profiles | every status, memory byte, alias and guard must replay | confirmed within captured scope on macOS, Linux and native Windows |
| VA5 | every provider reports copied name length on overflow | initial NTFS/PrlSF measurements | NPFS short buffers; full name length falsifies | falsified; 168 initial replay mismatches drove provider-specific records |

High impact: pending native requests must never outlive private buffers; this
is addressed in the shared class4/class5 ownership helper. Medium impact: the
captured matrix requires an NTFS temporary fixture on Windows; an independent
raw native query binds actual flags and maximum-component fields while all
statuses, names, lengths, guards, aliases and other bytes remain exact. A
different fixture filesystem fails that corpus precondition explicitly.
Medium impact: names exceeding 16 MiB retain an explicit unsupported boundary.
Neither metadata class introduces a public C ABI, SDK, persistence schema,
package option or dependency change. The same Rust implementation is embedded
by existing RAX C API and Assist archive targets; those consumers require
their own validation in addition to library tests.


## Runtime qualification

The current focused and adjacent suites pass 74 tests on native macOS ARM64
and 73 tests on Linux AMD64 translation over the host's Linux kernel substrate,
with zero failures, ignores or skips. Both include all 11,424 normal and
12,584 fault class5 rows across the three guest ABIs, all 1,056 retained class4
rows, real synchronization-only/selected-library opens after remapping and
pathname replacement, and explicit legacy metadata-only identity rejection.
Native Windows ARM64 passes 69 tests with zero failures, ignores or skips,
including the same class5/class4 corpora and actual retained-handle cases.

Strict Clippy compiles both owning library and library-test artifacts on all
three host configurations with zero diagnostics in the changed files. The
broader strict invocation exits 101 for unchanged integration helpers on macOS
(`fixtures`/`temp_file` in the Linux support module), NVMe test imports on
Windows, and the unused PIC `init_slave` helper on Linux. No repository-wide
lint-pass claim is made. Native Windows compilation retains the pre-existing
vendor/vm-memory stdcall warning. Public C API 1.16.0 and private Assist Rust
ABI 1.366 are unchanged. The actual Assist archive and 22 consumers require a
separate pin qualification; they are not inferred from these library results.


The bounded installed ARM64 CMD comparison now passes the former class5
boundary and reaches `NtQueryInformationProcess` class12 at instruction-budget
bound 13,946,112 (64-instruction observation slices). Native
`cmd.exe /d /c dir /b C:\Windows\System32\cmd.exe` exits 0 and writes
`636d642e6578650d0a`; the emulated command stops at the explicit unsupported
class12 request with empty stdout. The observer exits 0 after recording that
failure; it is not a successful guest exit. The same installed libraries,
1 GiB arena, seed 7 and 50,000,000-instruction budget are retained. This is
measured progress toward the full process objective, which remains incomplete.
