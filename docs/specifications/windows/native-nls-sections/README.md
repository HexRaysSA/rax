# Installed NLS sections and guest view lifetime

Explicit Windows native selection captures installed NLS section bytes once.
Only selection-time code calls host NtGetNlsSectionPtr/NtUnmapViewOfSection;
all host mappings close before return. Guest requests use immutable private
records, allocate guest-only views and never forward guest arguments to the
host kernel. The supplied-only profile has no selected NLS section namespace.

Candidates are decimal value names from the fixed system CodePage snapshot,
plus decimal C_*.NLS names enumerated in the fixed native system directory.
Types 12 and 14 use the measured fixed normalization/case table requests.
Every acquired section must have a nonnull address and page-rounded length
between 4,096 and 8,388,608 bytes; copied total is bounded to 67,108,864 bytes.
There are at most 4,096 code-page candidates plus six fixed requests. Missing
host sections are recorded by absence; unexpected NT failures preserve their
NTSTATUS and fail selection. This is a bounded selection snapshot, not an
atomic host-update transaction across registry and files. No host addresses or
callbacks survive in the records.

| SectionType | SectionData | Installed mapping on build29683 |
|---|---|---|
| 11 | Decimal code-page ID | Actual installed code-page section; 437/1252 map C_437.NLS/C_1252.NLS |
| 12 | 1, 2, 5, 6, 13 | NFC, NFD, NFKC, NFKD, IDNA normalization tables |
| 14 | Ignored | l_intl.nls case table |

NtGetNlsSectionPtr has five arguments. Native64 probes the nonnull pointer
output, then nonnull size output, then reads pointer-width ContextData.
WoW64 reads ContextData first, then probes its 4-byte pointer output. A readable
nonnull context returns STATUS_INVALID_PARAMETER_3 before null-output/type
validation. Null pointer output returns STATUS_INVALID_PARAMETER; other types
return STATUS_INVALID_PARAMETER_1. Native SectionSize is optional despite the
PHNT declaration. Unaligned outputs are accepted. Pointer output precedes size
publication, so aliases overwrite its low bytes. Native faults/guards precede
namespace lookup and create no view. WoW64 attempts optional size copy/probing
after a kernel result; size-copy faults consume a guard but preserve the kernel
status. Error size bytes have no defined output in this admitted profile.

Each successful query allocates a distinct 65,536-byte-aligned guest view,
reports page-rounded size, preserves selected bytes/padding, and publishes
MEM_MAPPED/PAGE_READONLY. The common guest virtual-memory manager seals NLS
view policy after initialization. Protection changes, including NOACCESS,
write/copy/execute and GUARD, return STATUS_INVALID_PAGE_PROTECTION; READONLY
remains valid. Repeated READONLY commitment returns STATUS_ALREADY_COMMITTED;
write commitment returns invalid-page-protection. Private release/decommit
return STATUS_UNABLE_TO_DELETE_SECTION. NtProtectVirtualMemory publishes
PAGE_NOACCESS as old protection on that rejected NLS protection request.
Host bytes remain immutable regardless of guest view operations.

NtUnmapViewOfSection releases an owned NLS view containing any interior address.
The current-process pseudo-handle or a typed current-process handle with
PROCESS_VM_OPERATION is admitted. Invalid/wrong-type/denied handles return
itemized NT statuses; another process or an unrelated mapped/image section is
explicitly unsupported. An absent/private address returns STATUS_NOT_MAPPED_VIEW.
Unmap returns commitment and address range; snapshots survive for later views.

| ID | Assumption | Basis | Dependent result | Stress / falsification probe | Status |
|---|---|---|---|---|---|
| N1 | Explicit native selection admits fixed installed NLS metadata and tables | User installed-runtime goal and existing read_files_outside selection gate | Selection-only capture, no guest host calls | Supplied-only rejection; inspect FFI call sites and retained host pointer lifetime | Retained explicit scope; guest forwarding would falsify |
| N2 | Captured NT mapping bytes own the selected table | Actual host NtGetNlsSectionPtr plus independent mapped-file/byte probes | Exact private bytes, rounded size, locale-dependent data | Compare all eight measured tables with actual files and zero padding; concurrent OS replacement | Confirmed on recorded installation; atomic updates unknown |
| N3 | Build29683 ordering owns this admitted NT profile | Original three-ABI native pointer/guard/context/lifetime/protection probes | NT status/capture/copy/lifetime policy | Null SectionSize, misalignment, aliases, crossed page, two guards, repeated/interior unmap | Revised: required-size/aligned-output/WoW size-fault assumptions falsified |
| N4 | The finite system candidate capture covers this installed namespace | Fixed CodePage numeric names, fixed directory names, five normalization forms and case table | Missing candidate returns name-not-found in selected profile | Unregistered installed code-page file, alternate locale, changed kernel section types | Retained bounded profile; future Windows forms/builds unknown |
| N5 | NLS read-only section policy must reach every memory caller | Native NT/Win32 protection, free and commitment results | Shared memory-manager sealing plus NT old-protection result | VM and installed service tests; writable/executable/guard/private-free attempt | Confirmed measured policy; regression recorded before correction |

Snapshot acquisition is O(S + C log C + B) time and O(C+B) space for S directory entries, C candidates
and B copied bytes, excluding native filesystem/kernel costs. Lookup costs
O(log C). Each new view costs O(B + P + log V) time and O(4,096 P) bytes of guest backing for
P pages and V views; immutable table bytes are shared by Arc. Unmap costs the
existing manager's page/state teardown plus O(log V) ownership lookup.

All original source/oracle bytes, primary declarations, notices and regression
captures are identified in sources.json. Counts and final complete library,
C API and owning Assist archive results are recorded in native-runtime.md.
Four retained original NLS programs make 1,596 NLS requests across the three
ABIs; the separate RTL status program makes 12 conversions. The portable
checker validates 126 matrix, 28 pointer, 12 lifetime, 9 protection and 4 RTL
status rows per ABI and agreement of defined table fingerprints. Eight shared
tests and two installed Windows tests separate model, actual file bytes and
actual NTDLL leaf execution. Three observed regressions cover missing service,
view sealing and NT-to-Win32 errors.

Native ARM64 and compatibility x86/x64 execution on one Windows ARM64 kernel
is not physical Intel-kernel proof. Other builds and arbitrary concurrent
host NLS replacement remain unknown.

High-impact remaining work: full native loader/RTL heap/CRT initialization,
wider NT/security/registry/section services and complete application/package
matrix; these block the full process goal. Medium: private WoW64 undefined
error-size bytes and atomic registry/file updates are outside defined fidelity.
Low: sharing one selection snapshot across independent processes is a possible
allocation optimization and is not implemented. Public Rust VmError adds AlreadyCommitted and CannotDeleteSection variants.
No C ABI/layout, dependency,
lock, default, ISA/SMIR/JIT or package target changes are included.
