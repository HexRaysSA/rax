# ProcessImageInformation native observations

The unchanged installed-library hardware-exception fixture now reaches
`NtQueryInformationProcess` class 37 during x86 startup. This observation group
measures the owned control process and its own executable. The runtime query
remains unimplemented. No guest request is forwarded to a host kernel.

`native-image-information-v4.cpp` and `run-v6.py` retain three complete
length/buffer/handle/right/alias matrices: 694 ARM64, 694 x64 and 678 WoW64
calls, or 2,066 matrix calls. Each admitted executable also makes one metadata
query. Twelve profiles per view produce 33 admitted images and three ARM64
loader rejections, giving 2,099 explicit class-37 calls in total. A rejected
image contributes zero query coverage. The local kernel is Windows build
29683 on ARM64; the x64 executable is its compatibility view.

The driver compiles one image per view, copies fresh profile executables, and
changes only declared PE fields or an owned file overlay before first launch.
Profiles cover stack reserve/commit, OS/subsystem versions and GUI subsystem,
checksum, loader flags, dynamic-base policy, code-size/section-code metadata,
relocation stripping with and without dynamic-base retained, and an EOF overlay.
Source/compiler/original-compiled-binary/final-executable SHA-256 values identify
each producer. Executed bytes remain unchanged. Original on-disk PE fields and
file length are decoded independently before launch and compared with mapped
headers and Win32 file size. No compiled image or native library is published.

The published payload has an 80-byte output projection and a 16-byte return
projection. Both carry exact redaction masks for the output pointer field and,
on native64, padding bytes 12 through 15. Redacted bytes are zero, including
intersections with aliased return buffers. Invalid-pointer fallback projections
are masked using the same integer-relative rule. All other scratch bytes are
retained after restoring the control's own protections. The driver independently
reconstructs masks from input roles. Masked positions do not prove byte equality.
TransferAddress is instead checked through bounded RVAs and equality predicates;
no live image base or pointer is emitted.

| Behavior | Native ARM64/x64 | WoW64 |
|---|---|---|
| Accepted record length | Exactly 64 bytes | Exactly 48 bytes |
| Output alignment | Four bytes for nonzero length | Unaligned accepted |
| ReturnLength validation | Early optional probe | Converted copy after output/query |
| Query failure return length | Unchanged | `0xFFFFFFF0`, with copy/allocation exceptions |
| NULL output with valid length | Access violation | Access violation and converted failure length |
| Read-only output guard | Guard visited | Access violation, guard retained |
| Read-only return guard | Guard visited during early probe | Access violation, guard retained |
| Requested handle rights | `0x0400` or `0x1000` admitted | Same |

Native upper-output span rejection precedes the early return probe. WoW64 has
private conversion backing; a non-null length `0xFFFFFFFF` returns no memory
before touching either caller destination. NULL output bypasses that allocation
and still publishes the converted mismatch length. Access mask zero did not
open a native handle in this control; its invalid-handle result is not evidence
about an existing zero-grant handle. Requested access masks also do not expose
every implicitly granted right. These observations do not qualify every
native allocation threshold, debugger state or foreign process.

The mapped 64-bit PE image base differs from its original on-disk preferred
base and matches the loaded module. TransferAddress matches loaded base plus
the entry RVA. The first version read the mapped header as its preferred-base
reference; the independent disk comparison corrects that attribution. All
original captures and failed producers remain in the task evidence archive.

The arrays in each image record have these exact mappings:

| Meaning | `pe` index | `section` index |
|---|---:|---:|
| Machine | 0 | 10 |
| Entry RVA | 1 | Predicates and bounded RVAs; pointer omitted |
| SizeOfImage | 2 | Separate from file-size result |
| Stack reserve | 3 | 1 |
| Stack commit | 4 | 2 |
| Subsystem | 5 | 3 |
| Subsystem minor/major | 6/7 | 4/5 |
| OS major/minor | 8/9 | 6/7 |
| Image characteristics | 10 | 8 |
| DLL characteristics | 11 | 9 |
| Loader flags | 12 | 13 |
| Checksum | 13 | 15 |
| ZeroBits | No source field | 0 |
| ImageContainsCode | Separate code profiles | 11 |
| Raw ImageFlags | Relocation profiles | 12 |
| File size | Independent `file_bytes` | 14 |

All admitted profiles preserve the corresponding PE scalar fields. File size
is EOF length, including the 133-byte overlay, rather than SizeOfImage. Clearing
SizeOfCode, section CNT_CODE flags, or both leaves ImageContainsCode equal to
one in these executable controls. Raw ImageFlags is four for the ordinary
relocatable dynamic-base images and zero for admitted fixed/stripped profiles,
including images that retain dynamic-base while stripping relocations. Actual
base movement alone does not explain this field. Managed/CLR, resource-only,
non-executable, flat-mapped and other private flag states remain unqualified.

ARM64 variants without dynamic-base or with relocations stripped are rejected
by CreateProcess with error 193. `run-v6.py` records only these qualified
architecture/profile/header failures as unavailable. Other launch failures
remain failures. The earlier strict `run-v4.py` failure at the first rejected
variant is preserved. The original v1 compiler failure from a shadowed local
name contributes zero native query coverage.

Six projection checks cover complete producer/result identity, all ordered
matrices and metadata profiles, missing/duplicate/reordered rows, invalid scalar
fields, wrong views, cleanup receipts, redaction tampering, independent PE/EOF
comparison and false loader-availability claims. They do not replace native
execution. The existing Windows 2022/2025 profile workflow runs this observer;
hosted class-37 results are pending. No jobs are added.

Capture time is O(n + p) and retained data O(n + p), for n matrix calls and p
admitted images. Each matrix call owns 16 KiB of scratch; live scratch is O(1).
This group affects Windows-native controls, portable parsers, engineering records
and existing CI only. The Windows API control reports that native Windows is
required on Unix hosts; the parser runs on all three operating systems. No
shipping target, C API, private ABI, permission, install or package changes occur.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| PI1 | Each record belongs to the owned executable view. | PE machine, producer hashes and independently decoded file fields. | Metadata attribution. | Alter view/binary/header identity; the driver rejects mismatch. | Confirmed locally |
| PI2 | Public projections redact only the declared pointer/padding positions. | Independent C++/Python role and alias calculations. | Unredacted-byte copy coverage. | Change a mask or any redacted byte; parser rejects it. | Confirmed locally; masked bytes excluded |
| PI3 | Record widths and query order apply to the captured kernel. | Three complete native matrices and exact baseline lengths. | Native/WoW layout and copy ordering. | Repeat on hosted kernels 20348 and 26100. | Local confirmation; cross-kernel qualification pending |
| PI4 | Tested executable profiles do not establish all PE/CLR/flat-image flags. | Only the declared header mutations were run. | Limits of future metadata derivation. | Observe an independently constructed additional image profile. | Retained boundary |

High impact, blocking full process qualification: runtime class 37, complete
exception entry, older NLS, DPI and current-root shipping validation remain
unfinished. Medium impact: general allocator thresholds and additional image
flag states remain unknown. The current observation group does not resolve them.

Primary definitions are System Informer's
[PROCESSINFOCLASS](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h)
and the pinned `SECTION_IMAGE_INFORMATION` declaration already retained in
`../native-section-open/references/phnt-ntmmapi.h`. Microsoft's
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
describes the general API; the class-37 layout and detailed copy order here
are measured private behavior. The complete local receipt is
`local-29683-v6.json`.
