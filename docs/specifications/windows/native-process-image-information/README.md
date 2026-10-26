# ProcessImageInformation native observations

The installed-library hardware-exception fixture previously stopped at
`NtQueryInformationProcess` class 37 during x86 startup. This observation group
measures the owned control process and its own executable. The runtime now
answers the qualified ordinary-executable query from an immutable loader
snapshot. No guest request is forwarded to a host kernel.

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
hosted class-37 results are retained below. No jobs are added.

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

High impact, blocking full process qualification: complete exception entry,
older NLS, DPI and current-root shipping validation remain unfinished. Medium impact: general allocator thresholds and additional image
flag states remain unknown. The current observation group does not resolve them.

Primary definitions are System Informer's
[PROCESSINFOCLASS](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h)
and the pinned `SECTION_IMAGE_INFORMATION` declaration already retained in
`../native-section-open/references/phnt-ntmmapi.h`. Microsoft's
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
describes the general API; the class-37 layout and detailed copy order here
are measured private behavior. The complete local receipt is
`local-29683-v6.json`.


## Pointer-write and granted-right follow-up

`native-image-information-v7.cpp` and `run-v9.py` retain the earlier controls
and add an output with exactly eight writable bytes before a read-only page.
The new capture contains 2,108 matrix calls plus 33 metadata calls (2,141
explicit class-37 calls). The same three ARM64 loader rejections contribute
zero query coverage. The original v4/v6 source, driver and receipt remain
unchanged. All 2,066 prior input/status/guard observations agree with the new
capture; the additional boundary contributes 42 matrix calls across three views.

Each row adds three address-free bit predicates for the selected pointer-prefix
scratch bytes: `pointer_valid_mask` marks reference-entry bytes different from
fill byte `0xA5`; `pointer_changed_mask` marks scratch bytes different from that
fill; `pointer_match_mask` marks bytes equal to the reference entry. No pointer
byte values are emitted. A native reference byte equal to fill remains ambiguous
and is excluded through the validity mask. An aliased ReturnLength can overwrite
pointer bytes; matching predicates describe the final bytes rather than proving
the provenance of such an overwrite.

On the ARM64 kernel, both native64 executable views write the eight-byte entry
pointer before faulting at the new boundary. WoW64 leaves the pointer unchanged
when its full converted record cannot be written. The older hosted v6 controls
also expose a native-copy difference: x64 kernels 20348/26100 preserve a
read-only output guard, while the local ARM64 kernel consumes it. At the
60-writable-byte boundary, the ARM64 kernel preserves completed scalar fields
through byte 55 and the native x64 kernels through byte 47. Masked padding is
excluded from that comparison. These are captured kernel differences, including for
the local x64 compatibility view. A future model must select by the captured
kernel identity, not caller ISA, build-host macros or a spoofed guest version.
The hosted follow-up confirms the x64 kernels leave the first eight-byte
prefix untouched at the new boundary, whereas the ARM64 kernel copies it.

Real owned-process rights rows now query `ObjectBasicInformation` and publish
its granted-access scalar. Other rows publish JSON null for that unmeasured
field. Requested `0x0400` yields grant `0x1400`; requested `0x1000` yields
`0x1000`. The grant probe uses the independently measured exact 56-byte request.
The first extended attempt stopped with an incomplete matrix after using a
larger request; that failed input and partial receipt are preserved separately.
The completed follow-up adds 18 ObjectBasicInformation calls, independent of
the class-37 call counts above.

Four new projection checks cover producer/result identities, all expanded
matrices, unchanged prior observations, pointer predicates, measured grants,
and rejection of malformed bit masks or false grant measurements. They run
alongside the original six checks in the same existing Windows workflow jobs.
All completed native follow-up outputs and transfers are archived and removed;
compatible build caches are retained for the pending runtime and exception work.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| PP1 | Address-free byte predicates can qualify writes only where reference bytes differ from fill. | Three explicit per-byte bit masks plus unchanged scratch projections. | Partial pointer-copy evidence. | Force a reference byte equal to fill or overlap ReturnLength; retain the validity/alias qualification. | Confirmed for captured local views |
| PP2 | The granted mask is distinct from the requested mask. | Owned-handle ObjectBasicInformation scalar and earlier native grant controls. | Query-right attribution. | Tamper a nullable grant, query a different right or compare another kernel. | Confirmed locally; hosted follow-up pending |

Microsoft documents the automatic limited-query grant in
[Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
The detailed copy predicates are native observations. The extended local receipt
is `local-29683-v9.json`; the bounded runtime contract follows.


## Runtime image information

`process/image_information.rs` captures the original admitted PE fields and EOF
size after `load_exe` chooses the actual guest entry. `Proc` owns this immutable
snapshot. Querying class 37 never rereads mapped guest headers, copies a host
process record, consumes the PRNG, or changes process DEP policy. Header
rewrites by guest code cannot alter a later image-information result.

The encoder emits the exact native64 64-byte or WoW64 48-byte little-endian
record. It preserves stack sizes, subsystem and OS versions, image/DLL
characteristics, machine, loader flags, checksum and original EOF length.
TransferAddress is the loader-selected guest entry. ZeroBits is zero;
ImageContainsCode is one for the qualified executable profiles. Native padding
bytes 12..16 are initialized to zero but excluded from native-byte equivalence.
The dynamic image flag is four when dynamic-base is set and relocations are not
marked stripped, otherwise zero; actual relocation movement does not select it.

`run-relocation-directory-v1.py` qualifies directory presence separately from
these two flags. It makes three baseline self queries and ten native64 queries
of suspended, task-owned children. Two ARM64 variants are rejected with error
193 and contribute zero queries. Removing the relocation directory alone leaves
the flag at four in all three admitted executable views. Setting stripped while
retaining the directory clears it in the admitted x64/x86 views. The original
observer source is reused unchanged. Child initialization is not resumed or
claimed as successful. `local-relocation-directory-29683-v1.json` retains all 15
producer/result records, source/compiler/binary hashes, original PE fields and
directory values; no live TransferAddress or native padding is published.
The first private self-query attempt failed at its first changed child; its
partial receipt and executed inputs remain in task evidence without added query
coverage. The suspended-child capture resolves that startup-dependent method.
The CREATE_SUSPENDED definition is retained in
`../native-console-owner/microsoft-process-creation-flags.html`; PE field
definitions are retained in `../microsoft-docs/pe-format.md`.

| Query plane | Record bytes | Output preflight/copy group | Read-only output guard |
|---|---:|---:|---|
| Captured 10.0.29683 ARM64 kernel, either native64 view | 64 | 8 bytes | Visited |
| Captured 10.0.20348 or 10.0.26100 x64 kernel | 64 | 16 bytes | Preserved |
| WoW64 on those captured kernels | 48 | Full 48 bytes | Preserved |
| Built-in DLL model, ARM64/x64 guest | 64 | Model policy: 8/16 bytes | Model policy: visited/preserved |

Installed-library mode selects using the captured kernel machine and version,
independently of guest ISA, build-host macros and editable `cfg.version`.
Unqualified installed identities fail explicitly. Built-in mode has a separate
modeled kernel policy; it supplies no native installation evidence. Native
length/alignment/upper-user-span and early ReturnLength checks remain in the
shared entry. WoW64 bypasses that entry preflight, uses private converted backing,
accepts unaligned output, and publishes `0xFFFFFFF0` on ordinary query failures.
Its minimum temporary charge is `round_up(length + 16 bytes, 4096 bytes)` against
the existing guest budget, calculated in u64 without proportional host allocation.
NULL output bypasses this charge. This is guest resource policy; the general
native allocator threshold remains unknown.

Typed current-process handles need granted `PROCESS_QUERY_LIMITED_INFORMATION`
(0x1000); requested 0x400 in the native observations acquired 0x1400. Explicit
zero-grant and 0x400-only synthetic handles are denied. Other-process image state,
managed/CLR, flat, DLL, non-GUI/CUI, entry-less and non-executable-section profiles
remain explicit unsupported query states; unrelated spawn/loader behavior is
preserved. An EOF exceeding the record's ULONG is also rejected explicitly.

The hosted v9 receipts come from [run 40246722617](https://github.com/HexRaysSA/rax/actions/runs/40246722617),
jobs [121329729509](https://github.com/HexRaysSA/rax/actions/runs/40246722617/job/121329729509)
and [121329729671](https://github.com/HexRaysSA/rax/actions/runs/40246722617/job/121329729671).
Raw logs remain in task evidence; the retained scalar records preserve all
parsed native JSON values without log transport timestamp prefixes. Their identities and LF/CRLF source hashes are
validated by `test_model_profiles.py`.
The receipts retain two complete 1,400-row matrices, plus 24 metadata
queries per kernel. Together with the local 2,108 rows and 33 metadata queries,
the runtime replay checks 4,908 query cases and 81 original metadata profiles.
Ten additional suspended-child profiles check the metadata encoder independently
of relocation-directory presence. Every case compares status, guard state,
unaltered projection bytes, ReturnLength bytes, validity-qualified pointer
predicates, PC, SP and frame preservation. Pointer predicate checks exclude
bytes overlapped by ReturnLength and native reference bytes equal to fill 0xA5;
masked padding is never claimed as byte-equal. Roughly 2.64 MB of hosted scalar
receipts supplies the independent x64-kernel copy/guard evidence and contains no
native binary. Pure projection tests validate producer identities and tampering.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| IM1 | Original ordinary-executable metadata plus final loader entry determines this bounded record. | 81 original profiles and ten suspended-child metadata queries. | Immutable snapshot and encoder. | Rewrite guest headers, change scalar/EOF/relocation fields; any captured field mismatch falsifies the rule. | Qualified captured profiles; additional image states explicit unsupported |
| IM2 | Captured kernel identity selects native copy groups and guards. | Seven executable views over three kernels and exact pointer predicates. | Partial native copy and WoW policy. | Eight/60 writable bytes, RO guards, spoofed guest version; any status/projection/predicate/guard mismatch falsifies the profile. | Captured identities qualified; other installed identities explicit unsupported |
| IM3 | Minimum converted backing can be charged against guest resources. | Length expansion and observed UINT_MAX allocation failure. | Bounded resource handling. | NULL bypass and huge non-NULL input; host allocation proportional to guest length would falsify the implementation contract. | Retained guest policy; native allocator threshold unknown |

Snapshot capture costs O(s) for s section headers and retains O(1) metadata.
Encoding, bounded caller copying and query resource accounting use O(1) time and
space. Replay is O(n + p) for n query rows and p metadata profiles. No public
Rust/C ABI, private Assist ABI, dependency, permission or installed-library search
policy changes. All hosts compile the Windows personality; native Windows leaf
checks execute installed NtQueryInformationProcess in the supported native and
WoW64 views. High-impact remaining full-process gaps listed above still block
the overall goal. Medium-impact additional image flags and allocator thresholds
remain outside this bounded query qualification.


The current combined-tree qualification has 23 process-query tests on macOS and
Linux and 27 on Windows, including the installed native/WoW64 image-information
leaf. Full library runs pass 8,415 tests on macOS and 8,408 on Linux, each with
two existing ignored microkernel validation tests and no failures. Windows has
7,900 passes, one failure and the same two ignores. The unchanged hardware-fault
fixture advances past class 37 and stops at unsupported NtSetInformationProcess
class 63 during x86 execution. The cause of reaching that later path still
requires tracing; complete exception/startup behavior remains unqualified.
These full runs include the separate uncommitted exception-entry/context draft,
whose exact source hashes are retained in task evidence. They qualify that
combined tree rather than a clean committed-pin artifact. All 191 C API tests pass on each host. These package checks are recorded
separately from owning Assist archive and shipping-package validation.
