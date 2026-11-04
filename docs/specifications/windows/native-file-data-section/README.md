# File-backed data sections

This profile covers standard unnamed non-image sections over an already
admitted, readable file resource. It uses the retained file rather than reopening
a pathname or building a separate sysroot. Guest pointers, handles, names and
security descriptors are never passed to the host NT object manager.

## Implementation contract

`NtCreateSection` checks the effective file-handle grant before constructing the
section. A zero or absent maximum selects the current file length; a positive
maximum remains byte-exact in `SectionBasicInformation`. Only shared-writable
section protection can extend the file. Empty zero-sized sections return
`STATUS_MAPPED_FILE_SIZE_ZERO`.

`NtMapViewOfSection` checks the exact byte limit before rounding the selected
view outward to 4096-byte pages. File offsets and explicit bases require
65536-byte alignment. File views report `MEM_MAPPED`; their original view
protection bounds later protection changes. Standard `SEC_COMMIT` and
`SEC_RESERVE` file sections report `SEC_FILE` (`0x00800000`).

Independent sections and shared views observe live file updates. A write-copy
view continues observing those updates until its first write to each page.
That write allocates a private frame, including an identical-value store or a
writable probe. An untouched page can return to shared-write policy; a page
already copied remains private. A partial final file page has a zero-filled
tail without extending the file.

Mapped views retain their backing after guest file and section handles close.
`NtUnmapViewOfSection` releases the view; `VirtualFree` cannot replace that
section lifecycle. Windows retains adapter-owned native sections and views
without duplicating the source file handle. Closing the guest file therefore
releases that open's sharing reservation even while its sections or views remain
alive. Native file-section lifetime rules apply before guest pages are touched.

`NtQuerySection` class 0 serializes the section maximum and allocation attributes.
Non-image class 1/2 requests return `STATUS_SECTION_NOT_IMAGE` after their
class-specific length and access checks; native64 class 3 has the same non-image
result. The measured WoW64 converter has separate length, guard and copy-back
rules. After a first private store, successful protection changes return the current
page protection, including the conversion from write-copy to read-write.
Allocation-wide region queries report private copy commitment separately
from shared file bytes.

| Host | File pages | Private first write |
|---|---|---|
| Windows | Retained native sections and arena placeholder views | Private frame; independent section views share the kernel file cache |
| macOS | Retained file and shared host mapping | Private frame over the same live source |
| Linux | Retained file and shared host mapping | Private frame over the same live source |

The existing address-space scheduler contract applies: guest threads in an
address space run on one host thread. Mapping changes, population and first-write
replacement serialize under the VMA owner lock.

## Independent native evidence

The archive contains 16,122 cases from independent programs importing Kernel32
and the installed NTDLL. These programs contain no RAX headers or product code.
Each corpus binds the executed input, image hash and byte-exact reconstructed
stdout. Build-input bundles retain the original CMake/SEH inputs; their recorded
build paths are provenance, not runtime dependencies.

| Control | Cases per ABI | Total |
|---|---:|---:|
| Constructor, basic query, initial view and file effects | 1134 | 3402 |
| Live-file, alias, copy, growth and lifetime phases | 45 | 135 |
| Pointer capture, geometry and basic protection transitions | 1950 | 5850 |
| Complete standard protection compatibility matrix | 448 | 1344 |
| Query lengths, alignment, guards, grants and output bytes | 1584 | 4752 |
| Installed RTL status-to-error conversion | 6 | 18 |
| Protection changes after a first private store | 72 | 216 |
| File cleanup, sharing and retained Section/view lifetimes | 135 | 405 |

The process ABIs are ARM64, x64 and WoW64 x86 on one Windows ARM64 kernel,
10.0.29698.1000. These observations do not establish physical x86 kernel
equivalence. The WoW64 coherence run has one process-wide handle-count delta
of five with unknown cause; it is not attributed to five File/Section leaks.
Raw observations remain in the archive.

Verify the archive from the repository root:

```text
python3 docs/specifications/windows/native-file-data-section/verify.py
```

Expected output:

```text
Verified 16122 independent native cases and their source/image/stdout bindings
```

To rebuild on Windows, use a Developer Command Prompt and LLVM/MSVC-compatible
SDK environment matching the target architecture. Keep build and compiler
temporaries inside this checkout. For a native build with Ninja and clang-cl:

```powershell
$probeBuild = Join-Path $PWD 'build-native-file-data'
New-Item -ItemType Directory -Force (Join-Path $probeBuild 'tmp') | Out-Null
$env:TMP = Join-Path $probeBuild 'tmp'
$env:TEMP = $env:TMP
cmake -S docs/specifications/windows/native-file-data-section -B $probeBuild -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_LINKER=lld-link -DCMAKE_AR=llvm-lib
cmake --build $probeBuild --parallel 2
ctest --test-dir $probeBuild --output-on-failure -j 1
```

CMake registers eight independent controls and places their file fixtures below
the build directory. Cross builds require a matching Windows toolchain, SDK
library architecture and `CMAKE_SYSTEM_PROCESSOR`; execution must use a Windows
host supporting that process ABI. New observations on another DLL/kernel build
are separate evidence rather than replacements for the frozen archive.

Owning product checks use the `native_file_data_` tests, alongside existing
`native_section_file_` tests and `user::mm::file_cow::` tests. Native observations
and product replay qualification are separate: an archived successful native
call does not prove the emulator implements it.

## Scope and assumptions

| ID | Assumption and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| A1 | Creation-time snapshots could represent file sections | Native views touched before later external file writes | Falsified; live backing is required |
| A2 | Every private-labelled shared backing could acquire copying implicitly | Device and Mach-memory mappings with intentional physical sharing | Revised; copying is explicit and existing callers retain their policy |
| A3 | Native64 query output needs pointer alignment | Native class-0 output at a 4-byte but not 8-byte aligned address | Falsified; the measured output alignment is 4 bytes |
| A4 | Constructor success alone establishes usable file-section support | Owning map, protect, close and unmap service calls | Falsified; all lifecycle paths require wiring |

The current resource policy bounds a section to 64 MiB and conservatively
reserves a view-sized amount of the configured no-paging-file frame budget.
Native allocation-region private commitment is reported from actual copy policy
and acquired private pages, not from that conservative internal budget.

Named/permanent sections, based/no-change/64 KiB allocation modes, large-page
file sections, and byte extraction from execute-only backing descriptors remain
explicit frontiers. A readable retained descriptor can still carry a reduced
guest execute-only handle grant. The engine does not reopen a pathname to add
rights when the retained resource cannot supply bytes.

Resizing or overwriting a file with a live data-section object or view returns
an explicit unavailable result before changing its length. This includes a view
whose file and section handles have already closed. Ordinary writes and creation
of a larger shared-writable section retain their qualified behavior. Independent
host truncation outside the process's admitted file operations is an external
mutation boundary. Native Windows also retains a section before page access;
its resources retire before the final deferred-delete owner.

This change does not implement anonymous `Object::Mapping` native view dispatch,
selected CSR snapshot basic allocation attributes, or image-specific
`NtQuerySection` information classes. Those paths retain explicit unavailable
results. Complete same-host process emulation remains a broader goal.

Primary API contracts: [ZwCreateSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection),
[ZwMapViewOfSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection),
[SetEndOfFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setendoffile).
Capture-order and WoW64 details above come from the archived native observations.
