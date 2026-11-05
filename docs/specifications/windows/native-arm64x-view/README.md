# Installed ARM64X image views

The installed Windows NTDLL can have an ARM64 file header while its kernel
image view in an AMD64 process has an AMD64 header, different exports and
AMD64 syscall leaves. The loader must interpret metadata and executable bytes
from the same selected view. Changing the file's machine value alone does not
perform that selection.

This changeset adds an explicit mapped PE representation and decodes ARM64EC
CHPE metadata. Installed KnownDLL selection retains its pinned kernel section and
uses that section's architecture-specific image for headers, exports, load
configuration and mapped bytes. File bytes remain separately available as the
original source. Source/view selection checks the NT-header offset, timestamp,
optional-header kind and size, image/header sizes, alignments, characteristics
and complete section table. These are structural identity checks, not a claim
of a cryptographic binding between a file and a kernel section.

The instruction guard consults the selected module's code map before each
instruction during AMD64 compatibility execution. An AMD64 range can continue
in the x64 interpreter; ARM64/ARM64EC ranges need the separate ISA/ABI bridge.
Native ARM64 execution keeps its normal instruction decoder and page checks:
an ARM64EC ABI tag does not make its instructions a different instruction set.
The initial broader guard regressed an actual installed ARM64 CMD command;
the correction and its positive/negative evidence are described in
[the native ARM64 guard record](../native-arm64-hybrid-guard/README.md).
Execution classification of additional kernel image-extension code is part of
the remaining mixed-ISA work.

This is an intermediate part of the full same-host installed-library process
implementation. ARM64EC register/context transitions, entry/exit thunks,
emulator-helper bindings, projected non-KnownDLL images and complete mixed-ISA process
startup remain required. This document does not claim arbitrary x64 programs
run on Windows ARM64, physical AMD64 qualification, or completion of the
Linux/macOS/Windows process goal. ELF and Mach-O loading are unchanged.

## Format and bounds

`PeImage::with_mapped_view` retains immutable file and mapped buffers separately.
It decodes projected headers as mapped data and does not validate file offsets
against the mapped buffer or copy section bytes from file offsets again.
It requires exactly `SizeOfImage` bytes and unchanged source section geometry.
The caller still owns architecture admission and the selected section's
lifetime and authority.

`LoadConfig` reads `CHPEMetadataPointer` only when both the directory and the
structure's declared size cover its complete pointer-width field. The offsets
are 124 bytes in PE32 and 200 bytes in PE32+. The ARM64EC decoder is used for
PE32+; the x86 CHPE metadata format is separate.

The metadata decoder accepts versions 1 and 2, with 80-byte and 92-byte headers.
Code-map entries have an 8-byte stride: the low two bits of the start word encode
ARM64 (0), ARM64EC (1), or AMD64 (2). Tag 3 is rejected. Ranges are half-open,
nonempty, ordered, nonoverlapping and inside the selected image. Gaps do not
inherit the preceding range's ISA. Entry ranges and redirections have 12-byte
and 8-byte strides. All VA subtraction, table extents, targets, helper-pointer
slots and count bounds are checked before allocation or use.

Each table has a RAX admission bound of 65,536 records, independently of its
image extent. This is an implementation bound, not a Windows format limit.
Unknown versions, unavailable bytes and unsupported layouts produce errors.
The decoder does not apply dynamic relocations or initialize emulator helpers.
File-backed metadata reads use validated RVA ranges and zero fill without
allocating `SizeOfImage`. This preserves arena/commit-budget rejection for a
small supplied file that declares a multi-gigabyte image.
Parsing costs O(C + E + R) time and storage for the three table sizes. Code-map
classification costs O(log C). The current module guard costs O(M + log C) for
M registered modules.

The primary LLVM layouts, implementation and license are retained unmodified
under `references/`, together with Microsoft's ARM64EC ABI documentation and
license. `references/provenance.json` records immutable revisions, retrieval
URLs and SHA-256 values.

## Native observations

`observations-arm64-29698-v1.log` and `observations-x64-29698-v1.log` record the
owning PE decoder reading each native process's already loaded NTDLL. The probe
uses the current-process pseudo handle and opens no external process handles.
Both executions completed with exit code 0 against disk NTDLL SHA-256
`e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd`.

| Caller | Loaded machine | NtQueryInformationProcess RVA | Code kind |
|---|---|---|---|
| Native ARM64 | 0xAA64 | 0x11A0 | ARM64 |
| Translated x64 | 0x8664 | 0x321340 | AMD64 |

Both views expose metadata version 2, 15 code ranges, 2,078 entry ranges and
2,078 redirections. All 15 decoded code ranges match the independent LLVM
23.0.0git parse of the captured installed file. The receipts and image/source
hashes are summarized in `provenance-v1.json`. These observations validate the
metadata decoder over real loaded views; they do not validate guest execution
or an ARM64EC transition.

The producer source is retained byte-for-byte. Its relative module import
reflects the exact in-tree location used to compile it. To reproduce from a
checkout, first copy it into that location:

```sh
mkdir -p .task-evidence/windows-arm64x-view-v1
cp docs/specifications/windows/native-arm64x-view/native-loaded-view-parser-v1.rs \
  .task-evidence/windows-arm64x-view-v1/native-loaded-view-parser-v1.rs
```

Compile this std-only producer for `aarch64-pc-windows-msvc` and
`x86_64-pc-windows-msvc` with Rust 1.95.0, keeping linker intermediates, temporary
files and output under the current checkout's `target/`. Run both executables
on native Windows ARM64. They print the selected machine, base, image extent,
export bytes and complete code-range classification. No separate sysroot or
copied replacement DLL is supplied to the running process.

## Validation ledger

The full affected module selection includes the PE decoder, Windows CPU and
loader, native-view selection, shared AArch64 CPU adapter, and existing file
create/open/read/write/information/volume query regressions. The complete
standalone PE module has 62 tests.

| Host view | Passed | Failed | Ignored |
|---|---|---|---|
| Native macOS ARM64 | 159 | 0 | 0 |
| Linux amd64 translation | 159 | 0 | 0 |
| Native Windows ARM64 | 164 | 0 | 0 |
| Translated Windows x64 | 164 | 0 | 0 |

All four owning-library configurations compile; all four normal Clippy
`--lib --tests` checks complete with no diagnostics in owned files. Windows
retains the existing third-party `vm-memory` calling-convention diagnostic.
`regression-qualification-v1.json` binds the 646 passing tests to source and
image hashes. Each Windows view also passed a separate three-case selector and
installed-service-leaf scout. Native pre/post hashes cover NTDLL, Kernel32,
KernelBase and the WoW64 NTDLL.

The earlier x64 baseline failed at raw NTDLL selection. The initial projection
candidate advanced to raw Kernel32 rejection; general KnownDLL view selection
then allowed both existing installed file-service leaves to run successfully.
These failure records remain in task evidence. No test was skipped or weakened
to obtain the final results.

A separate bounded x64 startup observation loads the executable and all three
installed dependencies, then stops before ARM64EC code at NTDLL RVA 0x245470.
The wrapper completed collection; the guest did not complete. ARM64EC execution
is the next required frontier. The broader registered process integration run
is separate and is not counted as a completed gate here.

Assumption VIEW1 ties the captured installed DLL to the intended native source.
Fresh native pre/post hashes confirmed that identity for both decoder probes.
The guest execution and packaging portions of the full goal remain unproven
until their corresponding consumers and native runs complete.
