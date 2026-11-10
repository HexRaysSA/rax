# Owned file-backed image sections

This increment implements the original seven-argument `NtCreateSection` for
unnamed, standard `SEC_IMAGE` sections backed by an already admitted, retained
file. It does not widen path admission, runtime-library selection, or file
authority. The full same-host process-userland objective remains active.

## Contract

The service validates the effective file-handle grant before acquiring bytes.
The independent build29683 controls establish these requirements:

| PAGE value | Required file rights |
|---|---|
| `0x02` | `FILE_READ_DATA` (`0x01`) |
| `0x04` | `FILE_READ_DATA | FILE_WRITE_DATA` (`0x03`) |
| `0x08` | `FILE_READ_DATA` (`0x01`) |
| `0x10` | `FILE_EXECUTE` (`0x20`) |
| `0x20` | `FILE_READ_DATA | FILE_EXECUTE` (`0x21`) |
| `0x40` | `FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE` (`0x23`) |
| `0x80` | `FILE_READ_DATA | FILE_EXECUTE` (`0x21`) |

Generic file rights are expanded for this check. A more privileged retained
host handle does not replace a reduced guest handle's rights. Requested Section
rights use the captured constructor mapping; explicit duplication suppresses
`MAXIMUM_ALLOWED` expansion. `ACCESS_SYSTEM_SECURITY` requires the captured
enabled `SeSecurityPrivilege`; absent subject evidence is unsupported.

Creation publishes a typed `ImageSection` with an empty object-manager name.
Guest handles and pointers never enter a host NT call. The Windows adapter
receives an owned host File and local native scratch; it retains private kernel
Section handles and captures the existing kernel image-template representation.
Other hosts use the bounded portable PE representation. Both routes reject
shared writable image runs because the current image mapper owns private frames.
Independent v14 establishes that accepting those runs would lose native alias
coherence across independently created Sections.

`SEC_IMAGE_NO_EXECUTE` requires `PAGE_READONLY` at creation and at mapping.
On Windows, the retained Section supplies the kernel's inspection-image bytes
and the AMD64 projection for ARM64X images. On other hosts, the portable PE
reader supplies the image layout. The guest publishes `MEM_IMAGE` with
read-only initial and allocation protection and `ImageNotExecutable` in
image information. The view remains non-executable after closing the file and
Section handles. An explicit protection change can still create a private
writable or copy-on-write page. Unspecified bases use ordinary allocation
placement, and the relocation flag leaves inspection image bytes unchanged.
[Microsoft's mapping contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection).

The build 29704 controls ran on ARM64, AMD64 and WoW64 x86. They inspected
three matching PE fixtures and the installed ARM64X `version.dll`. For
successful full inspection views, the control verified `PAGE_READONLY`,
`ImageNotExecutable`, and absence of image extensions. An explicit preferred
base preserved the same view bytes as automatic placement. The kernel's
process-specific placement address is variable. See
[the native probe](validation/image-no-execute-29704.cpp) and its
[capture identities](validation/image-no-execute-29704.json).

Maximum-size semantics preserve three separate quantities:

```text
MaximumSize = 1 B
     |
     +--> Section basic maximum:             1 B
     +--> ordinary mapped extent:         4096 B
     +--> image-information size: full SizeOfImage
```

The default or zero maximum uses the full image. A partial image does not reserve
the full image's extension tail. Image-information queries retain the complete
image size and set the partial-view flag. A mapped view retains the Section and
file lifetime after caller file/Section handles close; final unmap releases that
reference. This is view ownership evidence, not a complete file-deletion contract.

WoW64 captures `OBJECT_ATTRIBUTES` before the native request. It uses a private
native HANDLE output, then copies to the guest destination. Maximum-size faults
can therefore consume guards before a late output-store fault. The constructor
preserves this order, zero copy-back on native failure, and single-store cleanup
when publication itself faults. Existing pagefile constructor and image-map
replays exercise the common path after these corrections.

The portable reader preserves the retained file cursor on every read outcome.
Windows `FileExt::seek_read` changes that cursor, so its adapter saves and restores
the position under scheduler serialization. Unix uses positional `read_at`.
The platform distinction is documented in the
[Rust 1.95.0 FileExt contract](https://doc.rust-lang.org/1.95.0/std/os/windows/fs/trait.FileExt.html).

## Evidence and limits

`native-producers.json` identifies eleven accepted independent producers with
7,396 recorded input/view rows across four execution views. Those rows cover
constructor, duplicate, and mapping procedures; they are not 7,396 constructor
calls. Native ABI controls use `SIZE_T`/`PSIZE_T` for `NtQuerySection`,
`ULONG`/`PULONG` for `NtQueryObject`, and exact 56-byte object-basic scratch.
Native Section-basic layout is asserted as 24 B on 64-bit Windows and 16 B on
32-bit Windows. Producer versions 1, 4, 9, and 13 are rejected and establish no
final behavior. V3 contains 149 roles including its 77 additional grant/PAGE
combinations; its historical driver scope sentence must not add 77 again.

The compiled replay matches 2,072 constructor rows and classifies 60 explicit
policy boundaries. It separately matches all 1,720 Win32 duplicate rows,
including exact grants, identity, cleanup, and last-error behavior. Raw records
and source/executable/module identities accompany the native producers.

The red run is against `02cefa7d675fbdb83494f8d2635a9e880bb4cba9` with only its
two test overlays: zero passes, one failure at the former file-backed boundary.
`validation/file-section-red-test-body-binding.json` proves the 2,722-byte
constructor test body is unchanged in the final test file. Later helper/module
declarations extend that file; the complete baseline/final files are not claimed
byte-identical.

The source freeze is `validation/file-section-candidate1-source.json`: 26,884
inputs, SHA-256
`985b35da38a798311293a8c3c48599f107e7a358547cbf2e9499d8414291413a`.
Compiler inputs include the exact replay corpus. Publication evidence added
after the freeze is outside that compilation graph. The Windows dependency
config override is pinned separately from the original config and from CRT
selection. Baseline, prototype, and final test executables have separate cache
ownership; the final native primary package is evicted before compilation and
the actual Cargo-selected executable is identified around execution.

Complete source, native, owning-core/carrier, and C++ consumer validation are
separate gates:

| Host | Unfiltered library | C API | Integration | Owning consumers |
|---|---|---|---|---|
| macOS ARM64 | 8,135 pass; 2 existing ignores | 183 pass | 544 pass | 7 CTests; 6 actual Ninja carrier link paths |
| Linux AMD64 container | 8,129 pass; 2 existing ignores | 183 pass | 544 pass | 5 compiled C++ consumers |
| Windows ARM64 | 7,598 pass; exactly 5 existing lowerer failures; 2 existing ignores | 183 pass | 4 pass | 5 compiled native C++ consumers |

All three all-target configurations pass. Windows ARM64 and AMD64 cross-target
all-target checks also pass. The focused selection has seven common tests and
one additional native Windows test, exercising host/WoW64 installed leaves and
the cached AMD64 image projection. Windows's complete section selection has
25 passes. Root/core archives are selected from actual Cargo artifact records,
walked completely, and identical before and after the owning consumer checks.

The native gate driver completed its required nine stages. Its extra ordinary
core selector then rejected `fresh=true`: the C API stage had already built that
same candidate core. `validation/file-section-candidate1-final-gates.json`
audits the completed stages and rehashes the actual selected test executable.
The original failed driver receipt is retained. Ordinary behavior is established
independently through the actual owning core and the Assist C++/C API carrier.

Both owning ordinary routes run smoke to exit status 0. Both advance `whoami.exe`
to the same SEH frame-walk failure at PC `0x037349F8`, SP `0x01A5E560`.
The Rust observer records terminal index 2,548 and the C API records 2,549 turns
started: the former is zero-based. A C API failure reason of 5 with an exit-code
field of 0 is not a guest exit. Its root cause remains unknown. Eight runtime
DLL inputs, source/program/caller identities, native control output hashes,
and the exact exercised core/carrier remain stable. Four separate retained
native byte copies preserve the core, carrier, and both ordinary callers.

Source success does not establish an installed Assist artifact, current-root
GUI, package, or complete ordinary-program result. The Linux AMD64 userspace
runs in Docker/Orb on an ARM64 development host; this is not a physical AMD64
hardware claim. Six public projections retain actual artifact metadata and
original byte identities while withholding private Assist compiler diagnostics.

Each host additionally rejects eight native-oracle corruptions and eight
owning/ordinary-result corruptions, with a fresh positive restoration after
every rejection: 48 negative checks and 48 restorations across all three hosts.
The source-set and archive-walk mutations adjust both snapshots consistently
so they reach the corresponding semantic checks.

## Remaining boundaries

| Impact | Boundary | Blocks this constructor increment |
|---|---|---|
| High | File-backed data sections, named objects, explicit security descriptors/QoS, and permanent lifetime remain unsupported. | No; explicit result, broader objective remains active. |
| High | Shared writable PE image coherence requires shared-frame integration; v14 proves the requirement. | No; rejected before publication. |
| High | AMD64 process spawning from ARM64X System32 is a separate runtime-directory selection boundary on the ARM64 host. | No; host/WoW64 leaves and the image adapter's cached AMD64 projection are independently exercised. |
| High | The prototype advances `whoami.exe` beyond file-backed creation and reaches an SEH frame-walk error. | No full-process completion claim; final owning routes must be observed separately. |
| Medium | The prior published RAX GitHub Windows precheck has five failures also present at its parent; its C API stage is not reached. | No CI-green claim. |

Native records come from one ARM64 Windows kernel, with ARM64, AMD64, WoW64,
and WoW64 large-address-aware execution views. They do not establish an
independent physical AMD64 kernel oracle. The retained Assist owning consumer
is ABI184; it is separate from the current root's ABI274.

Portable backing is bounded by a 64 MiB regular file and a 64 MiB page-aligned
image. The existing image-template validator bounds region count. Constructor
work consists of bounded PE parsing, O(F) file reading, and O(I + R) image/page
policy construction for F file bytes, I image bytes, and R region runs. Mapping
uses the existing O(B + R log P) image-copy policy for B mapped bytes and P page
state runs; no separate sysroot is introduced.
