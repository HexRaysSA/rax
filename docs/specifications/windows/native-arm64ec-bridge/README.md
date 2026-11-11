# ARM64EC execution through the process interpreters

The AMD64 Windows personality can execute installed ARM64EC ranges with paired
AMD64 and ARM64 interpreters. Module and mapped-image ranges select the instruction set;
the signed function prefix selects the compiler-generated entry thunk. The
thunk handles signature-specific arguments. Private guest helpers supply the
emulator's entry, return and exit boundaries. No host function pointer executes
guest code.

Before installed NTDLL replaces the initial checker slots, direct calls supply
their target in X9; indirect and CFG checkers use X11. The helpers preserve the
argument registers and reject unknown targets or unavailable CFG admission.

The paired context uses the Windows SDK ARM64EC_NT_CONTEXT mapping, including
integer, XMM and packed x87 carrier state. AMD64 remains the public CONTEXT
representation. NT services use the active instruction ABI while keeping the
process's logical AMD64 data layout. Entry stack ownership records the original
post-pop address and its 16-byte-aligned ARM64 address. Invalid or unmatched
return ownership fails explicitly.

A guest-owned sparse bitmap preserves the complete selected kernel reader.
For a guest address A, its byte is bitmap_base + (A >> 15), and its bit index is
(A >> 12) & 7: one classification bit per 4096-byte page. A 4-GiB virtual
reservation covers the lower 47-bit address space. Only ARM64EC ranges set bits.
Executable AMD64 pages require committed readable zero coverage too; ordinary
read-write allocations leave untouched bitmap pages reserved. Bitmap pages are
read-only, charge against the guest commitment limit, and retain their coverage
and set bits after image/private allocation release. Guest writes and stale
allocation reuse cannot replace the bitmap's owner.

The guest PEB publishes the bitmap at the native64 EcCodeBitMap field. Installed
NTDLL initializes its own cached globals from it. Each mixed thread has a
separate owned CHPE CPU-area reservation, AMD64 CONTEXT, doorbell and guarded
emulator stack. Instruction-boundary observation merges only changed CONTEXT
bytes into live state; an unchanged snapshot cannot roll back intervening
instructions. Private native pointers are never copied from the host.

The primary Microsoft ABI document and its redistribution license are retained
unchanged here. The pinned PHNT header names the PEB/TEB fields; provenance.json
records source revisions and checksums. Native observations of the selected
Windows build establish private bitmap geometry, protection, lifetime and CHPE
pointer fields separately from those declarations.

Bounded installed-call controls establish the entry/return path and six
scalar/service cases; they do not establish complete startup or nested
callbacks. The native alignment oracle accepts callback addresses at offsets
0, 4, 5 and 15 within owned executable pages. A guest probe that calls before
loader initialization completes reaches an installed NTDLL fail-fast before
entering its callback. Allowing actual loader initialization to continue reaches
the registry admission boundary described below before NTDLL enables its mixed
execution mode. The nested callback remains unqualified. No private NTDLL global
is patched to convert either frontier into success.

An earlier source-bound full AMD64 startup progressed to an explicit NtOpenKey
admission boundary outside the selected registry snapshot. General authorized
host-backed read-only registry access, full mixed-ISA unwinding and asynchronous
continuations remain requirements of complete same-host process emulation.
Native ARM64 keeps its original decoder and must retain the actual installed
CMD comparison. These limits are not a declaration of full process support.

The two native controls can be reproduced from an x64 Windows Rust developer
prompt with Rust 1.95.0 and the Windows SDK/linker available. Keep their output
inside the current worktree:

```powershell
rustc +1.95.0 --edition=2024 --target x86_64-pc-windows-msvc .\docs\specifications\windows\native-arm64ec-bridge\native-code-bitmap-v10.rs -o .\target\native-code-bitmap.exe
.\target\native-code-bitmap.exe
rustc +1.95.0 --edition=2024 --target x86_64-pc-windows-msvc .\docs\specifications\windows\native-arm64ec-bridge\native-callback-alignment-v11.rs -o .\target\native-callback-alignment.exe
.\target\native-callback-alignment.exe
```

For strict build-directory containment, set TMPDIR, TMP and TEMP to an owned
subdirectory of this worktree before invoking the compiler. These controls
read the current process's NTDLL and allocate only their own private memory.
The callback control must print NATIVE_CALLBACK_ALIGNMENT_PASSED=4. Its four
rows require status 0, once 0x4002 and context 0x4000. The bitmap control reports
an initially reserved ordinary allocation's bitmap byte, readable zero bytes
after adding execute permission, and retained EC bits after free/reuse. Native
addresses are process-specific; the checksums bind the retained observations
to their selected DLLs and source rather than to fixed future addresses.


## Guest-mapped images

Executable `SEC_IMAGE` views carry the instruction metadata of the exact
selected ARM64X projection, including partial-view RVA offsets. The immutable
CHPE record set is shared between mappings. Call checking and compiler
redirection consult that view when the guest loader has yet to publish a
module record. [Microsoft ARM64EC range-table contract](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi).

Classification follows committed executable pages and the live mapped
extent. Protection faults retain their instruction-fetch behavior. Unmapping
retires the metadata association. A replacement AMD64 image uses its own
projection even when the native bitmap retains an earlier EC tag.
`SEC_IMAGE_NO_EXECUTE` inspection views preserve their existing mapping
and metadata-probing behavior.

Captured kernel image extensions carry their native machine identity
separately from the PE projection. A live full view executes those recorded
extension bytes in the native instruction architecture. Partial views omit
the extensions. Rebase acquisition requires the same native identity for
the independently captured views.

On ARM64 Windows build 29704, the unchanged AMD64 fixture previously reached
unregistered KernelBase image bytes using the AMD64 decoder and raised an
access violation. The candidate routes that code and NTDLL's captured kernel
extension, then reaches a null instruction address and the existing AMD64
exception-frame qualification boundary. The ARM64 and x86 fixtures exit zero.
The focused selection passes 40 tests on macOS, 40 on native Linux and 43 on
native Windows, with zero failures or ignored tests.
[Source-bound mapping observations](mapped-image-routing-29704.json).
