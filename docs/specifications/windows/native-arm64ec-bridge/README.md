# ARM64EC execution through the process interpreters

The AMD64 Windows personality can execute installed ARM64EC ranges with paired
AMD64 and ARM64 interpreters. Module code ranges select the instruction set;
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
