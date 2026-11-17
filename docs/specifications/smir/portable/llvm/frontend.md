# TargetInfo, source ABI and hosted baseline

This is a proposed compiler configuration, acknowledged for local witnesses only.
ABI-P1/ABI-P3 and LLVM-IF-004 are coordination revisions; the integrator records
acceptance. The ABI chapter owns source layout and descriptors. The execution
chapter owns structural value types. This document defines compiler consumption.

| TargetInfo property | Required draft value |
|---|---|
| Triple | smir64-unknown-rax |
| char width / signedness | 8 bits / signed |
| short / int / long / long long | 16 / 32 / 64 / 64 bits |
| pointer representation / index | 64 / 64 bits; data AS0, stable external-state program AS1 |
| size_t / ptrdiff_t / intptr_t | unsigned long / signed long / signed long |
| wchar_t / wint_t | wchar_t signed 32; wint_t unsigned32, size4 B/align4 B; WEOF=0xffffffff (INT-006 local draft) |
| float / double / long double | IEEE binary32 / binary64 / binary128 |
| __int128 | 128 bits, size16 B, align16 B |
| _BitInt | unsigned1..65535, signed2..65535 bits; storage below |
| stack alignment | 16 B, no red zone or physical callee-save set |
| C++ ABI | GenericItanium, pinned Clang ABI behavior, libc++ stable ABI version1 |
| ARM method-pointer / guard-variable ABI | disabled; generic Itanium forms |
| native register/CPU features | none; no ISA intrinsics or inline assembly |
| MaxAtomicInlineWidth | 0 bits for ordinary atomics; dedicated atomic_flag port preserves its required lock-free guarantee |
| MaxAtomicPromoteWidth | 128 bits for object layout, no lock-free implication |
| __GCC_ATOMIC_*_LOCK_FREE / ordinary always_lock_free | 0 / false for ordinary baseline widths; atomic_flag is separately guaranteed lock-free |
| guest TLS / errno / fenv / exceptions | explicit logical thread state; no host storage |

The exact DataLayout string is machine-readable in target.json and constrained
by request.schema.json. LLVM DataLayout units are bits; independent layout
fixtures report bytes. For pointer size, `64 bits / (8 bits/B) = 8 B` exactly;
stack `S128` means `128 bits / (8 bits/B) = 16 B` exactly. No measurement error
or floating approximation enters these integer calculations.

The accepted compiler logical allocation appends `-pe1:64:64:64:64-P1` without
changing the prior data layout. Source function-address LLVM values use
`ptr addrspace(1)`; their storage addresses remain AS0. Program pointers have
64-bit size/index, 64-bit ABI and preferred alignment (8 B), stable representation,
external state and null bits0. AS1 is a compiler namespace, not a host PC or ISA
mapping. No implicit AS0/AS1 conversion is admitted.

Address space is insufficient to choose a SMIR value domain. Validate the original
source/type/descriptor context before lowering a function address, typed internal
CodePtr, block label or foreign address. In particular LLVM BlockAddress uses the
program space but keeps `E-CONSTANT-BLOCK-ADDRESS`; it is never converted to an
ordinary CodeAddress by an AS1 test. Generic LLVM casts only observe/create the
in-band bits of the validated source CodeAddress; actual source code exposure and
recovery use the accepted observing LLVM018 helpers before optimization.

The parameterless compiler-only TargetExt names `smir.code_binding` (B) and
`smir.source_scope` (S) join the existing four carrier whitelist entries. B carries
the actual checked CodePtr<Fn> constraint; S tracks original source lineage and
erases to a verified ScopeSlot. They have no guest storage or public source ABI
position. Reject sizing/alloca/load/store/raw or numeric conversion, foreign
escape, freeze and untyped escape. Permitted SSA calls/phi/select/copies retain
the actual original Fn/scope relation; B aggregate groups remain one exact checked
transaction. Generic LLVM parsing does not enforce these portable policies.
Ordinary code_bind/source_plan restrictions remain; AS1 does not supply the
separate nonordinary C++ caller binder/projection.

The library-only program-space witnesses parse and verify the exact custom layout
with pinned LLVM libraries and query geometry/null representation directly. The
older bootstrap optimizer's data-only size witnesses remain LLVM23 observations;
they do not qualify the LLVM24 target or program semantics. No foreign
TargetMachine is invoked to accept the custom layout.

Vector ABI entries v8/v16/v32/v64/v128/v256/v512 have alignment equal to bit
width; three-lane extended vectors allocate the next power-of-two storage size.
Use allocation size for array strides, not vector bit width. Boolean/scalable
vector source ABI is rejected by ABI-P1 even though LLVM fixed vector i1 values
can appear internally. LLVM type admissibility and source ABI admissibility
are separate checks.

Section1 execution memory layouts explicitly encode allocation size, alignment
and access bytes in bytes, but sequence stride and field extents in bits. Internal
vector<i1> lanes can therefore have stride1 bit while array<i1> elements have
stride8 bits. ABI-visible accesses additionally select section10 source nominal
and storage_binding; equal value shape or byte size does not prove an alias-correct
source view. Bindings preserve physical positions. Conversion to a differently
arranged temporary requires explicit copy/projection code.

For source `_BitInt(N)`:

```
bytes = ceil(N / 8)
align = min(8, next_power_of_two(bytes)) B
size  = round_up(bytes, align) B
```

For N=65: bytes=9 B, align=8 B, size=16 B. With preceding char, field offset=8 B,
record size=24 B, record alignment=8 B. Plain LLVM `{i8,i65}` under the candidate
DataLayout instead places the field at16 B and allocates32 B. They are different
representations. Preserve i65 SSA precision; lower memory using AST storage,
explicit padding/packed or byte-array fields as necessary, and explicit8 B
alignment on allocation/access/ABI attributes. An LLVM byte array's alignment1 B
alone does not establish source object alignment8 B. Never change binary128 or
__int128 alignment globally to hide this discrepancy.

An i65 typed store touches9 B, zeroing only the7 unused high bits in byte8;
the remaining7 allocation-tail bytes are untouched. Canonical packing of a fresh
16-B vararg payload is a distinct explicit effect. Source record/bit-field views
name exact source paths and execution fragments; raw byte copies preserve all
padding, poison and pointer-origin shadow.

Pinned `TargetInfo.h` exposes BitIntMaxAlign/getBitIntAlign/getBitIntWidth;
`CodeGenTypes.cpp` already separates SSA precision and storage and can split
memory representation into byte arrays. `CGRecordLayoutBuilder.cpp` must make
LLVM field offsets agree with AST record offsets. Witness all three: AST offsets,
LLVM storage geometry and access alignment. Existing x86-64 Linux Clang with
`-mlong-double-128` supplies a comparable subset; AArch64 currently aligns
BitInt65 to16 B and is an intentional negative comparison. Neither is a SMIR
TargetInfo implementation.

## Source record-input production and selected layout

The current coherent static contract uses ABI payload revision3. Envelope
version0.2 and profile2 are unchanged. The exact object-root revisions are:

| Sections | Payload revision |
|---|---:|
| 1,2,3,5 | 2 |
| 4,6,7,8,9 | 1 |
| 10 | 3 |

Every whole-object decoder checks each raw u32 payload revision before parsing
dependent records. Older payloads reject WIRE-REVISION; a frontend never upgrades
them by inferring missing source traits or call plans. Retained ABI2 observations
describe their historical cuts. The nominal source fingerprint domain is the
22-byte sequence `SMIR-NOMINAL-SHAPE-V3` followed by NUL, hexadecimal
`534d49522d4e4f4d494e414c2d53484150452d563300`. Execution type identity retains
its separate domain. Complete records carry Some(record_layout_input),
while nonrecords and incomplete record declarations carry None. Ordered source
field/base qrefs retain their original declaring module after provider selection.

The producer reads `isPOD`, `isTrivial`, `isCXX11StandardLayout`, `isPolymorphic`,
`isDynamicClass` and `isEmpty` from the pinned CXXRecordDecl. Dynamic does not
imply polymorphic: virtual-base-only classes can require a vptr. Explicit
alignment is the actual numeric Decl::getMaxAlignment divided by8 bits/B, not
an aligned/not-aligned flag. Fields and direct bases retain declaration order,
source names/access, bit widths, NUA and anonymous grouping. Selected physical
layouts are outputs; their geometry cannot establish those source facts.

The fixed GenericItanium TargetInfo uses useBitFieldTypeAlignment=true,
useZeroLengthBitfieldAlignment=false, useLeadingZeroLengthBitfield=true,
zeroLengthBitfieldBoundary=0 bits, useExplicitBitFieldAlignment=true and a
largest oversized bit-field container of128 bits/16 B. Int128 is available with
alignment16 B. The false zero-length alignment knob preserves the selected rule
that unnamed bit-fields do not raise record alignment; placement barriers remain
separate. Existing native x86 target's64-bit largest container is not this port.
Packed, ms_struct, pragma-pack/MaxFieldAlignment, external AST layout and native
AIX/ARM/Apple/sanitizer field-padding variants are outside the selected profile.

Read the full evaluated bit-width APInt before asking for AST record layout.
Pinned getBitWidthValue returns unsigned; an accepted width2^32 truncates to0
in its layout path. Until an upstream correction is adopted, widths above
UINT_MAX diagnose `E-SMIR-UPSTREAM-BITFIELD-WIDTH`; the portable u64 record
grammar is unchanged and its independent model does not copy this bug. Pinned
POD03 classification also has a distinct wide-bit-field/array FIXME: preserve
the pin's actual classification and record the upstream limitation separately.
The pinned ASTRecordLayout path separately rejects record sizes at or above
2^60 B, although the selected format/object ceiling is2^61-1 B. Header-free
syntax/layout witnesses distinguish a char-array record of size2^60-1 B
(accepted) from2^60 B and2^61-1 B (upstream errors). The source array address-width
bound remains2^61-1 B; it does not establish the same record extent support.
No LLVM checkout fix is applied and this upstream gap is not hidden by lowering
the portable format ceiling or certifying native layout for those records.

The isolated [AST witness](../../../../../tools/smir-llvm-contract/record_layout/README.md)
extracts typed inputs and existing-target physical observations. Empty-subobject
identity uses the canonical unqualified source class declaration; full source
fingerprints still preserve top CV. Native vptr reports retain offset,
offset_top, rtti, slots, vcall_offsets and vbase_offsets, with raw component
positions. The witness's RTTI/method references are explicitly unbound source
declarations, not serialized runtime symbols. A general AST-to-nominal producer,
SMIR TargetInfo, full source fingerprint producer and runtime symbol binder
remain absent. Accepted LLVM-PROD009REV2 normalizes actual implicit ordinary
unnamed lambda fields to Some($captureN), using zero-based declaration order
among all fields and preserving actual type/owner/access/traits. Selected names
and source_path components use that exact string. Actual source identifiers
beginning $capture diagnose E-SMIR-RESERVED-METADATA-NAME. Other implicit
ordinary unnamed fields reject. The generic ABI verifier checks canonical name,
index and nonanonymous/nonbitfield consistency; AST lambda origin remains a
producer obligation. Native negative vcall/vbase components can interleave.
Accepted INT033REV1 appends component_order with vcall/vbase tokens in increasing
physical address order, consuming the separate vectors exactly once. LengthL
and indexi map to slot `-8*(2+L-i)` B; offset-to-top remains at-16 B and RTTI
at-8 B, including a null RTTI value. Old omitted order is not synthesized.
Original source receiver/virtual-base target identity is a separate required
join; equal slot values cannot supply it. Full selected dispatch, VTT and
thunk/RTTI relations remain a pre-freeze gate beyond this order extension.

## Helper source metadata

Accepted INT032/ABI-PROD030REV6 defines seventeen helper names and nineteen
contract cases. A nominal namespace lookup alone does not establish the selected
role. The compiler attaches the actual source nominal and checked execution
representation; it does not attach an arbitrary int32 declaration because a
helper's execution signature uses an integer argument.

| Helpers | Exact compiler source choice |
|---|---|
| tls_address | Complete whole registered TLS object source nominal; drop only top CV for the compatibility comparison |
| tls_guard_acquire/release/abort; guard_acquire/release/abort | Initialized variable's declared type, including reference category/referent; separate runtime guard object is8 B/A8 |
| va_start/va_copy/va_end | Canonical c23 builtin array count1 of rax.va_state |
| va_arg | Requested source object after exact source promotions, with actual Type0 equal to its checked execution binding |
| setjmp_capture/longjmp_restore, setjmp and sigsetjmp contracts | Canonical c23 builtin array count1 of rax.jmp_state; normal source parameter adjustment passes its address |
| eh_allocate | Normalized thrown payload object, preserving legitimate c23 or cpp23 identity; not a header/exception-handle type |
| atomic_flag_test/test_and_set/clear | Exact source kind atomic_flag,1 B/A1, checked raw8 binding |

Both state records have size32 B/A8 and storage execution Array32<Raw8>.
rax.va_state has four unsigned-long fields area/cursor/limit/cookie at0/8/16/24 B.
rax.jmp_state has unsigned-int revision/reserved at0/4 B and unsigned-long
process/checkpoint/generation at8/16/24 B. Source scalar identities are exactly
c23/builtin/unsigned int or unsigned long; wrapper identity is c23/builtin/array,
with actual source child, extent1, no library/unit/top CV. Current ABI3 empty vectors and
record_input=None on nonrecords are explicit. The canonical reserved state
record uses the accepted six-false C trait convention, even when its compiler-
owned C++ AST declaration has true C++ traits. This normalization is restricted
to compiler-created reserved builtins; ordinary user record traits stay actual.
The ABI-owned source builder returns unsealed fragments, not verified facts.
Caller-allocated source/execution/layout IDs, original owner, actual domain/site,
definition sealing and full validation remain required before admission.

Reference variables store a reference cell of8 B/A8 with DataPtr64 execution;
its referent can be incomplete and its size is not the cell extent. The separate
guard object is not that cell. Static source validation cannot establish a
runtime guard/TLS/arena/EH registry association, generation or live lease.
Those dynamic requirements remain explicit and cannot be granted by metadata.

C23 ordinary _BitInt(N) default argument promotion preserves N and signedness.
A bit-field _BitInt(N):M becomes its declared _BitInt(N), not _BitInt(M) or int32.
The base C++23 profile diagnoses _BitInt source syntax as E-SMIR-LANGUAGE-EXTENSION;
any optional extension profile needs explicit separate negotiation. This does
not forbid internal LLVM iN types or change the selected C23 _BitInt object ABI.
Native register/vararg coercions do not define source promotion. Actual post-Sema
call argument types are witnessed independently of those native LLVM coercions.

The C++ producer applies ASTContext::getExceptionObjectType: array/function decay
and removal of top CV after expression reference normalization. Pointer payloads
require a complete pointee except cvvoid; pointers to functions remain valid.
Abstractness, accessible constructors/copies/destructors and target-specific
source diagnostics remain actual Sema obligations. A complete pointer-sized
object alone does not prove its pointed-to class is throwable. Runtime allocation
size/alignment must match the checked payload; construction/destruction recipes
and ownership are separate joins, not inferred from POD or equal bytes.

## Logical calls and variadics

Apply ABI-P1 before emission: scalar/complex/vector direct values; record/union
arguments fresh indirect copies; record/union result leading hidden sret pointer
and zero logical results. Nontrivial C++ construction/destruction and exceptional
cleanup follow explicit source lifetime records. References and this are guest
pointer arguments; sret precedes this, optional VTT follows this. Native byval,
inreg, preallocated, inalloca and target calling convention attributes are not
silently reinterpreted. The current policy maps calls to explicit logical execution/ABI/EH recipes; candidate signatures, regions, construction journal and imported helpers are verified together before freeze.

Frontend default argument promotions precede typed vararg arena formation.
`va_list` is the ABI-owned32 B {area,cursor,limit,cookie} object, not a host
BuiltinVaListKind chosen for convenience. Clang requires a dedicated va_list
construction/EmitVAArg implementation and va_start/va_copy/va_end lowering.
Checked type identity, alignment, bounds, activation/thread lifetime and cursor
commit must agree with ABI fixtures. No foreign native va_list crosses directly.
Execution signatures are fixed arity, variadic=false, with arena:data_ptr then
bytes:u64 as noundef suffix; source variadic classification stays in its ABI
signature. Exported source cc/noundef contracts do not change when an optimizer
infers stronger local attributes. Function abi_signature names call_signature;
that descriptor's function_type names the source nominal type.

Generic Itanium member-function pointers require even nonzero runtime function
tokens, leaving low bit for virtual dispatch; data-member null is signed -1.
Linker/admission checks signature and module generation. Source C++ ABI settings,
libc++ site configuration, exception/RTTI policy and sysroot content hashes belong
in the module compatibility identity. Windows host macros must not select an
LLP64/MSVC portable ABI accidentally.

## Macros, libraries and gaps

Target macros must identify SMIR and the portable data model, including
`__SMIR__=1`, `__SMIR_POINTER_WIDTH__=64`, `__LP64__=1`, exact scalar widths,
little-endian order and the compiler's proper binary128 long-double limits.
These symbolic macros are draft compiler-interface proposals, not currently
published definitions. Do not define __x86_64__, __aarch64__, __linux__, __APPLE__,
_WIN32 or _WIN64 solely from the host or selected personality. Personality
selection uses explicit imports and a dedicated sysroot configuration.

A pinned source checkout is not a built hosted sysroot. The five required source
components are LLVM libc, compiler-rt builtins, libc++abi, libc++ and libunwind.
The selected libunwind component requires the dedicated RAX logical-SMIR/private-EH
source adaptation specified in [integration.md](integration.md), preserving the
existing ABI site and `rax_logical_libunwind` identity. TLS/thread/fenv/setjmp
adapters and library ABI configuration also need target ports. OS-service imports
in the runtime catalog are distinct from compiler-internal checked memory/atomic/FP/EH
helpers. Target-specific assembly requires a replacement or diagnostic. Soft-FP
helper names such as __addtf3 alone do not define NaN, rounding, guest fenv or
exception behavior.

`upstream-gaps.json` is generated from primary upstream status tables. Preserve
paper identifiers, original status text and notes: a partial recommended practice
is not automatically a mandatory language-conformance failure. Examples include
Clang's documented P0533R9 constexpr-math gap and libc++'s stacktrace/P0533R9
status. These gaps are upstream; missing SMIR target, sysroot and adapters are
port gaps. All-six-host library qualification remains unrun.

CC-L superseding bindings: frontend-contract.json fixes predefines/driver/metadata choices; ABI-CC013 appends exact varargs arena+byte-count parameters, va_start(list,arena,bytes); ABI-CC010 routes atomic_flag through dedicated lock-free helpers rather than ordinary bool operations. Source fenv follows accepted INT-D009 / INT-010 revision2; source macro values never come from host headers.

C/C++ source linkage is independent from translation language. Emit actual C
language linkage for extern"C" declarations and preserve C++ overload/nominal
identities. A C-built libc provider and C++ caller require an admitted C boundary
compatibility projection; equal object layout alone is insufficient. The new
c-linkage.h/.c/.cpp witnesses compile matching explicit existing-target record
geometry and C symbol names, retain C++ overload mangling, and link/run on the
current host. This is neither a portable TargetInfo nor an automatic structural
nominal-identity rule; the ABI-owned cross-language contract governs admission.

The pinned function-TYPE gap is executable evidence: cxx-linkage-types.cpp asserts
that Clang reports C/C++ function typedefs equal while keeping wchar_t/charN types
distinct from integer counterparts. Function declaration linkage/mangling is still
observed separately. This documents the frontend behavior; no uncaptured ISO clause
or portable support for linkage-type-only overloads is asserted. ABI030's explicit
boundary view, eligible C-header mirrors and source flags must be verified by the
combined source ABI adapter before accepting C-provider/C++-consumer modules.

The source object extent limit is2^61-1 B: multiplying by8 bits/B yields
2^64-8 bits, within u64 extent metadata; the next byte count reaches2^64 bits.
Pinned SemaType/ConstantArrayType checks independently cap source array addressing
size at61 active bits for size_t64. Canonical runtime storage uses array<raw8,N>
with u64count even atN0; source logical SSA/nominal type is separate from these
allocation bytes. Source size/layout definitions must fit this bound before
publication. Raw MMU mappings retain their separate64-bit byte-range contract.
