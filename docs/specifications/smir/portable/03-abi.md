# Portable C/C++ ABI

Status: **candidate compiler contract for envelope0.2/profile2; not globally frozen**.
The ordered [ABI payload grammar](schema/abi/candidate.json), root `abi_contract`,
is mandatory section10. `tools/smir-abi/candidate.py` verifies this section using
actual admitted execution/layout/symbol/dependency roots and independent native
certificates. Successful reference verification returns
`admitted_for_execution=false`; it does not install a production executable.
The older [layout](schema/abi/layout.schema.json) and
[descriptor](schema/abi/descriptor.schema.json) JSON transports remain isolated
historical models. They cannot replace section10 or semantic module admission.

ABI-001: The target data model is LP64, little-endian, with 8-bit bytes. All
quantities below are exact integers; B denotes bytes, not bits.

| Source type/property | Value bits | Storage B | ABI alignment B |
|---|---:|---:|---:|
| bool, char, signed/unsigned char, char8_t | 1 for bool, otherwise 8 | 1 | 1 |
| short, unsigned short, char16_t | 16 | 2 | 2 |
| int, unsigned int, wchar_t, char32_t | 32 | 4 | 4 |
| wint_t (unsigned) | 32 | 4 | 4 |
| long, unsigned long, long long, unsigned long long | 64 | 8 | 8 |
| pointer, reference representation, nullptr_t, size_t, ptrdiff_t | 64 | 8 | 8 |
| float, double | binary32, binary64 | 4, 8 | 4, 8 |
| long double | IEEE binary128 | 16 | 16 |
| __int128, unsigned __int128 extension | 128 | 16 | 16 |
| data-member pointer | signed64 offset | 8 | 8 |
| member-function pointer | two signed64 words | 16 | 8 |

Plain char and wchar_t are signed; char8_t/char16_t/char32_t and size_t are
unsigned. wint_t is unsigned32 and WEOF is0xffffffff; every Unicode scalar is
distinct from WEOF. This dedicated-sysroot choice is independent of personality
(INT-006/ABI-P8), with no claim of native wide-I/O compatibility.
ptrdiff_t is signed. Integers are two's complement, without traps.
Bool stores 0 or 1; a typed load of another representation is a semantic invalid
value, not a host-dependent truth conversion. Null ordinary/code pointers are
all-zero. Data-member null is the separate -1 representation below. Reference
objects cannot be null in source semantics even though their ABI word can encode
zero. Qualifiers do not change size/alignment. No host OS macro changes this
model. A language pointer value is a guest address/token, never a host pointer.

## Scalar extensions, enumeration and aggregate layout

Let `RU(x,a) = a * ceil(x/a)`, where x and a use the same unit. Every alignment is
a power of two. Explicit object/member over-alignment through 65536 B is
supported; larger requests produce an explicit target diagnostic. Implementations
must reject source object extent greater than 2^61-1 B and checked-address overflow;
the corresponding bit extent is at most 2^64-8 bits. This source compiler limit
does not reduce the separate raw guest address-space bound of 2^64 B.
there is no wraparound layout. Stack call boundaries align to 16 B; an
individual alloca with greater alignment adjusts its own storage. No red zone.

For `_BitInt(N)`, unsigned N is 1..65535 and signed N is 2..65535:

```text
q = ceil(N / 8) B
A = min(8 B, next_power_of_two(q))
S = RU(q, A)
```

Only the low N bits carry value, signed at bit N-1. A typed N-bit store writes ceil(N/8) bytes and zeros unused bits in its final
access byte; it preserves the allocation tail beyond those bytes. Canonical
varargs packing instead zeros all nonvalue payload bits across sizeof(T). Byte
copies preserve object bytes. These three operations have distinct footprints. `_BitInt(65)` has q=9 B, A=8 B, S=16 B.
`{char a; _BitInt(65) b;}` places b at RU(1 B,8 B)=8 B, then has size
RU(8 B+16 B,8 B)=24 B. `_BitInt(128)` has alignment8 B, distinct from
`__int128` alignment16 B. LLVM's natural `i65..i128` layout cannot be used as an
unannotated source object representation. The frontend must use explicitly sized
byte storage and source ABI alignment, loading/storing N value bits.

Unfixed C/C++ unscoped enums select the first type in this ordered list that
represents every enumerator: int, unsigned int, long, unsigned long. Values
outside those ranges reject. C++ scoped enum without an explicit base uses int;
the frontend records that fixed base. Fixed enums use exactly their declared
integer base (including permitted bit-precise bases); out-of-range enumerators
reject. Bool is a permitted fixed C++ base with value range0..1. No short-enum
flag. This signed-first policy is a deliberate frontend decision; a native
Clang target's signedness choice is not an oracle for it.

`_Complex T` stores real followed by imaginary, no intervening padding, size
2*sizeof(T), alignment alignof(T), for T=float/double/long double. Fixed extension
vectors use arithmetic scalar elements (integer widths8/16/32/64 or
binary32/64), lane0 at the lowest address. For n lanes, size and alignment equal
the next power of two of n*sizeof(element), at most64 B. Three int32 lanes thus
occupy16 B with a padding lane that has no value semantics. Bool, bit-precise,
pointer, scalable and ISA-specific predicate vectors are outside this source ABI
and require diagnostics; execution types may have a wider internal domain.

Arrays use element stride sizeof(element), element alignment, and checked count
multiplication. Parameter arrays/functions undergo normal language adjustment
before ABI classification; a raw array/function is not an ABI parameter value.
C variable-length arrays use the same checked runtime multiplication and
alignment; a nonpositive bound is a semantic invalid bound. A flexible array is
C-only, final in a nonunion record with a preceding named member; its offset
is naturally aligned and contributes zero element extent, while its alignment
contributes to record alignment. It cannot be nested as an ordinary member or
array element. ABI2 preserves anonymous member grouping in source_field_decl;
selected direct outputs use $anonymousN and paths traverse that exact component.
Source-visible member lookup may flatten by walking those typed source edges.
The earlier standalone JSON layout model's flattened-input restriction is not
an executable ABI2 rule.

A record places each ordinary member at `RU(cursor, member_alignment)`, updates
cursor to the member end, and ends at `RU(max_extent, record_alignment)`.
Record alignment is the maximum member and explicit alignment. Unions place each
member at offset0 and use the maximum extent. Arrays/ordinary members do not reuse
another ordinary member's tail padding. The layout-schema member `align` is
optional; absence means no alignment increase. Empty C++ class/union size is at
least1 B; ISO C empty/all-unnamed records reject. Scalar object storage with alignas may
have greater allocation alignment without changing sizeof(T); member/record
alignas participates in the enclosing record extent. Packing, ms_struct,
short-enums, native vectorcall and target-specific ABI layout attributes require
explicit diagnostics in this baseline, not silent host inheritance.

`_Atomic(T)` for complete C object type T with size <=16 B rounds size up to a
power of two and uses at least that alignment; larger T retains its size and
alignment. Nested atomic, array and flexible-member T reject. C++ std::atomic
layout is library-defined and pinned with its sysroot. Layout is independent of lock freedom. Generic portable atomic queries report
false; the separate1-B atomic_flag protocol is always lock-free. All source atomic
extents use guarded shared-backing transactions, including large aggregates;
`full_storage` C operations compare/copy every storage byte, while C++ value
comparison uses the admitted source value mask. LLVM precision operations preserve
their specified bit width and physical access footprint. The immutable helper
catalog selects exact storage bindings; no size query identifies atomic_flag.
The runtime reference is a contract witness, not production parallel execution.

## Bit-fields

Fields allocate from low to high bits within little-endian bytes. Let p be the
next available bit offset, w the field width, S the declared type storage bits,
and A the declared type alignment bits. If w=0, or `(p mod A)+w>S`, move p to
`RU(p,A)`; otherwise use p. Allocate w bits and retain the next-bit cursor, but
ordinary members start at the next whole byte. Unions start each field at bit0.
Named fields raise record alignment to the base alignment; unnamed fields do not.
A zero-width field must be unnamed, raises no record alignment, and acts as an
alignment barrier even at the start. Enum fields use their fixed/chosen base.
C bool widths0..1 only; C fields cannot exceed their value width. Alignment
specifiers on bit-fields reject. Volatile accesses must not touch unrelated
non-bit-field storage; the frontend chooses bounded accesses rather than treating
the notional containing unit as an unconditional load/store footprint.

For C++ fields wider than sizeof(base)*8, select the largest integral container
of size1/2/4/8/16 B with size*8 <= w; begin at its alignment after the previous
allocated byte, allocate w bits, and raise record alignment to that container.
Only the underlying type's value bits carry value; excess bits are padding.
`unsigned char a:20; char b;` places b at byte3 and has size4 B/alignment2 B.
This generic Itanium rule is not Microsoft's storage-unit rule.

ABI-002: Portable calls use logical typed arguments, not architectural registers.
Their source-to-execution lowering is deterministic:

| Source value | Parameter lowering | Result lowering |
|---|---|---|
| scalar, pointer/reference, enum, complex, fixed vector, member pointer | one direct typed value | one direct typed value |
| record or union, including one-field/empty/trivial types | pointer to fresh caller-owned copy | first hidden result-storage pointer; zero direct results |
| nontrivial C++ record | pointer to caller-constructed copy/move temporary | callee constructs in hidden result storage |
| void | no parameter | zero results |
| source array/function parameter | adjust to pointer first | source-language result restrictions apply |

No size-based splitting, aggregate-to-integer coercion, homogeneous FP register
classification or empty-record elision. IR aggregate SSA values may still exist
inside a function; call ABI classification is a separate pass. Formal order is
hidden result (if any), this (if any), VTT (if required), fixed parameters, then
variadic arena pointer and u64 arena byte length (if any). Constructor/destructor variant and VTT
requirements follow the C++ ABI below. No physical callee-save register set.

Trivial argument copies are independent from the source object and other
by-value arguments. Their internal padding may be copied as bytes. For
nontrivial arguments, construction completes before callee entry; a failed
construction unwinds only the completed temporaries. The caller destroys those
temporaries after normal return or exceptional completion, in language cleanup
order. Record-result storage has the exact size/alignment and remains leased
through the call. The callee establishes a completed-construction flag only on
successful return; exceptional partial construction runs its own member/base
cleanups. The caller subsequently destroys a successfully constructed result.
Do not infer LLVM noalias for arbitrary other pointer arguments without a source
proof. Copy elision follows source-language rules and does not invent extra
constructors/destructors. References retain object identity; lifetime extension
is a source decision represented explicitly in cleanups.

## Variadic arguments

The portable `va_list` is an array-of-one wrapper around this32-B,8-B-aligned
record; parameter adjustment therefore passes its address. Its four u64 words
are area guest address, cursor relative offset, arena byte limit and activation
cookie. `va_copy` duplicates cursor state; it does not copy/release the arena.
`va_end` zeros all four words. Empty packs have limit0 and cannot yield an arg.
The arena base has alignment equal to the maximum entry alignment (at least8 B).

| Entry field | Offset B | Type |
|---|---:|---|
| canonical promoted type declaration | 0 | caller table-local u32 nominal declaration ID |
| reserved zero | 4 | u32 |
| payload storage size | 8 | u64 |
| payload alignment | 16 | u64 |
| next entry relative offset | 24 | u64 |

At entry e, payload starts at `RU(e+32 B,alignment)` and next is
`RU(payload+size,8 B)`. Inter-record padding is zero. The entry ID indexes the admitted caller's promoted nominal declaration table.
The module identity is retained in the arena registry, not squeezed into that
u32. Consumer declarations map explicitly to provider-private IDs; equal integers
from different modules do not establish equality. Rooted execution shape equality
cannot substitute for source nominal compatibility. The arena/backing/module lease
retains that table for the entire active va_list lifetime. Metadata does not encode a native
host va_list or pointers to host register-save areas.

Frontend default argument promotions apply before packing: ordinary narrow
integers/enums according to language rank/range, float to double, no promotion of
long double; C23 bit-precise types retain the language-mandated bit-precise
promotion behavior. _Complex float is not promoted to _Complex double. Nontrivial
C++ objects through ellipsis receive a diagnostic. Calling through an incompatible
variadic prototype rejects at admission where statically detectable.

`va_arg` checks live thread/activation cookie, arena lease, cursor/header bounds,
reserved bits, registered size/alignment, absolute alignment, checked next offset,
zero inter-entry padding and nominal compatibility before updating cursor.
Exact type match includes frontend-canonicalized compatible types. The permitted
corresponding signed/unsigned exception additionally checks that the value fits
both ranges; void*/character-pointer interchange is recognized. Other mismatches
trap `ABI_VARARG_TYPE_MISMATCH` with unchanged cursor. Exhaustion, stale copies,
mismatched owner identity, revocation and corrupt metadata trap before any cursor update.
Canonical bit-precise payload padding is checked. Nonlocal exit revokes the
abandoned activation cookie; all surviving copied lists then fail. Foreign varargs
use generated typed-pack bridges, never reinterpret this representation.

The cookie identifies the ORIGINAL variadic owner thread/activation/generation
in the process registry. It does not require the executing visitor to have that
identity. A synchronized visiting function or logical thread may use a source
list while its original owner, backing and nominal table remain live. The runtime
helper resolves that owner from the actual cookie registration. Shared cursor
mutation requires source synchronization; va_copy provides an independent cursor
with the same owner and arena. Owner return/unwind revokes all copies. Copying a
list into a fixed-parameter coroutine's ordinary32-B frame storage does not extend
that lifetime or retag its cookie. The opaque execution va_list handle remains
distinct and cannot be spilled as ordinary source storage.

ABI-003: Portable C++ uses GenericItanium layout/mangling/RTTI at the pinned LLVM
revision, with the following fully selected configuration and deviations.

| Configuration | Portable choice |
|---|---|
| Clang ABI compatibility | Latest enumerator at LLVM36763294ef639d8a6a4379d81da653dda1c20686; immutable pin |
| Object/class layout | ItaniumRecordLayoutBuilder + EmptySubobjectMap at that pin |
| Method/data member pointers | generic Itanium, no ARM method-pointer discriminator |
| Guards | 8-B guard; generic Itanium guard ABI, first-byte initialized test |
| Vtables | absolute8-B function tokens; no relative-vtable mode |
| Mangling | pinned ItaniumMangleContext; source identities qualified by module/library ABI |
| RTTI | pinned ItaniumRTTIBuilder; guest data relocations; no host type_info pointers |
| Standard library | libc++ ABI version1, namespace __1; no unstable ABI flags |
| Data-model deviations | table above, signed-first enums, BitInt align8, explicit portable call classification |
| Native-target features | no ARM/Apple/Microsoft ABI heuristics, authentication tags or ISA feature attributes |

The exact layout algorithm is source-defined by archived
`references/llvm-project/clang/lib/AST/RecordLayoutBuilder.cpp` at the pin, not by
whatever compiler happens to run the build. Nonvirtual bases follow declaration
order, dynamic primary base selection follows the pinned algorithm, virtual bases
use its deduplicated traversal, empty subobjects respect same-type address
conflicts, non-POD base tail padding and `[[no_unique_address]]` follow the pinned
rules. Public/private access does not change byte layout. Complete/base object
sizes, nonvirtual size/alignment and each base offset are distinct metadata;
no inference from sizeof alone. The ABI2 independent record_layout model implements
primary/nonvirtual/virtual placement and EmptySubobjectMap over checked source
facts. Its pinned existing-target corpus currently compares28 source records,
all five size/alignment/data/nonvirtual reports and direct field offsets. These
finite comparisons do not qualify complete C++ dispatch/RTTI/constructor metadata
or native execution. Required typed VB targets and full selected dispatch/VTT/
RTTI materialization remain explicit compiler-freeze blockers; no record proof
issuer opens from this geometric witness alone.

Data-member pointers are signed64 byte offsets from the adjusted object; null is
-1. Conversion can produce the Itanium negative-offset null collision and must
retain its ABI-defined representation rather than reinterpret null as zero.
Member-function pointers are `{ptr:i64,adj:i64}`. ptr=0 is null regardless of adj.
Even nonzero ptr is an admitted code token; odd ptr encodes a vtable byte offset
plus1. Adjust this by adj, then perform the admitted direct call or vtable lookup.
No ARM bit in adj. A data/code token cannot be forged by reading a vtable from an
unregistered object. The admitted code-token allocator must supply nonzero/even tokens; odd words
remain virtual-member tags. Production enforcement belongs to runtime admission,
so a reference layout result alone cannot execute a member pointer.
Vtable prefix offsets and RTTI use guest64-bit pointers/ptrdiff_t; vtable slots
store code tokens that resolve through the runtime, never host return addresses.

RTTI symbols/layout, virtual thunks, covariant returns, construction vtables,
VTT parameters, deleting/complete/base destructor variants, guard synchronization,
array cookies and exception allocation follow pinned ItaniumCXXABI and
VTableBuilder with these fixed target choices. Array-new cookie stores element
count in the final8 B before the element array when required by that algorithm;
allocation/header padding preserves element over-alignment. Global operator new
minimum alignment16 B, larger alignments use aligned overloads. Allocation failure
returns null only for nothrow overloads; ordinary new throws bad_alloc in the
portable C++ domain. Owner-domain deallocation is mandatory across adapters.

libc++ configuration includes no Apple alternate-string layout, no Microsoft ABI
force, no unstable/experimental ABI options, no bounded-unique_ptr ABI flag.
Site configuration, hardening mode and all ABI-affecting macros are part of the
sysroot/library identity; library ABI version1 alone is insufficient evidence.
The exact selected CMake options, defined/undefined site macros, external thread
API, hardening=none and logical-libunwind backend are in
[schema/abi/site.json](schema/abi/site.json); site identity hashes the complete
manifest, not merely ABI version1. Options describe the port to implement, not a
claim that unmodified upstream builds for SMIR. Actual library compilation,
linking and conformance remain later implementation gates.

ABI-004: Each guest thread owns TLS/error/fenv/exception state and its activation
stack; no host TLS default stands in for it. The call ABI preserves its TLS base,
portable errno, personality error cells, FP control/status, current exception and
cleanup state through nested callbacks. State is saved before foreign entry and
restored at its explicit continuation, including traps/unwind. TLS address
stability is bounded by thread and module leases, with dynamic initialization
once and destructor/module teardown ordering specified by runtime. There is no
portable host register or Rust unwind frame in this serialized state.

ABI-005: Compile a dedicated SMIR sysroot; host headers, precompiled modules,
std::va_list, platform wchar/long typedefs and inline ISA assembly are not reusable
ABI evidence. First-wave commands from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/smir-abi/check.py \
  --output /tmp/rax-portable-smir-01/ABI/check
python3 tools/smir-abi/layout.py docs/specifications/smir/portable/conformance/abi/layouts.json
python3 tools/smir-abi/witness.py --output /tmp/rax-portable-smir-01/ABI/witness
```

`SMIR_ABI_CLANG` may select an equivalent pinned binary; mismatched revision or
missing compiler is a failure, not a skip. The witnesses compile header-free C23
and C++23 for six existing triples. Only explicitly comparable subsets are
compared to portable equations. A native target's same-sized va_list, C++ class
or BitInt does not establish equivalent semantics. Layout witnesses do not execute their output or compile for an implemented SMIR
TargetInfo. A separate host C++ witness does execute constructor/catch/exception_ptr
and atomic_flag cases; it does not run SMIR or a foreign CPU adapter.

## Executable metadata, identity and physical storage

The schema's field order is the binary order. Common encodings are fixed-width
little-endian integers; bool byte0/1; token u8 length1..63 followed by ASCII
`[a-z][a-z0-9_]*`; utf8 u32 byte length and strict shortest UTF-8; digest32 exactly
32 bytes; hex u32 byte length plus those bytes; vectors u32 count plus elements.
Optional values encode byte0 for absent or byte1 plus payload. The JSON view is
`null` or the exact wrapper `{"some": VALUE}`, including nested options. No
implicit defaults, unknown fields, duplicate IDs, trailing bytes or host pointers.
`module_ref` is self{} or dependency{slot:u32}; qref is {module,id:u32}.
Current roots1,2,3,5 begin payload_revision:u32=2; roots4,6,7,8,9
retain payload_revision:u32=1; ABI root10 begins payload_revision:u32=3. Whole-object codecs check the raw firstu32LE before
revision-dependent decoding; old revisions reject WIRE-REVISION with no implicit upgrade.
Envelope0.2/profile2 is unchanged. Preserved ABI2 bytes are historical rejection
controls, separate from source-generated current semantic counterparts.
Independent C++ and Python codecs
check the same ordered grammar, with separately implemented parsers.

| Namespace | Section10 table | Semantic obligation |
|---|---|---|
| nominal | types | source identity/kind/layout; complete values need layout |
| signature | signatures | source function_type plus exact lowered parameter/result types |
| storage_binding | storage_bindings | exact source view to section1 physical layout |
| bridge | bridges | admitted foreign endpoint and conversion/lease protocol |
| recipe | recipes | typed conversion/cleanup action CFG |
| journal | journals | source owner signature, explicit capture params and subobjects |

Namespace selection comes from the consuming field or immutable helper/contract
catalog. A numeric ID never selects a table. Dependencies use admitted typed
consumer-declaration to provider-private maps; no artifact-hash cycles or implicit
highest-version winner. A library family is (namespace,name,ABI major). Actual
provider and compilation-baseline minor versions each satisfy the declared
inclusive range. Source internal/local identity additionally uses this family
and a stable translation-unit UID:

```text
SHA256("rax.source.unit.v1\0" || u32len(ns)||UTF8(ns)
       || u32len(name)||UTF8(name) || u32len(project_unit_key)||UTF8(project_unit_key)
       || ABI_major:u32LE)
```

Absolute POSIX/drive/UNC paths reject; no Unicode/path normalization. External and
odr_local identities have no TU UID. Runtime artifact/object/code generations and
leases remain separate authority. Pointee and prototype class/enum references are
nominal declaration leaves; their completeness in another translation unit does
not change the enclosing ABI. By-value fields/bases retain complete definitions.
Definition hashes use a rooted labelled bisimulation quotient with ordered edges,
root-first BFS numbering and canonical sorted compact ASCII JSON, prefixed by
`SMIR-NOMINAL-SHAPE-V3\0`. Labels contain stable source/site/layout information;
compiled body/symbol IDs and graph-sharing accidents are excluded. Execution
shape uses its separate `SMIR-TYPE-SHAPE-V1\0` identity and conveys no source or
object authority. Enum metadata records ordered names and canonical base-width
value bytes. `fixed_base` selects an explicit base; `scoped` implies fixed.
Empty C++ enums are valid; unfixed empty enums select int. Duplicate values are
valid; duplicate names reject. nullptr_t uses a data_ptr execution shape with
source semantics restricted to null values.

Function source linkage is explicit: both declarations carrying `c_linkage`
select the C compatibility projection. Eligible trivial `c_compatible` records
and enums may cross C/C++ language dialects, including the specified C character
typedef projections; ordinary C++ overload and type identities remain distinct.
Data symbols use separately verified `source_linkage=c` and
`data_boundary_compatible`: the provider supplies complete storage, while an
incomplete consumer object declaration permits taking its address only.
Transparent size_t, ptrdiff_t and wint_t aliases select their canonical builtins.
Constructor identities name the constructor kind, not printed type spellings.
Reference types require exactly one `lvalue_ref` or `rvalue_ref` flag, retaining
T& versus T&& despite identical pointer storage. Function types allow zero or
one of these flags for member-function ref-qualification; zero means unqualified.
Other kinds and C-linkage functions reject them. Existing function qualifiers
retain member const/volatile. These distinctions participate in nominal identity.
An actual call plan for a ref-qualified function requires an explicit hidden
this parameter; an unbound qualified function type does not create one implicitly.

Source call boundaries carry a SELF-local `abi_signature` reference in addition
to nominal type. `NominalGraph.signature_compatible` compares the complete
lowered plan: explicit arguments/results, hidden this/VTT/sret, by-value
temporary size/alignment, noundef, varargs protocol, and copy/move/destruction
recipe interfaces. Local IDs and compiled recipe bodies do not establish ABI
compatibility. Nested nominal dependencies remain module-qualified; foreign
native functions and internal primitive services have no source call signature.

`Function.abi_signature`, when present, associates the actual function entry with
its source `CallSignature`. Both ordinary functions and method entries retain
their ABI-verified lowered this/VTT/sret parameters, exact FullFn arity, nominal
execution types and noundef bits. Hidden roles do not become explicit source
parameters. This entry association grants no ordinary source-call or callable
address permission; those boundaries and reference-execution profiles apply
their own admission checks. Source noexcept, body `Function.escape` and
`Function.no_return` remain separate contracts. SourceProgram lifecycle joins,
incoming aliases, current scopes/Journals and exception protocols require their
own verification and runtime implementation.

An `object_layout` is the source allocation. A section1 execution_memory_layout
is the physical IR storage; a `storage_binding` explicitly relates a source view,
required alignment, byte access footprint and ordered bit fragments to it.
Fragments name source member paths and roles value/padding/base/vptr. Value bits
must be covered exactly once, padding cannot hide a value, and source/destination
positions cannot silently repack an aliased object. Repacking requires an adapter.
A source `_BitInt(65)` is16 B/alignment8/access9; an anonymous internal i65 may use
a different physical allocation/alignment. Internal packed records, coroutine
slots and arbitrary LLVM temporaries need no fabricated source nominal type.
Memory/LLVM helpers select optional storage_binding plus required physical target;
source full_storage/value_mask/c_fenv operations require that binding. The flag
helper independently requires nominal atomic_flag and its fixed1-B state.

An initialized source allocation uses physical `array<raw8,N>`, including N=0
for anonymous zero-length storage, with byte stride8 bits and physical alignment
1 B. Source instance alignment is checked separately. An `allocation` binding
covers the complete object representation with one identity fragment; it has no
static logical value mask and cannot satisfy typed source value operations.
Anonymous storage has neither nominal nor ABI binding. Source object size is
positive; `new T[0]` creates no T objects. Typed views must preserve adjacent
source value bits outside their exact access interval. Reference SSA/resource
quotas do not impose smaller language object extents.

All execution call signatures are nonvariadic with exact arity. A source variadic
signature has hidden suffix `(arena:data_ptr,bytes:u64)`, both noundef. At entry,
the runtime checks the registered arena extent/table/backing generation, then
mints the callee thread/activation cookie. Source va_start receives list,arena,
bytes; va_copy dst,src; va_end list; va_arg<T> list. The varargs_pack helper selects
the exact source call_signature and a typed recipe. Its input entries are32 B:
nominal declaration:u32, reserved0:u32, source address:u64, bytes:u64, alignment:u64.
Only the recipe's admitted promoted operand types/addresses may be packed.

## Private portable C++ exception contract

The selected site uses SSA-only exception values. Compiler-constant lexical
exception slots must be eliminated before optimization, LTO and final emission,
including O0. Exception values cannot inhabit ordinary memory, runtime cells,
integer casts or guest pointer fields. Native __cxa pointer/header conventions
belong to a foreign adapter or separately admitted extension.

Portable `std::exception_ptr` is exactly8 B, alignment8 B, with one guest data
pointer to a canonical process owner proxy. The readonly proxy is32 B,
alignment8 B: revision:u32=1, reserved:u32=0, proxy_id:u64, payload_id:u64,
generation:u64. Registry object identity, origin and live generation grant
authority; copied proxy bytes do not. Null is allzero. Current-owner acquisition
retains once from the top active catch, or returns null. Copy retains before
publication; assignment acquires before releasing; move transfers pointer and
provenance and nulls its source. Final release destroys the constructed owner
once, outside registry locks, before freeing it. Cross-thread rethrow creates a
fresh thread-local facade while retaining the original payload and module.
`make_exception_ptr` follows throw/catch/current-owner, without a native header
fast path. `_LIBCPP_ABI_RAX_EXCEPTION_PTR=1` identifies this dedicated library
port; the site manifest hashes these semantics. Native same-sized library
objects require an exact owner/library descriptor adapter.

Completed-object certificates describe currently live child lifetimes, not
constructor history. Destruction claims a fresh journal on its actual thread;
beginning destruction ends ordinary lifetime while its destruction capability
remains valid through cleanup. Transparent replacement may forward an eligible
old pointer to a new lifetime, but never revives the old certificate.

## Floating environment and source/runtime obligations

| Type/object | Size B | Alignment B | Exact representation |
|---|---:|---:|---|
| fenv_t | 32 | 8 | u32 version1,round,flags,traps0; u64 control0,reserved0 |
| femode_t | 16 | 8 | u32 round,traps0; u64 control0 |
| fexcept_t | 4 | 4 | u32 sticky flags |
| __rax_default_fenv | 32 | 8 | readonly guest object: version1, other fields0 |
| __rax_default_femode | 16 | 8 | readonly guest object: all fields0 |

Snapshots copy across guest threads; they contain no thread handle. Execution
fenv is the typed copyable snapshot; source fenv_t is its exact opaque memory
encoding. Default macros use ordinary guest data relocations/provenance, never
pointer-minus-one sentinels. Ambient rounds: nearest-even0, down0x400, up0x800,
toward-zero0xc00. Nearest-away is per-operation only. Sticky bits: DIVBYZERO1,
INEXACT2, INVALID4, OVERFLOW8, UNDERFLOW16, DENORM32, ALL63. DENORM is explicit
sticky state only, never an arithmetic diagnostic. The VM's separate five-IEEE
bit diagnostic policy is not captured, restored or cleared by source snapshots.
Flags accrue before a diagnostic stop; its normal result is uncommitted. Restore,
mode/setexcept/setexceptflag do not raise; raise/update apply the private policy.
Hold saves/clears flags while preserving that policy. Invalid snapshot/mask/mode
fails without partial state change. Portable errno is a separate per-thread cell,
0 or positive pinned LLVM/Linux errno domain as specified by runtime services.

## Provenance, assumptions and gate limits

[Legacy sources](schema/abi/sources.json) and
[candidate sources](schema/abi/candidate-sources.json) identify primary LLVM
oracles and exact hashes. All are archived through the integrator with source
revision, license and checksum; the candidate archive bytes were also compared
to exact pinned git objects. The selected source algorithms are project contracts,
not claims that ISO requires these representations. Native compiler profile
snapshots remain observed layouts, distinct from independent equations.

| Assumption | Dependent result | Stress/falsification probe | Current status |
|---|---|---|---|
| ABI-A1: candidate wire/namespace decisions are integrated consistently | section10 consumers | shared-record mismatch, wrong-table IDs, stale schema hashes | independent codecs and cross-role ACKs; integrator owns global freeze |
| ABI-A2: existing targets witness comparable subsets | native layout evidence | LP64/LLP64, BitInt/quad/member-pointer divergence | explicit target differences retained |
| ABI-A3: native certificates come from separately admitted compiler/image evidence | foreign boundaries | absent/mismatched type/build/CFI certificate | reference rejects; fixture authority is synthetic |
| ABI-A4: execution/layout resolvers derive actual admitted roots | source-to-IR binding | producer identity strings, anonymous storage, same-number IDs | actual RootContext and independent shape tests |
| ABI-A5: bounded reference resources are not language-size limits | large types/arenas | quota boundary and streaming implementation | explicit deterministic reference rejection; production allocation policy separate |

High impact: source graph sharing/completeness and multiple storage views can
cause false compatibility or false rejection unless normalized/selected explicitly;
regressions cover both. High impact: guarded aggregate atomics and lock-free flag
have different progress requirements; generic atomic overlap with a live flag
rejects. Medium impact: native Microsoft profile differences need exact per-build
certificates, including rejected wide bit-fields/no_unique_address differences.
Low impact: same-size native records are useful negative examples, not proof of
portable compatibility.

The reference bounds include4096 nominal graph states,1 MiB materialized value
masks,8 MiB ordered payloads,10000 vector elements,200000 decode nodes and128
nesting levels. Exceeding a bound is an explicit resource error, never success or
silent truncation. Nominal quotient worst-case time O(V*(V+E)logV), space O(V+E);
layout graph evaluation O(V+E), materialized masks O(object bytes+members). C++
inheritance layout follows the pinned source algorithm; independent hand-derived
and compiler witnesses cover strategic cases rather than exhaustively proving
that algorithm. No production frontend, hosted library, native bridge, parallel
runtime or JIT is claimed by this contract package. Those are subsequent gates;
the integrator alone decides whether the combined compiler contract is frozen.


## Source declaration input and selected layout (introduced in ABI2)

Accepted INT030REV2 introduced ABI payload2 with source input revision1. ABI3
retains that input and appends mandatory call_signature.execution. The current
ordered grammar is schema/abi/candidate.json; independent candidate_schema.py
and candidate_records.inc encode the same records. Current root revisions are
listed above. Old ABI1/ABI2 whole objects reject WIRE-REVISION before changed record interpretation;
partial codecs are syntax tools without semantic/execution admission. Archives
preserve old source/bytes/receipts; no missing input is inferred from old offsets.

```text
source_field_decl = name:opt:utf8,type:qref,bit_width:opt:u64,
 explicit_align:opt:u32,no_unique_address:bool,anonymous:bool,access:token
source_base_decl = type:qref,virtual:bool,access:token
record_layout_input = revision:u32(1),kind:token,explicit_align:opt:u32,
 pod03:bool,trivial:bool,standard_layout:bool,polymorphic:bool,dynamic:bool,
 empty:bool,fields:vec:source_field_decl,bases:vec:source_base_decl
nominal_type APPENDS record_input:opt:record_layout_input
field_layout = declaration_index:u32,name:utf8,type:qref,offset_bits:u64,
 width_bits:u64,flags:vec:token
base_layout = type:qref,offset:u64,virtual:bool,declaration_index:opt:u32,
 origin_path:vec:u32,adjustment:adjustment
vptr_layout = offset:u64,offset_top:i64,rtti:opt:qref,slots:vec:qref,
 vcall_offsets:vec:i64,vbase_offsets:vec:i64,component_order:vec:token
```

Complete portable records require actual source input; other kinds and incomplete
records have None. Accepted ABI040REV3 also requires every portable non-record
layout to have empty fields, bases and vptrs. Function and void types have no
object layout in every domain. Incomplete records and arrays have no layout,
record_input, execution representation or allocated object facts. Native
certified aggregate representations retain their separately checked issuer rules.

An array has exactly one source element and either no count or a positive count.
It is complete exactly when its count is known and its element is a complete
object type with an actual layout; a complete array requires its own layout.
An unknown-count array remains incomplete. A known-count array of an incomplete
class may describe an opaque C++23 declaration expectation, with no sizeof,
element access, allocation, load/store or by-value call authority. C23 producer
Sema rejects creating an actual array with an incomplete element. The canonical
builtin constructor identity language c23 is an ABI identity, not evidence that
the enclosing translation unit was parsed in C23 mode. Source language otherwise
comes from nominal.identity.language. Ordinary
C++ input facts mean pinned CXXRecordDecl isPOD/isTrivial/isCXX11StandardLayout/
isPolymorphic/isDynamicClass/isEmpty, not heuristics from copy/destroy flags.
Dynamic includes inherited virtual bases with no virtual methods. C23 struct/union
has no bases/class/C++access/NUA and allsix C++trait booleans false. Reserved builtin
normalization below is the only selected exception for compiler-created states.

Source field Some names retain exact nonempty UTF8 bytes without NUL. Canonical
$anonymousN/$unnamedN are reserved for generated None-name output at declaration
indexN, canonical decimal. None is only unnamed bitfield or typed anonymous
member; C++ anonymous ordinary members are unions in this standard profile.
Accepted LLVM009 adds producer-generated Some($captureN) for actual implicit
lambda capture fields. Generic validation checks exact index, anonymous=false,
bit_width=None; it does not prove lambda origin. Producer rejects source spelling
beginning $capture, qualifies actual AST lambda/implicit facts and preserves type,
access/alignment/NUA. No source-origin flag or invented certificate is present.
Storage source_path vectors use exact direct output components, including
$anonymousN/$captureN; never split dots/slashes or guess flattened visible names.

Each input member has exactly one selected output, same declaration index/order,
name/type and independently computed offset/width. Derived flags are lexical
bitfield,unnamed,anonymous,no_unique_address,private,protected,flexible as applicable.
Source explicit alignment is bytes, power-of-two1..65536; bitfield alignas rejects.
C flexible array is final/nonunion/preceded by named member, width0, actual element
alignment and no fake sizeof. Nested flexible member/array element rejects.
Ordinary source records are recomputed, not accepted for merely in-range fields.

Direct nonvirtual bases have Some(index)/origin_path[index]. Virtual placements
are deduplicated by actual canonical source target class, topcv erased only for
empty-class identity, with canonical declaration-edge DFS origin path; physical
placement does not erase multiple private/public source paths. Native opaque
records may omit source input only when no source field/hierarchy query requires
it; missing such metadata rejects explicitly, never uses guessed native offsets.

Selected TargetInfo is GenericItanium LP64 LE/char8, bitfield type alignmenttrue,
zero-length unnamed alignmentfalse, leadingzero placementtrue, zero boundary0,
explicit-bitfield alignmenttrue (source alignas itself invalid), oversized integer
container128bits/alignment16B. No packing/ms_struct/AIX/ARM/Apple/external placement
or sanitizer padding. NUA overlap privilege requires C++ record type; effective
extent=max(nvsize,dsize). Ordinary scalar NUA does not gain that privilege.
Pinned POD03 tail behavior, including its wide-bitfield FIXME, is deliberately
retained as an upstream limitation, not silently repaired in the model.

Source hash V3 retains all source input primitive labels and field/base declaration
attributes, with owner-resolved inputfield/inputbase type edges after existing
element/method edges. Selected fields include declaration_index/name/offset/width/
sortedflags; bases include offset/virtual/index/origin/adjustment; vptrs include
all selected numeric fields/component_order and slot_count. Outputfield/base
edges follow input edges. EXPR declaration leaves propagate transitively through
constructors as defined by the ABI3 normalization below.
Compiled symbol/RTTI IDs and bodies remain excluded and separately validated.
Source member renaming/reordering changes definition identity; private-ID renaming
and alternate sharing do not. Source-name identity is distinct from C projection.

Accepted INT033 component_order preserves all prior six vptr fields, adds an
ordered vcall|vbase token per negative entry and consumes each corresponding value
vector once. For L entries, indexi maps to -8*(2+L-i) B from the address point.
Two8B headers remain even with nullRTTI; relative/omitted-header profiles reject.
This proves slot positions/kinds/values, not which source VB an equal-valued entry
represents. Missing typed target/final dispatch/construction/VTT/RTTI relations
remain unavailable and block freeze. The cohesive ABI038 proposal is UNACCEPTED
and not this executable grammar; no proposed new fields or optional-slot format
are silently admitted here.

Pinned frontend gaps are separate from format mathematics: full evaluated
bitfield widths above UINT_MAX=4294967295bits diagnose before the pin's unsigned
getBitWidthValue truncation. Struct layout >=2^60B diagnoses in the pin although
ordinary arrays/source format permit2^61-1B. Raw Itanium RTTI signed56 packed
base offsets additionally cannot represent positive2^55B; emitting wrapped bits
is not portable semantics. Actual source/IR witnesses are compilation evidence,
not SMIR emission or native source-program execution.

## Exact helper source roles and canonical state declarations

Accepted INT032/ABI030REV6 supplies the exact source meaning of17 helper names;
namespace existence, equal bytes or a matching execution prototype do not prove
source role. R008REV2 source_layout/source_compatible resolve ORIGINAL SELF/DEP
references through actual checked consumer expectations and snapshot; topcv-only
comparison never uses C boundary projection or erases pointee cv. ABI035 exposes
that comparison on actual samecontext Nominal keys, with cumulative Budget.

| Helpers | abi.nominal role | Additional source predicate |
|---|---|---|
| tls_address | Whole registered TLS variable cell | Actual target nominal compatible ignoring only topcv; registered object start, not interior subobject |
| tls_guard_acquire/release/abort,guard_acquire/release/abort | Declared initialized variable type | Complete actual source cell; void/function/internalhandle excluded; separate runtime guard association |
| va_start/va_copy/va_end | Canonical c23 array1<rax.va_state> | Exact builtin source graph and32B/A8 state/transport |
| va_arg | Requested promoted/canonical source object | Actual nominal execution equals Type0, trivial aggregate storage transport explicit; runtime signed/unsigned-fit and void*/char* exceptions preserved |
| setjmp_capture/longjmp_restore | Canonical c23 array1<rax.jmp_state> | Same source wrapper for setjmp/sigsetjmp;128B signal state retained separately |
| eh_allocate | Normalized complete thrown payload | C23 orCpp23 identity, topcv/reference removed/array+function decay by C++producer; pointerpointee complete exceptvoid/function |
| atomic_flag_test/test_and_set/clear | Source kindatomic_flag | Exactly1B/A1/raw8; neitherint32 noruchar substitutes |

Canonical states have c23 builtin identities, entity rax.va_state orrax.jmp_state,
no library/unit, flags[complete,trivial_copy,trivial_destroy], bits0/signedfalse,
no elements/extent/methods/enumerators, actual record_input kindstruct/revision1,
allsix C++traits false/no bases/alignas/NUA/anonymous/bitfields. State fields are
public, grouped and declared exactly as follows; selected size/data_size/nvsize32B,
align/nvalign8B, no bases/vptrs. State execution is actual Array32<Raw8> storage.

| State | Ordered source fields and byte offsets |
|---|---|
| rax.va_state | unsigned long area@0,cursor@8,limit@16,cookie@24, all64bits |
| rax.jmp_state | unsigned int revision@0,reserved@4, both32bits; unsigned long process@8,checkpoint@16,generation@24, all64bits |

Unsigned int/long source nodes are exact c23 builtin scalar identities,32/64bits,
signedfalse/noqualifiers, value execution Int32/Int64, source size/A4/4 or8/8 and
empty selected aggregates. Source wrapper is c23 builtin entityarray,count1 of
correct state, ordinary complete/trivial flags, actual execution Array1<state>,
size32/A8, selected fields/bases/vptrs empty. Mandatory vectors/options are []/None,
not omitted. C++frontend compiler-created builtin states normalize to this c23
contract even if its private AST used CXXRecordDecl with true POD03; that explicit
reserved-builtin exception never rewrites ordinary C++ class traits. Reserved
builtin misuse rejects ABI_CC_BUILTIN_STATE even unused. Accepted ABI042REV1
validates the underlying reserved declaration while ignoring only OUTERMOST const
and volatile. These qualifiers and their source hashes are retained; restrict
and nested field/pointee qualifiers are never erased. Exact helper roles still
require the unqualified state and unqualified array1 wrapper. Thus a globally
valid array1<const state> does not satisfy va_list or jmp_buf helper source roles.
The current production canonical-state profile returns Unknown for otherwise
valid qualified forms; global declaration validation is not a profile expansion.
User external records with the same name/size cannot satisfy these roles.

A reference variable's source cell is8B/A8/DataPtr64 with exact reference category
and original referent qref; referent may remain incomplete. sizeof(reference-
expression) denotes the referent and is not the cell or independent guard8B.
A registered TLS reference variable likewise names its whole8Bcell. Guard/TLS
registration, live activation/cookie/arena/checkpoint/source construction and
provider obligations remain runtime/admission requirements; no static source
shape grants authority or manufactures provider facts.

C23 ordinary _BitInt(N) retains N/signedness under default promotion. A bitfield
_BitInt(N):M converts to DECLARED _BitInt(N), not _BitInt(M) or int32. Ordinary
non-BitInt fields follow pinned rank/range rules. C++BitInt is an upstream
extension relative to hostedC++23 and requires explicit extension mode or
E-SMIR-LANGUAGE-EXTENSION. Source instance constructor/destructor accessibility,
nonabstract throw and other actual C++Sema truths remain producer obligations;
represented exact allocation/transport/lifecycle associations remain separately
checked. EH bytes/alignment must equal actual source payload allocation, not a
native __cxa header guessed from pointer width.


## Declared source-data reference interface

Accepted S-PROD014REV2 appends three optional ABI Context fields after
native_personality: source_data, source_stamp, source_budget. The callback remains
outside legacy bytes/dict resolver wrappers; shared SourceDataError kind/code and
existing source/context/storage errors propagate unchanged. Ordinary non-C++
reference verification does not prepare a source snapshot or choose a default
budget. Logical unissued declarations require no materialized-data query.

RootContext.prepare_source_data(budget=...) captures an immutable source/schema
snapshot under one explicit cumulative SourceQueryBudget. That context retains
that exact budget and stamp; every query/read checks identity and the current
source/schema snapshot. Equal bytes in another context do not substitute. The
reference mutable context has no supported concurrent mutation; this API does
not implement production parallel lifetime or private Rust proof issuance.

source_data(original_symbol,offset,length,budget=...) returns exactly Local or
Dependency. Local retains original Symbol and actual Data identities separately,
full-symbol readonly/defined eligibility, actual declared/backing alignments,
bounded immutable byte prefix, symbolic zero tail, and whole absolute overlapping
leaf/constant records. An intersecting patch is never clipped to the queried
range. Defined weak/COMDAT is declared input, with actual future binding/selection
conditions; it is not a selected winner. Dependency retains only original checked
consumer expectation and range; no provider bytes/extent/alignment are guessed.

LocalSourceData.read(relative_offset,length,budget=...) constructs only the
bounded requested bytes after charging. The prefix is a readonly contiguous 1D
memoryview of immutable bytes, format B/itemsize1. Zero tails are not expanded.
Actual bytes remain pre-relocation source data. Materialization consumers must reject known malformed writes and report
unexecuted constant-produced contents unavailable, never evaluate them to fill
the evidence. The general C++ materialization consumer remains unimplemented;
this API supplies declared source views and preserves their exact evidence boundary. No host pointer, source digest or dictionary grants code, object,
provider, native, unwind or live C++ phase authority.

For Q queries/reads, work is O(Q*(A+B+P)+sum L): A actual source/schema snapshot
work, B initialized prefix/shadow scanning, P all declared patch rows and L each
bounded read. Work/edge/copy/depth quota is charged before traversal/allocation;
this ledger does not retroactively meter historical reference APIs. Shared types
load once from tools/smir-runtime-contract/source_roles/source_data.py as
_rax_smir_source_data_v1 with exact path/class identity. Legacy metadata(ref)
continues its existing contract and is no fallback for this bounded interface.

ABI boundary tests use actual ten-root contexts: distinct Symbol/Data IDs, partial
absolute relocation interval, declared weak data, 1TiB symbolic tail with 8B read,
same-byte different contexts, wrong budget, source mutation, zero preparation
quota, missing root5 and poison outside the requested slice. These are reference
source-data checks; no relocation, native execution, C++ dispatch, semantic
admission or compiler freeze follows from their passing.

## ABI3 ordinary function addresses and independently issued call plans

The incompatible ABI3 cut appends mandatory `execution:qref` LAST to every
`call_signature`. The actual referenced section1 type is a closed portable Fn;
source-to-lowered params/results/noundef/cc/varargs are verified from THAT Fn.
There is no decoder default and no fallback to nominal Function.execution.
Rust SignatureFact.execution_signature() is a nonoptional context-branded
TypeHandle. Root3payload2 call/invoke/tailcall append mandatory syntax
source_plan:opt:entity_ref: None is an explicit generic legacy call; Some is the
original caller's independently checked ordinary CallSignature. It never derives
from code_bind's plan, retained permit, equal Fn or another module's SELF IDs.

Ordinary source pointers/references to Function use representation=code_address
and section1 CodeAddress: exact64 value bits,8B size/A8, no Fn child. The source
pointee prototype remains explicit nominal metadata. A complete source Function
may use representation=none, execution=None; its arity/element/qualifier/flag
checks still execute. Source R(R) and its pointer can be declared with incomplete
R without inventing sizeof(R), an execution Fn, call plan or native entry. A
by-value call requires a real checked plan and complete source layouts.

A portable Function.execution=Some(E) is only an optional issued ordinary
default: at least one already checked LOCAL plan must resolve function_type to
that exact nominal key, have this_type=None/vtt=false, and have execution
structurally equivalent to E in the same actual TypeFacts. Equivalent source
prototypes at another local key do not supply that default. Multiple choices
need not share execution IDs. Foreign source Function.execution must be None;
portable-facing bridge plans remain separately checked metadata.

CodeAddress storage/copy and direct ABI passing preserve actual source address
origins; they do not issue a callable permit. Explicit observing code_bind occurs
after source argument evaluation and before the call's argument noundef checks.
Actual entry checks selected provider A and retained bind view B against actual
caller plan C. CodeAddress, typed internal CodePtr, native program counters and
integer bits are distinct. Generic terminate/TLS/dispatch CodePtr helpers retain
their exact interfaces; hosted source facades require real bindings/retention/
transactions and remain unavailable until their actual implementations exist.

V3 has exact22B domain `SMIR-NOMINAL-SHAPE-V3\0`. DEF retains all source/layout
metadata and ordered by-value edges. EXPR propagates through every intermediate
constructor; record/enum are declaration leaves. Pointer/reference/member-pointer/
Function DEF element edges become EXPR; methods are EXPR, field/base source and
selected-layout edges DEF. Learning an R definition cannot change R(*)[3] or its
containing prototype. Bound3->4, nested qualifiers and nested noexcept remain
significant. Root cv removal removes const/volatile only, retaining restrict.
Compiled execution/default choices and graph-sharing/private IDs are excluded.

API6 ordinary compatibility uses two genuine canonical SourceCallContext views
and ONE cumulative SourceQueryBudget. It compares complete checked sites, domains,
source DEF/EXPR graphs, lowered fields, actual recipe interfaces, vararg state and
full execution descriptors. Only actual root noexcept true->expected false may
weaken; nested noexcept remains exact. Both snapshots are checked before work and
before true or false. Semantic/unavailable/resource errors keep exact identities;
programming errors do not become false. The Rust relation checks both immutable
AbiFacts/TypeFacts context brands and original CallSignature keys. Compatibility
is not provider/entry/generation/lease/object/native authority.

SourceCallContext.module_family(budget=...) returns the charged captured original
root2 manifest key (namespace,name,ABI major). ABI minor is excluded. Internal/
local identity compares this family plus the explicit stable unit UID; equal unit
bytes in different families do not identify one declaration. External/builtin
declarations do not acquire private family ownership. Both source snapshots and
the existing ledger are validated around this query; no private-field fallback.

Reference tools: function_address.execution_compare and function_address.model;
fixtures explicitly author ABI3 records. The independently implemented Python and
standalone Rust V3 normalizers remain separate oracles. Per-query full snapshot
cost is included: O(P+F+Q*S), with P paired nodes, F field/edge work, Q checks and
S charged source/schema size. New traversal metadata is precharged; quotas are
logical work/edges/bytes/depth rather than allocator/time guarantees.

Scope: static predicates/reference conformance do not implement portable JIT,
parallel execution, hosted character transport, foreign C++ bodies or native
bridges. Member-function-pointer transport/dispatch and selected C++ source
scopes remain separately gated; the older two-Int64 description above is not an
origin-preserving CodeAddress member-pointer implementation claim. Compiler
freeze/full platform qualification remains false until the integrator's gates.
