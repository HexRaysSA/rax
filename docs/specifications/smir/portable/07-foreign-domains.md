# Foreign guest-ISA and C++ domains

Status: **candidate ABI section10 and independently checked descriptor contracts**.
The authoritative ordered grammar is [candidate.json](schema/abi/candidate.json).
`candidate.py` checks source layouts/calls/typed recipes/CFI/catches against actual
section roots and independent native evidence. `descriptors.py` preserves the
older JSON-only descriptor model for regression tests. Neither tool loads code or
grants execution; both report `admitted_for_execution=false`. Native layout
compilation and host C++ language execution are separately labelled evidence.

FFI-001: A process has one portable domain and zero or one foreign guest ISA,
x86-64 or AArch64. Foreign code always executes through the appropriate guest
CPU adapter. The ISA may host multiple modules but cannot change midprocess.
Native host addresses/call conventions are not foreign guest addresses/calls.
The process selects one Linux/Darwin/Windows personality. Module manifests carry
requirements that must match it before SCC publication; they are not independent
simultaneous OS worlds. The first nonportable ISA pins the process once, including
after its last module unloads. Dynamic admission rechecks both under the publication
transaction. Domain personality=portable means the logical ABI, not another OS.
No mixed-OS adapter is inferred, and OS choice never selects portable layout. The release endpoint includes Itanium and Microsoft foreign
profiles; qualification is per exact compiler/runtime/library/build identity.
Multiple foreign build domains may coexist for that same ISA and selected OS;
each needs independently admitted build and metadata certificates. The reference
limit is4096 domains. Direct descriptor calls between two foreign domains reject;
they require two explicit portable bridge hops. Ordinary native-loader calls
inside an admitted native image remain governed by its native linkage contract.

Each candidate domain record has exactly id,isa,personality,abi,compiler,runtime,
build,library,abi_identity. Compiler/runtime/build/library are lowercase64-hex
SHA-256 identities; abi_identity is the stable compiler/library ABI-site identity,
checked against admitted modules rather than accepted from descriptor assertions.

| Domain kind | ISA | ABI | Unwind mechanism |
|---|---|---|---|
| portable | portable | portable | logical |
| Itanium foreign | x86_64 or aarch64 | itanium | Linux DWARF, Darwin compact/DWARF, or qualified Windows GNU SEH |
| Microsoft foreign | x86_64 or aarch64 | microsoft | seh; Windows personality required |

The domain's full profile additionally binds compiler flags, exception/RTTI
settings, class packing/inheritance model, standard-library ABI configuration and
all module code/metadata bytes through its admitted build identity. Names and
ABI family alone cannot establish representation compatibility. Unknown profiles,
missing compiler identity, unsupported ISA/features and missing unwind formats
are admission errors. A module without EH metadata is usable only through a
verified no-throw boundary; it cannot be traversed during mixed unwinding.

FFI-002: The preserved legacy JSON root has exactly revision, domains, types, mappings and
calls. Arrays have at most4096 records; IDs are unique nonempty strings. Unknown
keys, duplicate JSON keys, missing required fields and invalid enumerators reject.
The local canonical reference transport uses ASCII JSON with escaped Unicode,
sorted keys, compact separators, no floats/NaN/negative zero and no trailing bytes.
It is not the executable SMIR binary payload. Module-qualified execution IDs and
nominal identities require linker normalization before any future wire binding.

## Type and symbol evidence

A type record declares id, domain, identity, library (exact library hash or null),
layout, trivial, ownership, destructor, copy, move, allocator, deallocator, retain
and release. Symbol-valued nullable fields are explicit; null never implies a
runtime default. `trivial` means trivially copyable for this boundary's byte
transfer. Nontrivial types require owner-domain destruction metadata; a
nontrivial by-value parameter also requires copy or move construction metadata.
Owned/shared types require matching allocator/deallocator operations; shared types
also require retain/release operations. Constructors/factories are ordinary typed
bridge calls returning the object type; special operation symbols are admitted
as their exact declared role and signature, not looked up by spelling alone.

The layout record has exactly size, align, fields, bases, vptrs and rtti:

| Field | Meaning |
|---|---|
| size, align | complete-object byte extent and power-of-two alignment |
| fields[] | name/path, nominal type_identity, offset_bits and width_bits |
| bases[] | nominal type_identity/subobject path, byte offset, virtual and public booleans |
| vptrs[] | byte offset and ordered admitted method-symbol slots |
| rtti | registered RTTI/type-identity hash, or explicit null |

Offsets are in the complete object, including virtual bases at the admitted
most-derived dynamic type. A different dynamic class needs a separate certificate.
All field extents fit storage; each vptr occupies an aligned8-B word. Source
layout may include overlap for unions/empty subobjects; admitted compiler evidence
must authorize the exact overlap. Descriptor offsets alone cannot authorize it.
For repeated bases, type_identity includes the unambiguous subobject path. RTTI
identity binds the registered cross-module type, not the address of host type_info.
A vtable method's entry must be a registered domain method with an even nonzero
code token. Virtual-base/vcall displacement and construction-state interpretation
remain native ABI behavior inside the compiler-generated bridge.

For member-pointer arguments, the type certificate records the complete native
representation as nominal fields and exact identity. Generic Itanium standard
and ARM member pointers have different discriminator rules; Microsoft member
pointer size depends on class/inheritance flags. Never guess those flags from
one observed sizeof. Member-pointer conversion/dispatch is an owner-domain bridge
operation; incompatible bit patterns are not reinterpreted as portable values.
Standard-library objects require their exact library hash even if apparent sizes
match. Exceptions, std::string, std::function, containers and exception_ptr do not
acquire cross-library binary compatibility from a common source name.

`validate(document,evidence)` takes a distinct trusted evidence object with domain,
type and symbol maps. The future loader/compiler pipeline supplies it only after
binding loaded object/code bytes and generated metadata to the selected profile.
The descriptor must equal the independently admitted domain/type certificate.
Symbols bind domain, exact operation role, token and signature. Bridge signatures
are SHA-256 over canonical `{params,result,variadic,exceptions}`. Evidence fixtures
are synthetic authority inputs, not real binary attestations. Unknown evidence
producers, binary-only classes without metadata and self-certified layout/build
hashes are explicit `ABI_*_EVIDENCE`/`ABI_MISSING_METADATA` errors.

## Generated bridges and fixed packet ABI

Every legacy JSON call descriptor has id, source_domain, target_domain, bridge, params,
result, variadic, callback, exceptions and mappings. Params are ordered target
nominal type IDs; result is a target nominal type ID or null. References/pointers
are declared as their own pointer-representation types; a class type ID denotes
by-value construction. Every used type has exactly one mapping from the source
domain to the target domain. Missing or ambiguous mappings reject. Constructors,
destructors, casts, methods, callbacks and ordinary functions use the same typed
call mechanism. Variadic calls are `none` or `typed-pack`; raw host/native va_list
forwarding is not representable.

An admitted compiler-generated packet bridge has native signature
`void bridge(BridgeFrame *)`. The packet pointer is passed in RDI for SysV
x86-64, RCX for Win64, and X0 for AAPCS64/Darwin/Windows ARM64, with the native
profile's required stack/call setup, including Win64's32-B shadow storage.
The runtime enters this guest code through the CPU adapter. For portable-to-foreign entry, the bridge constructs arguments, invokes the
actual native signature and extracts results. A reverse callback uses its typed
native wrapper in the foreign source domain, which invokes the coordinated
portable dispatcher. In both directions the packet stub, native calling convention,
CFI and personality belong to the foreign endpoint, not a portable pseudo-ISA. This avoids substituting the portable logical
calling convention for an arbitrary foreign signature. ABI metadata without the
required generated adapter is rejected.

BridgeFrame is80 B, alignment16 B, little-endian:

| Offset B | Field | Representation |
|---:|---|---|
| 0 | revision | u32, admitted bridge-protocol revision |
| 4 | flags | u32, zero for baseline |
| 8 | signature_ref | u64, admitted descriptor/signature token |
| 16 | arguments_address | u64 guest address |
| 24 | arguments_bytes | u64 bounded arena extent |
| 32 | result_address | u64 guest address, zero for void |
| 40 | result_bytes | u64 exact result-storage extent |
| 48 | transition_id | u64 live per-thread transition identity |
| 56 | exception_lease | u64 opaque lease or zero |
| 64 | status | u32, admitted bridge-protocol status |
| 68 | reserved_zero | u32 zero |
| 72 | continuation_generation | u64 stale-return protection |

The argument arena uses chapter3's entry-storage grammar. Fixed arguments use
their chapter3 ABI-lowered types; a record argument entry is therefore an8-B
typed pointer to its leased caller copy, not an inline object-size payload.
Nontrivial entries similarly identify source objects for the admitted construction
adapter, which constructs the target-domain argument. Default promotions apply
only to ellipsis operands; nontrivial objects in ellipsis remain rejected.
Result storage is guest memory with the target type's exact size/alignment;
nontrivial class result ownership transfers only after successful construction.

The symbolic packet states are ENTERED, SUSPENDED, RETURNED, RAISED and TERMINATED.
RETURNED makes the bridge result available for its admitted source-domain result
adapter; the normal portable result is published only after that conversion also
succeeds. Target result storage remains leased through conversion and its cleanup.
RAISED publishes an exception lease
at the exact unwind edge. SUSPENDED preserves the caller/foreign frame/lease
chain without publishing output. TERMINATED has no resumable continuation.
A generation/thread/signature mismatch fails before an adapter executes.
Symbolic states map through the admitted runtime protocol; arbitrary native status
integers cannot be treated as those states. Candidate section10 references are
qualified declarations with explicit namespace/table selection. The C++ layout witness statically checks all fields across six native target
profiles. It does not implement or execute generated bridges.

FFI-003: Mappings have exactly id, source, target, mode, lifetime, alias, identity,
adapter and typed_catch. Supported choices are:

| Property | Choices |
|---|---|
| mode | share, adapt, opaque |
| lifetime | call, object, shared |
| alias | shared, exclusive, none |
| identity | preserve, proxy |

A share mapping requires equal complete layout, triviality, ownership and library
identity; identity=preserve; no adapter. The reference schema rejects sharing a
vptr-bearing or RTTI-bearing type across ABI domains even when offsets match.
The admitted runtime additionally proves lifetime, provenance, alignment, active
union member, constness, alias permissions and synchronized backing access.
A type layout certificate is not an object lifetime or concurrency proof.
Nontrivial shared-storage admission requires owner/lifecycle metadata and a
runtime identity registry; the first-wave tool validates the metadata only.

Adapt/opaque mappings use explicit target-domain adapters and proxy identity.
They cannot declare simultaneous shared aliases. The object registry key is
(owner domain, owner module generation, object generation, allocation identity,
subobject path). Repeated visits return the same live proxy for that key;
revocation invalidates its generation before storage reuse. A proxy pointer is
not equal to the foreign raw pointer. Address-observable identity is preserved
only by a proven share mapping; otherwise a boundary requiring it rejects.
Copy-in/copy-out cannot represent simultaneous differently laid-out mutable
aliases, identity-sensitive observers, self-referential interior pointers or
callbacks that access the original during a copy. Such boundaries reject
`ABI_UNREPRESENTABLE_ALIAS`, rather than silently choosing last-writer wins.

Borrowing never transfers destruction. Owned transfer consumes the sender's
ownership only at its declared successful commit; failure restores sender
ownership unless the source operation's specified partial effect says otherwise.
Shared transfer acquires a retain before publication and releases in the owner
domain; no host reference count may outlive its module lease. Deallocation always
uses the owning allocator/profile; destructor/deallocator order remains explicit.
Objects cannot migrate between guest threads merely because their address fits
u64: thread-affinity and source-language synchronization remain admission duties.

FFI-004: Every crossing pushes a per-guest-thread transition with a fresh
continuation generation and a published saved logical frontier. It retains both
modules, code, descriptor, borrowed object/subobject and active exception leases.
Foreign architectural state includes registers, stack/TLS, FP environment,
error cells and domain exception state; portable state includes activation/value
IDs and normal/unwind continuation. Save/restore is explicit for both directions.

```text
thread T: portable P0 -> foreign F1 -> portable callback P2 -> foreign F3
                    leases retained until the matching LIFO return/unwind
thread U: independent attached context and transition chain
```

Each direct return must match thread, top transition, signature, generation and
normal continuation, then commit once and release leases. Callback policies are
none, owner-thread or attached-thread. An external callback on an unattached
thread cannot borrow another thread's state; attaching creates a new guest-thread
context before admission. Callback storage escaping its declared lifetime needs
an explicit owned/shared lease. No runtime lock may be held across reentrant
callback execution. Module unload closes new entry, then waits for all transition,
object, callback, RTTI, exception and exception_ptr leases before reclaiming code
or metadata. Cancellation is observed only at a published safepoint/frontier;
it does not discard an in-progress construction or duplicate an imported effect.

FFI-005: Mixed exceptions use two distinct phases across the entire dynamic
transition chain. The exception handle binds owner domain, exact exception/type
identity, payload/storage, destructor, active-unwind reference and retained
exception_ptr/module leases. The handle retains identity across catch-all and
rethrow; it is not a new portable wrapper object. Payload access/conversion and
owner destruction require admitted adapters. Typed cross-domain catches require
explicit registered source/target type mappings and a catch adjustment/copy
adapter. Unmapped foreign types can be observed only by opaque catch-all/rethrow.
No reinterpretation of native RTTI addresses establishes a mapping.

```text
RAISED -> SEARCH -> handler selected -> CLEANUP -> CAUGHT -> RETHROW -> SEARCH
                  no handler -> TERMINATED
forced SEARCH -> CLEANUP of traversed regions -> owner forced-exit continuation
```

Search walks each active domain's admitted personality/metadata, consulting
logical landing pads and foreign DWARF/SEH state without running destructors,
mutating results or releasing frame leases. A selected handler records exact
landing-pad, object-adjustment and cleanup frontier; search of an outer domain
cannot prematurely run inner cleanups. Missing metadata fails before starting
that mixed call; unexpected corruption during unwind terminates the process with
a deterministic metadata fault rather than attempting host unwinding.

Cleanup walks only the searched path, innermost active cleanup region first,
executing each selected cleanup exactly once, through its owning execution domain.
The handler frame may contain pre-landing-pad regions; only their metadata-selected
cleanups run. Itanium catch adjustment, base matching, virtual bases and catch
by-value copies use their registered owner/type adapters. Microsoft handler
search/funclet entry/restoration uses the exact foreign profile's metadata and
CPU adapter. Neither is implemented by unwinding Rust frames. A compiler-generated
bridge may return RAISED only after the coordinated protocol reaches that boundary;
catching/cleaning at every bridge before global search would change C++ behavior.

Begin/end-catch maintain nested per-thread active exception state. Copying
exception_ptr acquires a retained owner/module reference; releasing the final
reference destroys/deallocates in the owner domain only after active unwind/catch
references are gone. Rethrow preserves the original identity and continues from
the current catch region's outer continuation, with the catch object's required
cleanup in that region. Cross-thread rethrow through an admitted exception_ptr
uses the receiving thread's new dynamic chain while retaining original owner
storage; an active unwind handle itself is not moved between threads.

FFI-006: The termination/nonlocal policy is explicit:

| Event | Required effect |
|---|---|
| cleanup throws during active exception unwind | terminate process; do not resume prior exception |
| exception escapes noexcept boundary | terminate at that boundary; no result publication |
| no handler found for ordinary exception | terminate after search; no promise of cleanup before termination |
| opaque catch-all followed by rethrow | preserve exception identity and owner storage |
| nested throw handled within cleanup/catch | distinct nested exception state; restore outer current exception |
| forced unwind/cancellation | bypass ordinary catch selection, execute owner-declared cleanup path, enter forced-exit continuation |
| missing unwind metadata or invalid continuation | deterministic terminal fault; no guessed stack walk |
| module/domain exit with pending callback/object/exception lease | defer reclamation or return busy; no continuation invalidation |

Noexcept termination and nested-throw state are source/profile obligations that
require executable personality tests; the simple Python protocol model tests
search purity, cleanup order/once, cleanup throw, opaque rethrow, forced catch
bypass and owner-reference destruction only. The newer construction/exception reference additionally checks nested array
subobjects, catch-copy termination and retained exception_ptr lifetimes. Neither
reference executes arbitrary native personality dispatch or proves foreign CFI
by trusting a producer hash.
The evidence boundary is intentional and prevents those cases being reported as
implemented from protocol tests alone.

`setjmp` records the owner guest thread, activation generation, domain, stack
checkpoint and transition depth in an opaque runtime checkpoint. `longjmp` requires
a live checkpoint on the same thread, restores its source-language state, then
invalidates abandoned activation cookies/continuations and releases their runtime
leases. It does not run C++ language destructors where the source operation does
not provide them, or cross an unrepresented foreign checkpoint. A stale/wrong-
thread checkpoint traps. Foreign nonlocal jumps need generated profile-aware
checkpoint adapters; arbitrary captured native jmp_buf bytes are unavailable
metadata and reject at admission. Coroutine destruction similarly needs explicit
suspended-frame/object/module leases; raw continuation pointers are not adapters.

## Candidate typed recipes and normalized unwind evidence

Candidate schema field order is authoritative. Its tables bind nominal source
nodes to exact execution shapes, layouts, call signatures, foreign domains,
adapter recipes, personalities, native unwind recipes, catches, bridges and
cleanup programs. The common wire primitives and namespace/dependency rules are
specified in chapter3. Legacy string IDs/canonical JSON are not this payload.

| Record | Exact role and rejection condition |
|---|---|
| adapter_recipe | domain, typed formal IDs/results, entry and finite action CFG; no unreachable/cyclic adapter graph |
| adapter_step | typed inputs/outputs, optional source/target types, callee/adjustment, extent/alignment, journal slot, unique effect ticket, normal/unwind edges and exception output |
| personality_binding | owner domain, exact flavor/entry/source prototype and search/cleanup/forced-unwind obligations |
| unwind_recipe | exact function/code extent, raw metadata ranges+digests, normalized CFI rows, action chains and protected regions |
| catch_mapping | thrown/caught/native-caught identities, relation/path/qualification/adjustment, copy/destroy/foreign adapters and reference/value mode |
| cleanup_program | source owner call_signature, explicit typed capture params, object/array slots and cleanup orders |
| bridge_descriptor | source/target domains, source call_signature, foreign packet entry/personality/unwind, conversion recipes, construction program and callback/ownership/alias policy |

Adapter action vocabulary is closed: adjust,byte_copy,copy,move,construct,destroy,
retain,release,convert,call,virtual_call,rtti_cast,catch_copy,checkpoint,return,
raise,terminate. Conversion/constructor/destructor code bodies are ordinary typed
compiled functions called by these recipes; finite adapter CFG does not restrict
user C++ destructor/control flow to a pattern. Each callee binds an independently
admitted exact source signature/domain. Return types and every argument agree.
A call output exists only on its normal edge; its exception lease exists only on
its unwind edge. Values must dominate every use on the corresponding path, and
effect tickets are unique. Catch-copy failure enters terminate rather than a new
handler search. A raised value is an exception lease, not an arbitrary u64 or
journal token. Section8 cleanup actions supply an explicit formal-ID capture
bijection: SSA value, injected exception or injected exact journal program. The
triggering operation's normal result cannot appear on its own unwind edge.

Section10 `unwind_recipe` describes foreign native CFI only. Its domain must
select x86-64 or AArch64; a portable domain rejects with `ABI_CC_CFI_PROFILE`
before native code-size, register or metadata lookup. The `logical` source-format
token is reserved and is not admitted in this table. Portable logical exception
handlers, actions and continuations remain in section8 and require no native
register context or code extent. A portable `logical_itanium` personality binding
remains permitted without an `unwind_recipe`; it grants no native CFI profile.

Native unwind rows cover the entire admitted code extent without gaps/overlap.
The normalized libunwind register numbers are x86-64 GPR/PC0..16 and XMM17..32;
AArch64 X0..30/SP/PC0..32 and V0..31 at64..95. CFA is SP/FP plus signed offset
(unused reg must0), or a GPR excluding PC plus signed offset. Scalar/PC saved
width is8 B; vector width is8 or16 B, with8 restoring low64 and preserving high64.
Register-to-register recovery requires equal register width. CFA-value recovery
is scalar only. Same preserves the register; undefined chooses a concrete zero
refinement. Both have no extra payload. All recovery reads use
the original context and commit simultaneously. Expression recovery and
nonaffine CFA are explicitly unsupported boundaries; compiler profiles must
produce normalized supported CFI, including dynamic/over-aligned stack cases.
Full x87 state belongs to the separate native checkpoint. Stack reads retain
the exact stack generation and bounds. Action chains
are acyclic; regions fit code, landing offsets are native PC offsets, not invented
callable labels. The native protected-region `landing_pad` option is reserved
None; `landing_offset` names the actual native PC offset. Section8 logical landing
handlers are separate from this native table.
Raw metadata extent/digest equality alone is insufficient: a separately admitted
native_unwind certificate must equal the normalized function/domain/CFI/actions.
The production registered metadata producer is a later implementation requirement;
self-reading section10 as evidence is invalid. Missing or unrepresentable CFI,
profile, symbol or type metadata rejects before entering the mixed call.

Baseline foreign profiles are generic Itanium Linux DWARF/LSDA, Itanium Darwin
compact-unwind with DWARF fallback, and Microsoft Windows x86-64/ARM64 unwind.
Qualified Itanium-on-Windows GNU SEH uses `guest_itanium_seh`, the Windows unwind
format and native Windows calling convention independently of C++ ABI family.
Its personality has prototype `i32(guest_ptr,guest_ptr,guest_ptr,guest_ptr)`.
Raw foreign SEH bypass can skip C++ destruction; mapped or opaque mixed-domain
bridges therefore require independently certified `cross_domain_translation`
alongside search_readonly, cleanup_calls and forced_unwind. Microsoft EH3/EH4
require their exact registered compiler/runtime metadata producer; a family name
is insufficient. Itanium personality source prototype is
`i32(i32,u32,u64,guest_ptr,guest_ptr)`; Microsoft personality is
`i32(guest_ptr,guest_ptr,guest_ptr,guest_ptr)`. Portable logical Itanium uses the
portable calling convention and section8 source semantics. Native CFI/personality
and packet entry must all refer to the same foreign domain/function profile.
`Context.native_personality(ref)` supplies the independently registered exact
binding, including prototype and phase/translation flags; copying section10 is
not independent evidence. Native symbol facts separately carry `native_cc`
(sysv_amd64, win64, aapcs64, aapcs64_darwin or aapcs64_windows) and `bridge_abi`
(none, sysv64_frame, win64_frame or aapcs64_frame). A personality entry has no
packet-frame convention. C++ Itanium/Microsoft family does not select native CC.

Catch matching compares recomputed source graphs, not names alone. It supports
exact/CV matches, unambiguous public bases, shared virtual-base identity,
qualification-allowed pointer conversions, null pointer/base adjustment,
nullptr_t to pointer/member-pointer, and permitted noexcept-function conversion.
Execution handler identity uses separately compiler-normalized caught RTTI:
array/function adjustment and reference stripping precede metadata emission.
`NominalGraph.catch_compatible` rejects raw reference/array/function/void roots,
ignores top-level cv only and preserves pointee cv, C++ builtin/library/private
identity. T, T& and const T& normalize to the same key; T* and const T* differ.
Catch-all is a separate key. Positive selectors1..INTMAX form a per-function
bijection with these keys; repeated catches of one key reuse the selector.
Cleanup/no-match uses0. Local handler IDs never determine observable selector
values; catch mode and copy action remain separate metadata.
Private/inaccessible or repeated ambiguous bases do not match; arbitrary arithmetic
and Derived/Base member-pointer conversions do not match. Native matching occurs
inside the thrown domain against native_caught, then an explicit foreign adapter
produces the portable caught representation. Missing adapter/adjustment/type
metadata rejects. Opaque catch-all retains the original lease for rethrow.

## Construction journals and live state

```text
empty -> constructing -> alive -> destroying -> destroyed
                  |                    |
                  +-> failed           +-> throw during unwind -> terminated
partial throw -> destroy completed children in reverse completion order
```

A slot records nominal type, offset/extent/alignment, literal count or captured
count_source, stride, parent, role, constructor/destructor recipe, destructor
variant/covers, owning domain, dependencies and optional child_program qref.
Program params are an explicit typed capture environment; signature names the
source owner and does not implicitly supply these formals. Captures biject params;
count_source selects unsigned nominal64 with a noundef admitted live value.
Intra-program parents have literal count1/no count_source. An array of classes
creates a separate child program instance per element; parent_instance is exactly
{journal:u64,slot:u32,element:u64}. Program IDs and live instance IDs are separate.
Every state/event carries instance, transition, guest thread, activation and
module/object generation facts from runtime registries; file integers cannot
mint them. Cross-module child programs resolve admitted declarations, not raw IDs.

Construction begins only after dependencies and the previous array element are
complete. Root/element commit waits for all required children; failed construction
never marks the complete object alive. Partial child cleanup finishes before
failure propagates to its uncommitted parent array element. Earlier elements
remain committed and destroy in reverse completion ordinal. Complete/base
destructor coverage delegates covered children once; independent member cleanups
cannot run again. Parent destruction cannot commit until its child instance
finishes. Tickets reject replay/stale/wrong-thread events. Nonlocal abandonment
of a live nontrivial object rejects. Heap allocation/ownership journals are
separate from in-place subobject offsets. Normal and exceptional program orders
are declared slot schedules; dynamic element order is reverse successful
completion, respecting those dependency/parent relations. Zero-element arrays
are empty, VLA count must be positive, checked extent multiplication cannot wrap.

The active exception lease counts outstanding throws/catches separately from
retained exception_ptr references. Begin-catch consumes a real pending throw;
it cannot fabricate a second catch reference. Nested rethrow creates a new active
reference to the same owner payload. Cross-thread exception_ptr rethrow uses the
receiving attached thread's chain; payload/destructor/module authority remain in
the owner domain. Final destruction occurs only after all active and retained
references end. Escaping catch-copy and destructor throw during active unwind
terminate without publishing a normal result.

## Foreign checkpoint and ownership closure

A suspended foreign transition stores the runtime's exact native_context profile,
including integer/vector/control registers, PC and live code generation, stack
object/generation and admitted unwind row. x86_64 baseline includes physical
x87 R0..7 as8*10-B payloads, FCW/FSW/full tags/FOP/FIP/FDP in112 B; logical ST(i)
uses TOP and MMX aliases the same low64 bits. TLS32 B retains FS/GS bases and
CS/SS/DS/ES/FS/GS selectors plus reserved0. AArch64 stores X0..30/SP, V0..31,
NZCV/FPCR/FPSR and16-B TPIDR_EL0/TPIDRRO_EL0. These are guest context facts,
never host defaults. Optional AVX/SVE/SME/AMX/PAuth state needs an exact admitted
profile; reachable unsupported state rejects before entry. Native x87/binary64
long double converts to portable binary128 through the exact compiler adapter
and guest rounding/flags. Snapshot bytes do not mint stack/code/TLS leases.

Portable services use exact immutable catalog entries and `abi=None`: their
internal multiple-result convention differs from source C ABI. Descriptors are
absent except `module.symbol`, whose descriptor names the returned function's
call signature, and `module.data_symbol`, whose descriptor names its nominal
data type. These take module, namespace pointer/length and name pointer/length;
they return status plus a typed pointer/token. Ordinary source library wrappers
carry their own source ABI. Personality-specific native API calls use an admitted
foreign bridge and the process-selected personality/ISA. Reserved OS service
names cannot bypass descriptors. errno conversions are explicit tables and
canonical service structures never reuse host stat/dirent/timespec layouts.
Ownership/alias rules above remain independent of signature or shape equality.

## Reference validation, assumptions and limitations

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/smir-abi/check.py \
  --output /tmp/rax-portable-smir-01/ABI/check-final
```

The checker binds actual owned source/schema/fixture hashes, compiler identities,
commands and nonzero pass/fail/skip counts. Legacy tests cover layout equations,
seeded bit-fields, descriptor evidence and sequential transition/search protocols.
Candidate tests add three independently implemented ordered decoders, every
nominal kind, source/execution/storage bindings, cross-module/private identities,
typed captures, CFG edge dominance, CFI corruption, callback direction, nested
arrays/partial cleanup, fenv restore semantics and namespace separation. Native
host C++ executes partial-construction trace ABa, public/private/ambiguous catches,
exception_ptr handoff, catch-copy termination and finite lock-free-flag progress.
Pinned Clang cross-compiles layouts/default fenv objects for six existing targets;
that compilation does not run those targets or a SMIR frontend.

Primary provenance and the Assumption Register are in chapter3 and the role
handoff. High impact: missing native metadata or unrepresentable mutable aliases
reject at admission; no universal binary-only C++ compatibility. High impact:
cleanup capture/program/instance identity must remain distinct under callbacks,
arrays and migration. Medium impact: independent CFI fixtures are synthetic
certificates; production metadata normalization and coordinated guest personalities
remain implementation work. Low impact: same-size native layouts do not establish
ABI or lifetime equality. Full six-host qualification, production foreign C++
bridges, parallel runtime and native unwinding are not claimed by these witnesses.
The combined compiler freeze remains the integrator's decision.


## Source hierarchy and descriptor evidence boundary

Executable ABI3 retains the ABI2 separation of source direct base declarations from selected physical
base placements. Catch/public-path/RTTI/base-conversion queries traverse actual
record_input.bases in original owner scope and read access there. Physical virtual
placements deduplicate storage and cannot erase distinct public/private source
paths. Canonical shared identity is the TARGET source class of the last virtual
edge plus nonvirtual suffix within the complete storage class, not that particular
base-specifier declaration or an equal physical address. Distinct nonvirtual/
empty subobjects remain distinct even with equal types/offsets. Raw source_path
components are exact direct names; anonymous grouping is explicit.

A native opaque source record may omit record_input only where no hierarchy or
field query is needed. Exact catch/cast/base/field query with missing source facts
reports unavailable metadata; native bytes, compiler-hash equality or a sizeof
observation do not supply a source hierarchy. An independent admitted native
issuer still binds supplied source input and selected layout/RTTI/build/library/
architecture to its original native evidence. Portable GenericItanium geometry
is never imposed on Microsoft or other foreign native layout certificates.

Accepted INT033 records actual interleaved negative vtable component order while
preserving the prior six vptr fields. Slot-byte mapping alone cannot distinguish
equal-valued entries naming different source virtual bases. Current reference
geometry checks explicit slot kind/value/complete-object offset then reports
ABI_CC_VBASE_TARGET_METADATA_UNAVAILABLE when the typed source target map is
absent. Full selected method/finalslot/thunk/RTTI/construction/VTT relations remain
compiler-freeze blockers under the unaccepted cohesive ABI038 proposal. That
proposal's additional records/optional callable slots are not admitted grammar.

No static descriptor, selected group or source layout certificate grants current
object identity, lifetime, generation, capability bounds, permissions, code token,
provider binding or unwind authority. Mixed-domain calls/callbacks keep the exact
existing bridge/personality/packet/lease protocol; two-phase exception search is
readonly and committed cleanup occurs only through the admitted owner recipes.
Source declaration verification, native issuer qualification and live runtime
phase enforcement are distinct gates. This package does not implement universal
binary-only C++ compatibility, native bridge dispatch or mixed-domain unwinding.

## ABI3 source addresses at foreign boundaries

Source Function prototypes and portable CodeAddress objects are independent of
foreign machine-entry representation. A foreign Function has no portable default
execution Fn. Its actual compiler/runtime/image metadata and a separately checked
portable-facing call plan/bridge are required before calls or callbacks can bind.
Neither equal64-bit addresses, compatible source names nor a decoded descriptor
issue a native entry or permit. Missing original source/ownership/identity/alias/
unwind metadata is an explicit unavailable boundary, never binary-only inference.

ABI3 call_signature.execution is mandatory, and the independently checked caller
source_plan is retained at call/invoke/tailcall. Actual/expected ABI facts and
execution graphs keep their own context brands and namespaces across every bridge
hop. Existing foreign descriptor/lifetime/exception contracts remain requirements;
the static CodeAddress migration supplies no foreign C++ execution implementation.

## As implemented

`crates/smir-portable` calls foreign code through bridges: so far from
portable code into foreign code, with integers and floats, where no
exception crosses and the foreign code does not call back. Where the
sections above leave something open, the table says how it is settled;
`tests/interp/foreign.rs` in that crate checks the engine's side on both
engines against a model of a processor, and `crates/smir-portable-foreign`
runs the same modules with machine code of both processors.

| Question | As implemented |
|---|---|
| Which bridges | An import of `kind` `foreign` whose bridge descriptor goes from the portable domain to a domain of x86-64 or AArch64, with `callbacks` `none` and `exceptions` `noexcept`, and whose call signature has plain parameters only, each passed as its value (`mode` `direct`), of integers and floats of up to 64 bits, and at most one such result. A module with any other bridge is valid and is refused as unimplemented when it is loaded. The descriptor's recipes, personality, unwind record and construction journal are verified and not otherwise used. |
| Where the foreign code is | Not in the module. The bridge's `entry` is a symbol with a `native` definition: the SHA-256 of an image, and the offset and size of the stub's code in the image's bytes. The embedder's processor has the images; the engine asks it, when the process starts, where each stub's code is. An image is so far a static ELF executable loaded at its own addresses, and the offset an offset into the file. |
| The processor | The embedder's: `interp::Foreign`, which the host hands over when a process starts. It has the images, memory of its own that the foreign code runs in, and enters code there with one argument and runs it until it returns. A module with bridges runs only under a host that grants `foreign` and has a processor of the module's kind with code at every byte range its bridges name (`EXEC_FOREIGN` otherwise, before the first step). The engine asks the processor for one thing at a time: foreign code of two threads of a program does not run at the same moment. |
| The convention | By the target domain: x86-64 with the `windows` personality takes the frame's address as Win64 has it, x86-64 otherwise as System V has it, AArch64 in X0. |
| The frame | As the table of BridgeFrame above. `revision` is 1 and `flags` 0. `signature_ref` is the bridge descriptor's identifier. `exception_lease` is 0. The states are numbered ENTERED 1, SUSPENDED 2, RETURNED 3, RAISED 4, TERMINATED 5; a frame is entered as 1. |
| Memory of a call | One block of the processor's memory, at a multiple of 16: the frame, the arena right after it, and the result at the next multiple of 16 after the arena; `result_address` is 0 if the function returns nothing. The block is given back when the call is over, however it ends. |
| The arena | The entry grammar of chapter 03's variadic arguments, for the fixed arguments in order: a header of 32 bytes (the nominal declaration of the lowered value type, zero, the size and the alignment of the argument's bytes, and the distance to the next header), then the argument's bytes at the next offset that has its alignment, then zeros to the next multiple of 8. The last header's distance is to the end of the arena. |
| Arguments | The bits of each. An unspecified value goes as zero. Poison is undefined behaviour and the foreign code is not entered: `ub_noundef_argument` where the signature says the parameter is defined, `ub_foreign_argument` otherwise. |
| A return | The stub writes the result where `result_address` says and sets `status` to RETURNED. Back in the engine the frame must be, byte for byte, the frame that was entered with that one change, and the result a value of its type. Anything else is the trap `foreign_return`: a stub that returns without saying so, or into a transition of another identity or generation. |
| Foreign code that fails | A fault of the foreign code, code that does not come back, and a processor that cannot run it or has no memory for the call, are the trap `foreign_fault`. Nothing is published as the call's result. |
| Transitions | Every crossing has an identity and a generation that no other crossing of the process has. Since foreign code does not call back yet, no thread has more than one at a time. |
| What is not done | Callbacks into portable code and nested transitions; exceptions at a bridge in either direction; pointers, records and everything else that needs a mapping; saving and restoring the foreign floating-point environment and error cells around a call; several foreign build domains; unloading. |

The crate has no processor of its own, and its tests run no machine code:
the model of a processor in them does in Rust what the stubs of the test
images do (`tests/interp/foreign/guest.c`, built for both processors into
the images the test modules name).

### The processor

`crates/smir-portable-foreign` is a processor: the emulator's user-mode
x86-64 and AArch64 cores, in an address space of the processor's own, on
any host the emulator builds for. Its tests run the stubs of the test
images themselves, on both engines.

| Question | As implemented |
|---|---|
| Images | Static ELF executables for the processor (64-bit, little-endian, `ET_EXEC`), given to the processor before the process starts. Each segment is at the address and has the permissions its header says. Nothing is relocated or linked; an image that would have to be, or that would lie where another is, is refused. The processor has the code a module names if the byte range lies in the file's part of one segment that may be executed. |
| Memory | All of it within a limit the embedder sets. Calls have a heap, zeroed when handed out, which is the only memory the engine reads and writes. Each thread of the program that crosses has a stack of its own, with a long stretch below it at which nothing is mapped. |
| Entry | With the frame's address as the convention has it: System V in RDI, with the stack as a `call` leaves it (the return address at RSP, and RSP + 8 a multiple of 16); Win64 in RCX, with the callee's 32 bytes above the return address; AArch64 in X0, with the return address in X30 and SP a multiple of 16. The x86-64 direction flag is clear. |
| Return | The return address is one at which nothing is ever mapped. The code has returned when the core faults fetching the instruction there, with the stack pointer where a return leaves it. |
| Not a return | A system call (foreign code has no operating system), a fault, an exception, an undefined instruction, a return with the stack pointer elsewhere, and code that runs longer than a limit the embedder may set. Each is `foreign_fault`; the processor records the reason in words for the embedder. Without a limit of time, code that never returns keeps its thread. |
| State between calls | The image's data lasts as long as the process. What a call leaves in a thread's core (registers, the floating-point control state) the thread's next call finds, except after a call that did not return, which leaves the thread a new core. A thread's stack is its own until the process ends. |
