# Candidate ABI admission context

`candidate.verify(document, context)` validates ordered section10. It returns
counts and payload SHA-256 with `admitted_for_execution=false`. It neither creates
runtime objects nor issues executable tokens. Call it after canonical decode,
section1 type/memory-layout verification and declaration/deployment resolution;
then verify section3/8 source bindings and the runtime roots on the same immutable
module graph. The integrator owns combined admission and compiler freeze.

`Context` has these fields, in constructor order:

| Field | Exact caller-supplied meaning |
|---|---|
| module | current admitted module resolver identity |
| execution(ref) | actual section1 type shape with recomputed S028 identity |
| symbol(ref) | actual admitted symbol facts below |
| metadata(ref) | immutable admitted data bytes, not a producer string/hash |
| modules | other ABI contracts keyed by resolver module identity |
| bindings | owner/slot consumer declaration to provider-private nominal ID maps |
| native_type(ref) | independently admitted nominal record for that foreign type |
| native_unwind(function_ref) | exact independently admitted normalized unwind recipe |
| families | module -> (namespace,name,ABI major), independent of artifact/minor |
| memory_layout(ref) | actual admitted section1 execution_memory_layout |
| native_domains | domain ID -> independently admitted complete domain record; default{} |
| native_layout(type_ref) | independently admitted full object_layout for foreign type; default unavailable |

All references are module_ref self{} or dependency{slot:u32}, followed by id:u32.
The id of a dependency reference is a consumer declaration, not a private provider
ID. Namespace is selected by the field: source nominal, call_signature, bridge,
recipe, journal or storage_binding. `namespaces.Entities` demonstrates closed
namespace resolution; `Entity.as_namespace` rejects wrong-table substitution.
Existing identical numeric IDs across different tables remain legal.

execution(ref) returns kind, the complete original section1 `record`, and a lowercase64-hex `identity` derived from actual
admitted type roots, never an accepted file-provided string. Required shape fields:

| Kind | Additional fields used by ABI verification |
|---|---|
| int/raw | bits |
| float | format binary32/binary64/binary128 |
| data_ptr | space guest_data |
| code_ptr | signature_identity |
| code_address | exact64 value bits, no signature child |
| array/vector | count,element_identity |
| struct | fields: ordered execution identity list |
| function | params/results: ordered identity lists,cc,variadic,param_noundef,result_noundef |
| exception/journal/stack_mark/fenv | exact kind, not an integer or ordinary pointer |

`ExecutionShapes.describe` independently computes this normalized view from raw
section1 records. SEMANTICS `RootContext.abi_execution` adapts its actual Types
resolver to the same interface. Equality is rooted labelled bisimulation with
ordered child edges, including function parameter/result partition. Shape equality
does not establish source C/C++ compatibility or live object authority.

symbol(ref) returns at least kind,signature,domain. signature is the exact nominal
function reference for a function. Native functions additionally carry actual
code_size and, for packet entries, bridge_abi sysv64_frame/win64_frame/aapcs64_frame.
The actual native definition binds immutable guest image/domain/RVA/extent and
independently registered compiler/CC/code/CFI facts. Native definitions cannot be
address_of/function_token targets for portable code; use an admitted foreign
import and its bridge token. The native CPU adapter executes native code; no
section3 portable-body or host-address fallback is permitted.

native_domains and native_layout are required for any foreign domain/type with
storage. Domain identity binds actual image build/compiler/runtime/library and
stable ABI configuration. Exact native layout includes compiled vptr/slot bindings,
where source nominal hashes intentionally exclude compiled body/symbol IDs. Native
unwind evidence includes full code/metadata ranges, CFI/action/landing recipes.
The registry must originate from independently admitted image/compiler metadata;
copying section10 as its own evidence is invalid. Fixtures under conformance/abi/
are synthetic authority inputs and explicitly do not establish such a producer.
Portable-only contexts need no native evidence and reject unavailable foreign
metadata deterministically. Callbacks never default to host ABI or host pointers.

`NominalGraph.compatible` checks ordinary source declarations, including legal
incomplete class references. `boundary_compatible` additionally requires complete
by-value parameter/result storage on both sides; a function hash or indirect
pointer shape alone is insufficient. Both c_linkage function boundaries invoke
an explicit C ABI projection. `data_boundary_compatible` is for an independently
verified source_linkage=c data symbol: provider storage is complete, while a
consumer incomplete object/array may obtain only its address. Complete FILE*
objects can hold pointers to incomplete FILE types. Ordinary C++ linkage remains
strict. C mirror eligibility, character typedef mappings and constructor identity
rules are in chapter3 and c_boundary.py.

`verify_captures` checks S026 recipe formal-ID bijection, recomputed execution type
and injected exception/journal brands. The execution verifier supplies PRE-trigger
SSA dominance and exact program/instance binding. Neither recipe names nor source
call_signature parameter positions substitute for explicit cleanup_program.params.

Reference tools deliberately have finite quotas. A quota rejection is not a proof
that the source language cannot express a type, and is not silent conformance.
No returned dictionary from these tools is production admission authority.

Source va_list is ordinary32-B/A8 array-wrapper storage. The thread/activation/
generation keywords of candidate_varargs.Cursor.arg, and protocols.VarArgs.arg's
thread keyword, name the registered ORIGINAL COOKIE OWNER. The runtime helper
obtains that tuple from the process cookie registry, independently of its actual
executing visitor. Another synchronized logical thread/callee may borrow the list;
the owner activation, arena and nominal-table lease must remain live. va_copy
retains that cookie and an independent cursor; it does not extend owner lifetime.
Owner return/unwind revokes all copies. Ordinary source record/frame storage is
distinct from the opaque execution va_list handle, which is not spillable.

`signature_compatible(left,right,left_owner,right_owner)` resolves the signature
namespace and compares complete lowered call plans, including hidden parameters,
noundef, temporary geometry, varargs protocol and lifecycle recipe interfaces.
The runtime callback form `(source,before,target,after)` delegates to
`graph.signature_compatible(before,after,source,target)`. Boundary signature refs
are SELF-local; nested nominal refs may be dependency-qualified.

`catch_compatible(left,right,left_owner=None,right_owner=None)` accepts only
frontend-normalized caught RTTI types. References, arrays, functions and void
roots reject ABI_CC_CATCH_NORMALIZATION. Ignore top-level cv only; preserve
pointee cv, C++ character/builtin identity, library cohorts and private source
ownership. Catch-all None is a separate execution-verifier key.

`Context.native_personality(ref)` returns the independently registered exact
personality_binding, including profile/prototype/phase/translation flags. It is
required for foreign personalities and cannot self-certify section10. Native
symbols carry both actual `native_cc` and independent `bridge_abi`; C++ ABI
family does not imply either. Multiple foreign domains retain separate build
certificates while sharing one selected guest ISA and OS personality.


ABI3 call_signature.execution is mandatory and selects the actual closed portable
Fn for every lowered call check. Function.execution is optional source metadata:
Some requires an already checked local ordinary plan for the exact nominal key
and structurally equivalent Fn; None still validates prototype grammar. The
execution callback's full original record is required for structural comparison
of optional defaults. Identity-only evidence rejects ABI_CC_EXECUTION_EVIDENCE.
CodeAddress has no execution-signature child; typed internal CodePtr remains a
separate execution category.

The bounded ordinary comparator takes actual SourceCallContext, original actual
CallSignature qref, expected SourceCallContext, original expected CallSignature
qref, and keyword-only existing SourceQueryBudget. Both views must be genuinely
issued and retain their own source snapshot and actual ledger. module_family()
uses the captured original root2 namespace/name/ABI-major tuple; minor versions
are deliberately excluded. Dependency plan queries retain the original consumer
declaration and resolve its own SELF ABI expectation, never provider-private IDs.
