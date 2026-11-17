# Candidate executable encoding 0.2

Status: exact compiler-facing candidate records, separate from historical
experimental envelope0.1/profile1. Candidate framing and ten root codecs do not
by themselves establish semantic or linked execution admission. Only the
integrator's current combined gate can freeze these contracts.

## Envelope and section directory

WIRE-001: Candidate version is exactly major0/minor2, profile2. All integer fields
are little-endian; offsets and extents are bytes. No native alignment, host pointer,
implicit padding or inferred default is part of a record. The header is48B and
directory records are24B, preserving the earlier framing geometry.

| Offset (B) | Width (B) | Header field | Candidate value |
|---:|---:|---|---|
| 0 | 8 | magic | 53 4d 49 52 0d 0a 1a 0a |
| 8 | 2 | major | 0 |
| 10 | 2 | minor | 2 |
| 12 | 2 | kind | 1 object,2 image |
| 14 | 2 | flags | 0 |
| 16 | 4 | profile | 2 |
| 20 | 4 | section_count | exact directory count |
| 24 | 8 | total_size | exact input length |
| 32 | 8 | directory_offset | 48 |
| 40 | 4 | entry_function | function ID or ffffffff for none |
| 44 | 4 | reserved | 0 |

Header calculation:8B+4*2B+2*4B+2*8B+2*4B=48B.
Objects have no entry. Images can be library images without entry; a requested
launch separately requires the entry appropriate to its admitted signature.
Section2 manifest entry, header entry, function existence and launch shape agree
at semantic admission; framing alone cannot validate that agreement.

| Relative offset (B) | Width (B) | Directory field |
|---:|---:|---|
| 0 | 2 | nonzero section kind |
| 2 | 2 | required1 / optional0 |
| 4 | 4 | reserved0 |
| 8 | 8 | payload offset |
| 16 | 8 | payload length |

WIRE-002: Section kinds are strictly increasing and unique. Checked directory
end=48B+count*24B. Payloads follow directory order at the next8B boundary;
padding is zero. No overlap, out-of-range slice or trailing bytes is allowed.
Total size is checked before allocation/arithmetic. Candidate mandatory semantic
sections cannot be empty: each starts with payload_revision:u32 and its root's
exact fields. Revisions are2 for sections1/2/3/5,1 for sections4/6/7/8/9 and3
for section10 (ABI3). Optional metadata never supplies missing executable fields.

WIRE-003: All ten semantic roots are mandatory and flagged required. Root names
and owners are integrator registry decisions, not separately allocated role IDs.

| Section | Exact root | Metaschema owner |
|---:|---|---|
| 1 | execution_types | schema/execution/candidate.json |
| 2 | runtime_symbols | schema/runtime/candidate.json |
| 3 | execution_functions | schema/execution/candidate.json |
| 4 | runtime_data | schema/runtime/candidate.json |
| 5 | runtime_relocations | schema/runtime/candidate.json |
| 6 | runtime_imports | schema/runtime/candidate.json |
| 7 | runtime_tls | schema/runtime/candidate.json |
| 8 | execution_exceptions | schema/execution/candidate.json |
| 9 | runtime_capabilities | schema/runtime/candidate.json |
| 10 | abi_contract | schema/abi/candidate.json |

Optional kinds0x8000..0x8002 retain debug/names/provenance; unknown optional kinds
>=0x8000 can be retained. Unknown kinds below0x8000 reject. No optional section can
supply a missing mandatory contract. The old0.1 registry reserves1..9 but contains
opaque payloads; its continued decode support is historical framing compatibility,
not an alternative candidate executable format or downgrade path.

## Common ordered record language

WIRE-004: [Execution metaschema](schema/execution/candidate.json) and the runtime/
ABI metaschemas define exact ordered fields. The integrator merges equal common
records and rejects conflicting definitions. JSON fixtures are logical objects;
key order is irrelevant, but duplicate keys, unknown keys, non-JSON constants,
bool-as-integer, noncanonical options and unknown union variants reject. There is
no open attribute bag. Each semantic root begins with payload_revision:u32;
sections1/2/3/5 require2, sections4/6/7/8/9 require1, and ABI root10 requires3.
Whole-object wrappers inspect each raw revision before decoding dependent members.
Earlier root bytes reject `WIRE-REVISION`; mandatory new fields are never inferred
from an older payload or inserted by the decoder.
The envelope remains0.2/profile2 and the historical0.1 framing stays separate.

| Primitive | Exact bytes | Logical fixture value |
|---|---|---|
| u8/u16/u32/u64 | unsigned little-endian exact width | integer in [0,2^width) |
| i8/i16/i32/i64 | signed two's-complement little-endian exact width | integer in [-2^(width-1),2^(width-1)) |
| bool | exactly byte0 or1 | JSON false/true only |
| token | u8 length1..63, ASCII `[a-z][a-z0-9_]*` | matching string |
| utf8 | u32 byte length, shortest valid UTF-8 | strict Unicode string, no implicit normalization |
| hex | u32 byte count, raw bytes | paired lowercase hex string |
| bytes | u32 byte count, raw bytes | codec-level byte buffer, not an alternate JSON hex shape |
| digest32 | exactly32 raw bytes, no length | exactly64 lowercase hex characters |
| vec:T | u32 count, consecutive T records | ordered list |
| opt:T | byte0 absent / byte1 followed by T | null / exactly {"some":value} |
| fixed record | schema fields in order | exact field set |
| discriminated union | token variant then that variant's fields | discriminator plus exact variant field set |

Nested options preserve all states: opt:opt:T distinguishes absent, present absent,
and present present. A bare T is never accepted as an option. Record/union values
have no additional implicit size word, sentinel or alignment. The enclosing
payload length must be consumed exactly. Counts/depth/bytes are bounded before
allocation, references or recursive semantic work. A decoder cannot skip an
unknown variant by guessing its extent.

Module reference variants are self{} / dependency{slot:u32}; entity_ref is
module:module_ref,id:u32. The dependency slot and ID name the consumer declaration
namespace. The binder verifies exact export/provider family/version/signature/
nominal compatibility and pins one deployment edge; it never interprets those
IDs as arbitrary provider internals. IDs can have the same numeric value in
different tables without being interchangeable.

## Execution roots and record map

The complete authoritative field lists are executable in candidate.json, generated
only by the SEMANTICS-owned schema_build.py. The following map fixes the meaning
of the important record namespaces; all recursive operation/terminator fields
are enumerated there, without an opaque operand payload.

| Record | Exact ordered fields |
|---|---|
| execution_types | payload_revision:u32,types:vec:type,memory_layouts:vec:execution_memory_layout |
| execution_functions | payload_revision:u32,functions:vec:function |
| execution_exceptions | payload_revision:u32,functions:vec:eh_function |
| decl | id:u32,type:entity_ref |
| function | id:u32,signature:entity_ref,abi_signature:opt:entity_ref,params:vec:decl,entry:u32,escape:token,no_return:bool,blocks:vec:block |
| block | id:u32,phis:vec:phi,ops:vec:operation,term:terminator |
| phi | result:decl,incoming:vec:incoming |
| incoming | predecessor:u32,value:u32 |
| normal_edge | target:u32,results:vec:decl |
| unwind_edge | target:u32,exception:decl |
| storage | type:entity_ref,layout:entity_ref,nominal:opt:entity_ref,abi_binding:opt:entity_ref,bytes:u64 |
| execution_memory_layout | id:u32,type:entity_ref,size:u64,alignment:u32,access_bytes:u64,fields:vec:execution_memory_field,element:opt:entity_ref,stride:u64 |
| execution_memory_field | value_index:u32,bit_offset:u64,bit_width:u64,layout:entity_ref |
| eh_function | function:u32,actions:vec:execution_action,regions:vec:region |
| execution_action | id:u32,program:entity_ref,recipe:entity_ref,captures:vec:execution_capture |
| execution_capture | parameter:u32,type:entity_ref,source:execution_capture_source |
| region | id:u32,parent:opt:u32,blocks:vec:u32,exit_actions:vec:u32,handlers:vec:handler,escape:token |
| handler | id:u32,selector:u32,kind:token,nominal:opt:entity_ref,entry:u32,cleanup_actions:vec:u32,catch_copy:opt:u32 |

Size/access/alignment are bytes; memory field extents/stride are bits. ABI_signature
names section10 call_signature, storage.layout section1 physical layout,
storage.abi_binding section10 storage_binding, action.program section10
cleanup_program, action.recipe section10 adapter_recipe. Handler cleanup/copy
IDs name function-local execution actions. Runtime helpers use the exact per-name/
contract abi_namespace and target_namespace in the hashed helper catalog; the
abi_required summary boolean cannot replace that map. Optional_storage_binding
means absent or a reference to the exact binding table, never nominal fallback.

Handler id is an alpha-local control identity. Selector is a semantic i32 code,
1..0x7fffffff for typed/catch-all entries; cleanup/no-match is0. Selectors are
function-local and remain ordinary integers through liveness and comparison.
Actual ABI-normalized RTTI types biject selectors within each function, including
one separate catch-all key. Every typed entry requires reflexive normalization,
even a single entry. Negative legacy filters are outside this private C++23
profile and receive E-EH-FILTER before emission. See chapter02 and the exact schema.

The assigned incompatible function-address cut uses these exact additions:

| Record/variant | Exact ordered fields after discriminator |
|---|---|
| type.code_address | id:u32 |
| operation.code_bind | results:vec:decl,operands:vec:u32,plan:entity_ref |
| operation.code_erase | results:vec:decl,operands:vec:u32 |
| operation.call | results:vec:decl,operands:vec:u32,target:target,unwind:token,source_plan:opt:entity_ref |
| terminator.tailcall | target:target,operands:vec:u32,source_plan:opt:entity_ref |
| terminator.invoke | target:target,operands:vec:u32,normal:normal_edge,unwind:unwind_edge,region:u32,source_plan:opt:entity_ref |

source_plan is mandatory syntax. None explicitly selects a generic call and issues
no source-call fact. Some names the actual caller plan C in CallSignature namespace,
including original DEP consumer expectations. Its mandatory execution reference
must structurally equal target.signature, and this_type=None/vtt=false identifies
an ordinary plan. It is independent of any earlier code_bind plan B. Neither Fn,
a token nor a retained permit supplies a missing C. Actual source entry additionally
requires genuine current-site/SSA/activation facts and A->C plus B->C compatibility.
The static schema and verifier do not implement those runtime producers.

Separately assigned runtime_live_state revision2 appends
binding_permit:opt:u64 LAST after range to execution_live_payload.pointer and
execution_origin_span. None is explicit for DataPtr, labels, CodeAddress and
legacy CodePtr. Some is positive and valid only for callable code with its original
runtime-issued permit. Parsing the number issues no authority. Full-bit restoration
retains that original permit; integer recovery is a distinct registry operation.
Object exception root8 remains revision1. These duplicate live record definitions
must be byte-for-byte equal in the execution and runtime metaschemas.

Operation is a closed token-discriminated union. Every variant begins with
results:vec:decl,operands:vec:u32, then its exact fields. Family contracts specify
arity and semantic validation in operations.py; [execution semantics](02-execution.md)
fix poison, result commitment, math, memory and exception behavior. Targets are
explicit direct/function, indirect/value or import/import refs, each with exact
execution signature. No existing lifted-ISA operation is interpreted as a portable
ABI operation by default.

| Family | Explicit operation surface |
|---|---|
| integer | add/sub/mul/shifts/div/rem/bitwise/rotates/counts/abs/bswap/bitreverse |
| values | constant/copy/freeze/icmp/select, aggregate/vector extract/insert/shuffle |
| cast/pointer | trunc/zext/sext/bitcast/ptrtoint/ptrtoaddr/inttoptr/ptr_offset/address_of/block_address |
| FP | add/sub/mul/div/fma/sqrt/frem/sign operations/six min-max/fcmp/format and integer conversions |
| fenv | get/set/pack/unpack/clear/raise/test |
| memory | ordinary/atomic load/store/RMW/cmpxchg/fence/bulk copy-move-set |
| effect | effect_barrier, observable even without a memory write |
| helpers | alloca/lifetime/stack save-restore/TLS/va*/setjmp/longjmp via exact imports |
| call/EH | call/landingpad/catch begin-end/journal, exact terminator union |

Types use token kind then id:u32 and kind-specific fields: int/raw bits:u32;
float format:token; data_ptr space:token; code_ptr signature:entity_ref;
code_address has only id:u32 and no signature; array/
vector element:entity_ref,count:u64; struct fields:vec:entity_ref; function params/
results:vec:entity_ref,variadic:bool,param_noundef/result_noundef:vec:bool,cc:token;
exception/fenv/stack_mark/va_list/journal have no further fields. Function variadic
must be false after decoding; source variadic is ABI metadata with fixed lowering.
Logical vector/aggregate width excludes all physical padding.

## Hashes, linkage and live state

INT-D007 module identity is SHA-256 of `SMIR0.2\0`, profile:u32le, and semantic
section records in order, each id:u16le,length:u64le,payload. All ten sections
participate. Only the exact self-identity digest field in manifest is zeroed;
self references are tagged. Debug/carrier bytes are excluded. Dependency identities
are declarations/deployment edges, avoiding a hash fixed point for cyclic modules.
The common encoder provides canonical payload bytes; decoded or unhashed producer
JSON alone cannot claim module identity.

INT-D011 execution shape identity is independent of module-local numbers; nominal
ABI fingerprints and service/helper catalog digests use their own domain and
canonicalization. INT-D010 helper catalog uses SHA-256(`SMIR-HELPERS-V1\0` followed
by sorted-key compact ensure_ascii JSON of the WHOLE catalog, no trailing newline,
no excluded fields, duplicate keys/non-JSON values rejected). Hash the actual
accepted catalog revision; do not retain an old hash after namespace changes.

Runtime live records are exact state-transfer contracts, not executable file
payload authority. execution_live_value contains a qualified execution type and
one exact poison/undef/scalar/aggregate/raw/pointer/handle/fenv payload. Raw shadow
contains separate same-width bits/poison/undef plus sparse origin spans; sparse
spans preserve original pointer bit index, domain, allocation generation and
optional range. A live numeric object/code/handle ID can only refer to a retained
runtime registry object; decoding does not register it. Restoring all values and
leases validates types, generations, thread/activation ownership and stack/code
ranges before publication.
The origin-span object is opt:u64: Some names a registered object/generation;
None requires generation0 and can retain only unprovenanced pointer/range taint.
Neither encoding issues authority. Restricted raw numeric conversion remains UB,
whereas unrestricted byte->number conversion strips origins without exposure.

Execution_progress.elementwise names activation/block/operation,next_lane,typed
observed prefix and input snapshot. Runtime-owned continuation/journal/native
CPU records add exact commit stage, action cursor, captures and issued tickets.
Memory bytes and shadow move together. A second ISA/foreign personality, stale
code generation, duplicate ticket completion or fabricated journal instance
cannot become valid because its bytes satisfy the record grammar.

Absolute ranges encode lower:u64,upper:u64,upper_is_limit:bool,empty:bool. Limittrue
requires upper=0 and denotes2^64; otherwise upper is ordinary. Emptytrue requires
lower=upper=0,limitfalse and permits no comparison/access. Emptyfalse[0,0] retains
the closed-comparison point0. Nonempty lower cannot exceed the effective upper;
mathematical restrictions clip to representable addresses. This preserves the
permitted
last-byte mapping [2^64-1,2^64). Known tombstone pointer provenance is preserved
as a value; it is not dereference/call permission. Typed live validation returns
no executable authority: restoration also requires the runtime's sealed one-use
handoff over all canonical bytes and parked epoch, preventing altered values,
ranges, event order or registry generations from becoming an injected snapshot.

Current runtime-owned records also carry source_linkage immediately after kind
on symbols/declarations/exports, and segment.abi_binding immediately after nominal.
Linkage is none/c/cpp; C data boundaries require the actual ABI C-view comparator,
while C++ identities remain strict. Defined allocation storage is array<raw8,N>
for allN including0, with count:u64 and stride8bits. Source maximum2^61-1B fits all
u64 bit extents; concrete value/reference quotas are separate. Allocation bindings
cannot stand in for field/value access bindings or source comparison masks.
Source storage paths are vectors of exact UTF-8 name components in the actual
original-owner nominal graph; dots and slashes do not split a component. Accepted
LLVM-PROD009REV2 capture metadata uses `$captureN`, where N is the canonical decimal
index among all declared nonstatic fields. Source-input and selected-layout names
agree, and V2 hashing retains those names/order/type edges. Generic ABI validation
checks the reserved prefix/index/nonanonymous/non-bitfield predicate for any record;
actual lambda/implicit-field origin is a frontend producer obligation. Execution
bit layouts acquire no lambda-origin restriction from this source metadata rule.
Native definition(image,domain,RVA,size) carries no portable token authority.
Its registered entry facts include independent execution shape and separate
physical native_cc / certified bridge_abi, never a host or C++ ABI guess.

## Admission and diagnostics

WIRE-005: Validate bounded framing, canonical record parsing and revisions, then
all type/nominal/storage/reference graphs and function CFG/SSA. Actual ABI evidence,
module dependency/SCC/symbol/import/relocation/TLS/data/capability checks are required
before creating executable authority. Native metadata and runtime registry records
require independent issuer evidence. Artifact decoding returns an explicitly
unverified candidate; reference component verification still reports that linked
runtime admission is required. No magic/version success executes an envelope.

An external TLS declaration carries the runtime schema's explicit symbol_kind=tls.
Its DEP reference is resolved through actual export/deployment/definition selection,
not reinterpreted as a provider segment ID. An issued metadata view preserves the
provider-owned SELF references through semantic verification; generation, module
pin and current logical-thread reservation checks remain separate runtime gates.
Prepared metadata permits cyclic verification without publishing executable state.

```text
bytes -> unverified envelope -> exact ten roots -> graph/ABI/SSA verification
                                                       |
                         dependency/SCC/runtime admission + independent evidence
                                                       |
                                            executable registry authority
```

The component verifier order is root shape/revision, type/layout graphs,
function declarations/ABI lowering, then functions in encoded order: CFG, reach,
dominance, definitions, phi/operation/terminator types, regions/capture PRE uses.
Local diagnostics are symbolic; their code names are not separately allocated
public numeric IDs. Multiply malformed records need not produce a cross-engine
identical first error unless the integrator assigns that stronger contract.
Unknown enum/token values reject at their semantic predicate; token syntax alone
is insufficient validation.

Default framing limits1GiB/1024sections are integrator policy. The reference
record defaults8MiB bytes,100000nodes/list elements,64nesting; function/SSA limits
are separately stated in chapter2. Reject/resource exhaustion must precede an
allocation or host-language overflow that bypasses bounds. Codec complexity is
O(bytes+nodes), bounded stack; full dominance/type/evidence validation has its
own stated complexity. Count and byte arithmetic never wraps.

## Conformance and historical compatibility

The independent Python/Rust/C++ candidate framing codecs are integrator-owned.
SEMANTICS provides a second ordered-record implementation plus verifier/evaluator,
integer Rust witness, Rust path-exclusion SSA witness, strict native FP probes and
positive/boundary/rejection fixtures. Round-trip is checked but is not sufficient:
golden bytes, every truncated root prefix, wrong-option states, wrong-edge IDs,
poison bits, physical layout mismatch and actual cross-section ABI witnesses
exercise distinct oracles. A compiled probe is counted as native only after its
observed run, with exact finite sample and excluded cases in the receipt.

Legacy `records.json`, types.json, floating.json, exceptions.json and raw-bits.json
remain preserved with their original draft revisions and CLI behavior. Historical
integer field names/opcodes and widths1..65535 apply only to that local revision.
They do not override candidate tokens/qualified refs/payload_revision or change
existing lifted-ISA paths. Legacy `reference.py pack` writes separate local draft
payloads, not an executable candidate image. Current candidate tools/tests reside
in tools/smir-format/execution/candidate/ and test_candidate*.py.

| Assumption | Dependent result | Falsification probe |
|---|---|---|
| W-A1 shared common records are byte-identical at consumed revision | merged codecs | schema conflict, stale source hash, mismatched option wrapper |
| W-A2 metadata excluded from module identity cannot alter semantics | carrier packaging | move/strip debug without changing semantic payload/hash/admission |
| W-A3 registry authority is independently issued | live restore/import/code validation | valid bytes with stale/unissued identity must reject |
| W-A4 legacy and candidate interfaces stay distinct | compatibility | reject0.1 opaque sections as0.2 executable roots; never infer missingABI10 |

High impact: malformed bytes can be rejected while forged or inconsistent semantic
records still require graph/runtime checks; neither validation layer substitutes
for the other. Medium impact: source-less packed LLVM storage must select explicit
physical layout and exact optional source storage_binding, avoiding nominal-ID
collisions. Low impact: preserved legacy witnesses remain useful independent
math/codec checks while their receipts are historical after artifact changes.

Primary-source identity and license are in [sources.json](schema/execution/sources.json)
and integrator [PROVENANCE](PROVENANCE.md). All wire shapes/hash domains here are
project contracts; no uncaptured RFC/ISO standard is claimed as their source.

## Experimental Root3 revision 3 context binding

The runtime-owned ordered carrier grammar
[schema/runtime/source_carrier_records.json](schema/runtime/source_carrier_records.json)
with SHA-256 c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0
assigns Root3 revision 3 to `execution_functions_v3`: payload_revision=3,
ordinary functions in encoded order, then the complete required source_contract.
Root1 remains revision 2; ABI Root10 remains revision 3. This is a separately
selected experimental grammar, not an extension accepted by legacy revision 2
readers. The generic candidate CLI and Rust executable reader remain revision 2
until independently migrated. Structural carrier decoding is not admission.

The source snapshot hashes the actual complete ordered Root3 bytes, including
embedded source tables and any observer syntax. It retains the original content
identity and all ten roots. The original module digest still uses the SMIR0.2
algorithm, normalizing only its own manifest.identity bytes, now including the
actual revision 3 payload as bytes. No synthetic revision 2 digest is substituted.

For a revision 3 source stamp, let B be the 32-byte SHA-256 digest of the original
merged revision 2 record grammar and R the 32-byte SHA-256 of the complete carrier
grammar file (including field caps and scalar refinements). The schema digest is
`SHA256(b'SMIR_SOURCE_ROOT3_V3\0' || B || R)`. The two digests are raw 32-byte values,
not their hexadecimal text. Revision 2 source stamps retain the exact old digest.
Any active grammar/cap/scalar change invalidates the pinned version 3 constructor.

The constructor uses metered ordered records with at most 256 UTF-8 octets per
text, 256 elements per list, depth 64 and 1 MiB per encoded root; aggregate payload
bytes and the tighter actual factory tree/graph limits are checked before ABI/body
factories. Hex strings remain canonical lowercase even-length bytes with their
separate byte/width bounds. Body verification preserves all ordinary operations
and source metadata in the actual version 3 root, rejects observer execution, and
issues only the nonexecutable `V3BodyChecks` described in chapter 2. Public source
constraints consume that exact embedded contract; no caller report or decoded
structure creates executable or source-registry authority.


The actual ordered source_journal_observe variant is also consumed by the fixed
version3 static body predicate. Its one result is an ordinary Journal SSA; empty
operands do not make its source ScopeValue/ReturnAdoption fields ordinary SSA.
Those source IDs use their existing nonsentinel bounds; physical type, block and
ordinary result IDs retain full u32 bounds. No wire field/cap/tag or base revision2
SCHEMA is dynamically patched. V3BodyChecks appends only a process-local tuple of
original observer coordinates; it is neither serialized admission nor a caller
proof accepted by R. Full module/root/schema hashes retain the original observer
and complete source contract bytes. Semantic source constraints remain a second
real pass with original owner/stamp/B custody. Static success does not enable
Machine/source-registry/production execution or skip source obligations.
