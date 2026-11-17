# CC-L contract closure

CC-001 keeps the complete platform endpoint. This package supplies compiler
contracts and independently executable references; source TargetInfo/backend,
production runtime/JIT, hosted-library ports and native qualification are later
implementation gates. Their absence is not a circular prerequisite for deciding
a lowering contract. Contract acceptance and actual implementation remain separate.

The previous draft's generic E-*-CONTRACT rows are superseded for required
constructs by [lowering-contracts.json](lowering-contracts.json). Every required
instruction family has operand/result semantics, exact expansion steps,
poison/UB rules, effect/frontier behavior and helper family requirements. All
69 opcode/16601 intrinsic/115 attribute/22 type rows remain exhaustive at the pin.
Rows with diagnostics are optional nonbaseline target/language/instrumentation
extensions or invalid pass-only IR, not missing core port contracts. Unknown
future source intrinsics fail the classification witness. No emitter is implemented.

The accepted logical program carrier is AS1 with
`-pe1:64:64:64:64-P1`, stable external state and zero null bits; data/storage
addresses stay AS0. Parameterless `smir.code_binding` and `smir.source_scope` are
compiler-only unsized SSA carriers, not new execution types or private issuers.
Their actual source/Fn/lineage constraints, forbidden storage/freeze/public ABI
and exact group/effect rules remain mandatory. LLVM's parser/verifier establishes
structural support only. AS1 does not identify a portable value domain: BlockAddress
retains its computed-label diagnostic, and actual source/descriptor context must
select CodeAddress versus typed code/native/label values. The allocation does not
relax ordinary source-plan guards or close nonordinary CPP caller projection.

[frontend-contract.json](frontend-contract.json) fixes target predefines,
macro exclusions, scalar aliases, storage representation, module metadata,
operand bundles, driver/link/LTO options and sysroot/site binding. Standard
compiler/FP-limit/language macros derive from the pinned Clang macro generator
using this fixed TargetInfo. Over90 comparable ABI predefines are checked against
an explicitly configured existing-target Clang witness; SMIR-only and ordinary
non-lock-free macros are never inferred from that native target.

The selected libc++/libc++abi/libunwind configuration is the ABI-owned
`schema/abi/site.json`; its canonical hash is a compiler/nominal ABI input.
Generic Itanium/ABI1/__1, external thread API, RTTI/EH, filesystem/localization/
wide/Unicode/timezones and logical unwinding are chosen now. Building these
libraries and implementing their service backends are later gates. Upstream
language/library gaps remain separately recorded in upstream-gaps.json.

## Core operations and explicit helpers

The compiler emits direct candidate core records for arithmetic, FP, memory,
atomics and ordinary control flow. These records carry complete closed profile
semantics/attributes. A backend's choice of an internal native helper is an
implementation detail; no ambiguous guest import lookup is permitted. S-018
acknowledges this distinction. The compiler's `bindings.py` checks exact candidate
operation/terminator names and explicit helper catalog names.

Explicit imported libcalls/intrinsics use section6 internal records with exact
namespace/name/version/catalog, instantiated function signature/type parameters,
ABI layout and `runtime_helper_options`. R-010 fixes ordered option fields:
alignment/scope/order/failure_order/weak/comparison/mask/rounding/exceptions/
predicate/target/flags. Missing or contradictory static context rejects. A
fully configured fp_compare import includes its predicate; two bare float
arguments alone do not specify a comparison. No untyped attribute dictionary.

Raw bN/int widths support LLVM's1..2^23 range independently of source BitInt's
65535-bit limit. Per-bit poison and sparse origin spans preserve complete pointer
origins across copies/chunks. GEP expands each checked index/stride/offset step;
`inbounds` permits tombstoned original allocation bounds and checks intermediate
addresses including one-past. Dereference separately validates liveness.
`inrange` carries derived access/comparison constraints. Unused bad pure pointer
calculations poison instead of causing eager memory traps.

Ordinary atomics may strengthen to SC through arbitrary-size lock-backed helpers.
Failure ordering is not rejected merely for being stronger than success at this
LLVM pin. C generic storage CAS, LLVM precision CAS and C++ value-representation
CAS use distinct admitted masks. C++ padding normalization needs the portable
clear-padding/layout equivalent; an upstream fallback is not a contract waiver.

**atomic_flag is distinct:** source size1 B/align1 B, canonical0/1, mask01,
dedicated test/test_and_set/clear guaranteed lock-free progress. Ordinary bool
macros remain0. The dedicated sysroot stdatomic.h/libc++ port routes flag operations
to dedicated helpers, preserving memory order/volatile semantics. Registration
and lifetime setup precede publication; valid hot operations use lock-free
metadata/pinning and no mutex/global SC gate or paused guest-worker dependency.
Reclamation may wait outside hot operations. Foreign aliases must share the
coherent registered flag protocol; incompatible sharing rejects before entry.
Wait/notify is a separately blocking interface. Actual all-host lock-free runtime
implementation is a later gate; choosing and testing this progress contract is
required now (LLVM-CC007/ABI-CC010).

## Identity, COMDAT and independent compilation

[canonical-contract.json](canonical-contract.json) is the exact *comparison view*
and hash/deployment contract. It is not an executable payload. canonical.py
checks reference declarations/shape and normalizes producer-verified semantics;
full CFG/SSA/type/EH verification remains the candidate semantic verifier's job.
Semantic numeric constants are never guessed to be IDs. Local references are
explicitly tagged; type/symbol/region identities come from admitted normalized
schemas. Symbolic relocation target identities and addends remain in bodies.

```
LLVM module + accepted ABI/semantic records
                    |
       verified typed comparison view
                    |
     CFG/value ID normalization + refs
                    |
       canonical member/group content
                    |
  COMDAT selection + independent ABI checks
```

Module content SHA256 uses accepted INT-D006's `SMIR0.2\0` domain, profile u32,
then ID u16/length u64/payload for sections1..10. Only the exact own-identity
field is zeroed. Optional metadata/carriers are excluded; equal byte patterns
inside user data are preserved. Module identity may change on alpha renaming;
COMDAT exactmatch body identity does not. These hashes do not prove program
semantics or ABI compatibility. The standard-library SHA256 result is independently
checked with the system shasum executable on a known explicitly constructed preimage.

COMDAT any chooses one whole group without requiring equal O0/O2 bodies or
identical helper-member sets. Any/largest/samesize compare ABI on every common
member across inputs. Exactmatch requires full membership equality. Selection
precedes provider/SCC publication; a needed loser-only member absent from the
winner rejects at binding, rather than combining members from different groups.
Exactmatch compares normalized bodies/relocations/types, not private numeric IDs.
Largest/samesize use the accepted portable key-member extent: canonical comparison
UTF8 body length for functions, actual allocation bytes for data/TLS. Function
extent is recomputed, never trusted from a producer counter. ABI storage extent
policy separately governs whether data definitions may differ. nodeduplicate
retains all copies; the project noduplicates policy rejects repeated keys.
Other external strong-symbol collision rules still apply.

INT-D007 separates logical dependency family, module artifact content and runtime
generation. External entity IDs index consumer declaration tables by dependency
slot; explicit maps bind provider export IDs. No content-hash fixed point is needed
for A->B->A because required code bytes reference logical family/declarations,
while a separate admitted deployment manifest pins both artifacts together.
`deployment.py` independently verifies all declarations/signatures/nominal types/
versions/generations and returns binding maps only after the complete set passes.
No constructors or tokens exist in this model. Replacing ABI-compatible B's body
changes deployment/content identity without recompiling A. Source internal/ODR
nominal identity follows ABI source-unit/entity rules; exact artifact/generation
still controls ownership and live authority.

## Observed witness scope

New header-free pinned Clang fixtures exercise aggregate copies, TLS, volatile,
32-B atomic library calls, varargs, binary128 conversion, fixed vectors, C++
EH/RTTI/returns_twice, strict FP and ordinary coroutine frame/resume/destroy/cleanup.
Actual pinned Clang stdatomic.h supplies a native1-B flag exchange/release-store
witness; this does not prove portable helper lock freedom. Hand-authored LLVM24
fixtures preserve b128 load/store/freeze and stronger CAS failure order.

Reference models cover alpha-renamed CFG/value IDs, numeric constants, COMDAT
selection/ABI rejection, exact content-hash masking and A->B->A deployment with
O0/O2 replacement and invalid signature/artifact/version rejection. GEP witnesses
cover signed-vs-unsigned wrap, intermediate bounds, all-zero/null and tombstones.
They execute no portable SMIR and qualify no native guest/JIT or hosted sysroot.

Accepted INT-D009 / INT-010 revision2 fixes source fenv_t32B/align8 and
femode_t16B/align8, fexcept_tu32; flags63 preserve DENORM only as explicit sticky
extension, arithmetic raises five IEEE causes and never input-denorm. Source
traps field must0. VM diagnostics are separate private IEEE-five policy, never
captured/changed by C save/set/hold/update. Ambient rounding has four generic
codes; nearest-away is per operation only. Defaults are real readonly guest data
objects with normal relocations/provenance. Raise/update versus set/restore
no-trap semantics and API-specific errno behavior are explicit, not host defaults.

A pinned libc source difference is separately documented in upstream-behavior.json:
fesetexceptflag clears unselected flags. An actual-source controlled-primitives
witness confirms the bitmask effect; no native libc fenv qualification or uncaptured
ISO clause is asserted. The port must preserve unselected flags per INT-010.

Rounding-to-integer intrinsics lrint/llrint/lround/llround return a concrete
freeze(poison) choice on overflow; ordinary fptosi/ui returns poison. The exact
Fraction reference and tests distinguish127.5->127 truncation from128 rounded
overflow->concrete0, NaN/infinity, saturation and all five operation modes.
is.fpclass uses raw bit classification with all ten classes, never host signaling
NaN arithmetic. Sincospi requires exact pi-argument reduction; multiplying by a
rounded pi constant first is not the selected correctly-rounded contract.

Mandatory powi legalization precedes all LLVM optimizations, not merely backend
emission. The actual pinned constant folder truncates a wide exponent; the native
LLVM-only replacement witness covers normal values, exponents wider than32 and64
bits, negative/MIN exponents, parity, zero exponent and width1 without overshift.
The exact ordinary multiplication sequence preserves operand FP semantics;
exponent freeze prevents an unused poisoned intrinsic from becoming branch UB.
PassBuilder default, full/ThinLTO and imported-module hooks are enumerated in
integration.md. No first-wave LLVM source or backend emission is introduced.

S026/ABI018 cleanup actions bind formal IDs and PRE-trigger typed captures to a
full cleanup-function CFG; arbitrary branches/loops survive and cleanup occurs
once. S027/S031/ABI019 separate bit-stride execution layouts from alias-faithful
source storage bindings; differently arranged temporaries require explicit code.
S030/ABI020 snapshots are copyable32-B values with pure raw256 pack/unpack; an
invalid unpack returns poison snapshot,false without changing current state.
S032 names function abi_signature and R017 requires closed per-helper/contract ABI
namespaces. A nominal ID with the same integer as a signature or bridge is not
a valid substitute. Joint owner admission tests, not this ACK, close that gate.
The actual catalog is now checked for every contract. Portable call_dispatch uses
signature; foreign/callback uses bridge; journal_advance uses cleanup_program;
varargs_pack uses signature plus target recipe; va_arg uses promoted nominalT.
TLS initialization uses no ABI ref plus TLS target; destructor wrapper uses
signature; eh_allocate uses thrown nominalT and subsequent EH helpers use no
fabricated staticT. The live admitted exception/handler/action context supplies
their authority. An unused ABI/target ref rejects. bind_context tests deliberately
reuse integer7 across all namespaces and reject wrong-table fallback; actual
record relationship/lease validation remains the owner/root verifier's job.

INT-D010 catalog identity hashes all fields as canonical ASCII JSON with the
SMIR-HELPERS-V1 NUL domain; duplicate keys/nonfinite JSON/selfdigest reject.
candidate-bindings.json records this protocol identity separately from artifact
SHA256. INT-D011 uses the exact S028 rooted labeled bisimulation quotient for
resolved execution shapes; independent pair-elimination agrees with actual
Types.digest on curated shared/recursive graphs. Nominal identity and live
artifact/generation authority remain separate from shape equality.

LLVM-CC014, explicitly acknowledged by INTEGRATOR, selects LangRef-permitted
constant0 for readcyclecounter/readsteadycounter on this baseline. Hosted clock
services remain separate. Resumable debugtrap receives E-EXT-DEBUGGER for an
optional non-ISO debugger profile; a terminal trap cannot represent its continuation.
Objectsize uses exact conservative0 minimum/all-ones maximum, with null handling
per flags, so no missing runtime allocation-query operation is invented. A stronger
optimizer-proven source bound remains permitted. These choices sacrifice counter/
extent precision, with no hosted language requirement disabled.

The latest exact constrained binding inventory contains49 source intrinsics.
Basic arithmetic/conversions and both compare forms use direct core; signaling
fcmps explicitly sets signaling=true. Remaining libm uses whole-operation helpers.
Constrained powi exponent is FIXEDi32 at this pin (TableGen oracle), unlike ordinary
any-scalar-int power. It remains constrained metadata through optimization; no
invented generic-width private-call ABI is required. The temporary proposal was
withdrawn after that source check. Full-width ordinary preoptimization remains.

LLVM-CC019 selects executed-step power semantics: shift magnitude before deciding
whether to square, so no final unused square; no unchosen product/reciprocal updates
flags. Exponent0 performs no FP arithmetic, including signaling-NaN bases. Source
C real pow stays a separate contract. Four LLVM-CC020 integer-round helpers return
signed integer width exactly, invalid->concrete0 with no inexact; valid lrint can
raise inexact, lround never does. They publish one flag/result frontier. Compound
rint+fptosi+freeze is not a constrained lowering because its intermediate flags/
traps can differ. Fraction and independent semantic bit-format references cover
these distinctions.

LLVM-CC021 floating_value/integer_value constraints admit scalar or matched fixed
vectors for applicable libm helpers, including vector ldexp and scalar-exponent
vector powi. Preserve lane poison and collect actual lane flags before a single
source-operation diagnostic/result commit. Four constrained integer-round forms
and frexp/ilogb fixed-i32 helper results stay scalar at this pin; ordinary vector
forms can expand without guest fenv. Source C c_fenv libm is scalar-only, avoiding
an invented errno aggregation rule. Compiler access to private diagnostic masks
is never a batching mechanism. Schema/shape witnesses are not implemented libm.

ABI027/028 source identity uses exact enum fixedness/scoping/encodings and rooted
nominal quotient with declaration leaves for pointer/prototype record/enum edges,
full by-value layouts. An independent pair-elimination oracle checks actual ABI
canonicalizer projections as well as execution shapes. C provider/C++ externC
consumer fixtures retain a C symbol and distinct ordinary C++ overloads, including
native host link/run; ABI cross-language boundary compatibility must be explicit
and does not follow from layout equality or erasing source-language identities.

LLVM-CC027 makes the target-dependent LLVM environment encoding executable:
i64 fpenv = source-round-code OR six sticky bits, mask0xC3F; i64 fpmode uses
round bits only, mask0xC00. Reserved bits/other widths reject before mutation.
LLVM FLT_ROUNDS0/1/2/3 mean zero/nearest/up/down and explicitly translate to source
FE codes; ambient4 rejects while per-operation nearest-away remains supported.
Source fenv_t32B/femode_t16B packing stays distinct. Exact fenv_set/mode_only helper
updates round while preserving CURRENT flags at one frontier; core/full-default
set restores all snapshot state. No read-old-flags/fullrestore race or private
VM diagnostic bits. Independent tests enumerate all4rounds x64flag patterns,
invalidreservedword/non64/modeflags and actual pinned intrinsic width retention.

LLVM-CC030/031 fixes primitive service/helper transport: exact0/1/N logical
results become LLVM void/T/unpackedstruct{T0..}; final call still has N typed
results and SSA reconstruction preserves component poison/origins. Source C sret/
record ABI is not applied to these compiler-private calls. Full runtime_import
metadata/types/descriptor and unit-scoped actual context disambiguate identical
LLVM ptr or struct spelling. Memory.map now returns typeddata_ptr, not a numeric
address; lookup code_ptr<S> carries the returned function descriptor, data lookup
nominalT; other descriptor fieldsNone. Service ABI is alwaysNone. Guest source
wrappers remain ordinary ABI and handle status/outparams/errno.

Pinned threadlocal.address is memory(none), speculatable. It uses the exact
noninitializing tls_address_raw helper over pre-reserved slots, never a hidden
C++ initializer/throw. Source TLS initialization stays in explicit wrapper
call/invoke; S047 catchable-helper frontier rule applies to those calls. A longjmp
operation is terminal with unreachable following it; no callback normal return
counts as implementation of the separate checkpoint protocol. Completed C++
objects publish process-owned lifetime certificates; fresh destruction claims use
current revision/children/union/counts, not retagged constructor history or a
user-required ownership transfer API.

Symbol boundaries carry explicit source_linkage none/c/cpp. C-data compatibility
uses actual eligible C view and complete provider storage; opaque consumer has
address-only authority. Strict C++ identities stay separate. Normalized comparison
views consume admitted boundary identities, not raw dialect hashes. Current C/
C++ witness covers shared struct/pointer globals and Cint/C++wchar declarations.

Accepted LLVM-CC032 private carrier exception to generic TargetExt rejection:
exact parameterless smir.exception/journal/stack_mark/fenv map corresponding admitted
logical kinds. Only typed calls/returns/phis/selects/copies; no ordinary sizing/
memory/arithmetic/cast/forge. fenv freeze may choose default snapshot; registry
handles freeze only if proved concrete-valid, else E-OPAQUE-FREEZE. Other names/
parameters E-TARGET-TYPE. Actual pinned IR optimization preserves journal carrier.
The prototype creates no runtime handle or native code. Unrestricted raw numeric
bitcast strips provenance WITHOUT exposure per pinned LangRef; independent
ptrtoint exposure is required for later recovery. Inrange taint rules remain.


Actual candidate projection is implemented by `candidate_projection.py`, separate
from the comparison normalizer. It consumes admitted section3/8 records, the actual
SEM Types graph and a named identity resolver over the same immutable module
roots. Exact record shapes follow candidate.json; no producer digest or numeric
ID is a fallback identity. Capture formals use actual admitted recipe parameter
order. Invocation normal results and unwind exception declarations, complete
region/action/handler metadata, source ABI, escape and no-return semantics enter
the comparison. Computed block addresses and indirect branches report the
optional `E-COMPARE-BLOCK-ADDRESS` diagnostic. Public ODR identity excludes module
family; private entities use their source-unit namespace. Deployment family still
controls dependency lookup and artifact pinning.

`projection_witness.py` runs the actual SEM type/SSA/CFG/EH verifier on
conformance/llvm/candidate-comparison.json before projection, then compares LLVM
canonical bytes with the independent runtime function_body implementation. Tests
rename type/function/block/SSA/region IDs non-monotonically, change constants and
escape behavior, and reject invalid SSA/extra fields. This is an actual component
witness. Full ten-root admission and selection-before-SCC publication remain the
integrator/runtime composition responsibility; this witness does not assert them.


Full source call-plan relation (reviewed R034; local resolved reference draft in
LLVM-CC040): lowered execution function type and nominal function TYPE alone do
not encode this-owner, VTT, hidden result/byval/varargs or noundef classification.
The resolved deployment model carries a separately admitted normalized complete
abi_signature identity and rejects presence/content mismatch. The actual runtime
wire uses opt entity_ref and actual ABI cross-module comparator, not these model
strings as evidence. Symbol-to-body and alias/fallback source joins precede
publication. Source metadata missing from the actual body is an error, never
inferred from equal LLVM function types.

EH source closure review: actual exception-allocation.cpp emits payload allocation
BEFORE construction, raw free on construction unwind, then throw/catch. Accepted
R035REV5 provides eh_object_address(E) before construction, selected adjusted
catch-copy getter, dynamic current-catch rethrow and process-owner proxy operations.
The actual catalog publishes those helpers; ABI045 selects source8-B exception_ptr
and the private library port macro. opaque-landingpad.ll proves pinned LLVM24
accepts `{E,i32}` without ordinary E storage. No native header inference or runtime
opaque memory cell is permitted. Combined semantic admission remains a separate
gate; the earlier missing-profile decision is superseded by those named revisions.


Root selected the LLVM-CC039 private E direction, with LLVM-CC041 compiler-only
slots instead of runtime opaque cells. [eh-slot-contract.json](eh-slot-contract.json)
contains exact get/set declarations, revisioned function metadata, logical schema
and pre-expansion resource bounds. eh_slots.py independently converts logical
variables to pruned block-parameter SSA, checks definite assignment and removes
trivial phis. Get/set and all slot metadata must disappear before any optimization,
full/ThinLTO/import optimization or emission; unknown/escaped/residual forms reject.
Opaque E is never alloca/load/store data. The slot model does not parse LLVM or
implement that production first pass. It supplies a reproducible independent
oracle; both original and expected SSA LLVM witnesses pass the actual pinned
parser/verifier, including two nested landingpads restoring the outer exception.
Loops evaluate phis simultaneously, duplicate CFG edge multiplicity is retained,
and unset paths reject instead of creating opaque undef/poison. SEM independently
reviewed the algorithm and focused suite. Bounds slots*blocks<=65536 and
phi count<=65536 are checked before expansion, with a distinct resource error;
these are reference quotas, not source-language/profile limits.

Under reviewed S062, zero and freeze recurse through present by-value components.
No zero-created opaque lease and no generic SEM freeze of a present E/journal/stack/va handle
is allowed, including struct{E,i32}. Copyable fenv snapshot freeze is allowed and
selects the default snapshot for poison/undef (S062). Empty array0 has no present opaque component.
Frontend-proven concrete valid opaque freeze becomes COPY before serialization;
otherwise LLVM reports E-OPAQUE-FREEZE. A copyable fenv's undefined components
select the specified default snapshot. Opaque aggregate SSA insert/extract/phi/
select transport remains valid; no pointer/function-signature edge is traversed.


Reviewed R037 separates source fence order0 (relaxed no-op, no SC event) from
LLVM fence's acquire/release/acq_rel/seq_cst grammar. Source consume maps to acquire;
actual pinned source-fence.c witness verifies order1/2 share the acquire block.
Unused helper options are rejected rather than assigned hidden effects; atomic
comparison matches actual source/LLVM precision contract and allocation-only
bindings cannot authorize typed value accesses. Ordinary generic atomics remain
lock-backed; dedicated atomic_flag retains its separate lock-free guarantee.


[Constant forms](constants.md) enumerate23 Constant ValueIDs and13 retained CE
opcodes, with exact selected static initializer programs, ordered source GEP
promises, authenticated weak absence and source constructor distinctions.
[Coroutines](coroutines.md) specify exact phase-specific passes, typed header,
selected aligned-allocation extension, private E liveness and published partial
Builder protocol. [Retained lifetime notes](lifetime-markers.md) specify the
compiler-private source-fact/actual-LLVMValue channel, phase schemas, capture
stabilization and exact post-Split consumption. Combined qualification is external
accounting; production lowering/runtime implementations remain subsequent work.
