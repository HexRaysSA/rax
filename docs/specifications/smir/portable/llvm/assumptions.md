# Assumptions, scope and evidence limits

| ID | Assumption | Dependent results | Stress test / falsification probe | Current status |
|---|---|---|---|---|
| L-A1 | Accepted candidate decisions permit isolated reference tools before compiler freeze | CC-L contracts and witnesses | Compare exact INT-D006..011 and named-role acknowledgements; reject a superseded interface | Candidate permission confirmed; joint admission remains a separate gate |
| L-A2 | The specified LLVM pin governs this finite compiler contract | Exhaustive matrices, semantic source rules | Verify HEAD and every manifest source against its Git blob, regenerate expanded TableGen universe | Executably checked; no LLVM edits |
| L-A3 | A build directory can contain mixed executable revisions | Optimizer/layout witnesses | Record realpath, SHA256, --version and Clang Git ID separately | Clang/TableGen24, opt23; no reproducible-build attestation |
| L-A4 | Explicit existing-target Clang supplies a comparable ABI/language subset | Frontend/layout/header witnesses | Static assertions, actual storage geometry/access align; AArch64 BitInt65 alignment16 falsifies direct substitution | Finite subset; no SMIR TargetInfo |
| L-A5 | A concrete zero can refine undef/freeze where selected | Integer/FP/reference power choices | Repeated freeze uses, selected arms, source immediate-UB cases; independent optimizer examples | Finite witnesses; no universal equivalence proof |
| L-A6 | Comparison/deployment views consume independently verified semantic/ABI identities | COMDAT and SCC references | Wrong signature/ABI/hash/ID maps reject; actual candidate verifier must construct the view | Explicit precondition; reference view is never admission |
| L-A7 | Physical source storage bindings preserve alias-visible field positions | Source/LLVM layout separation | Reviewed actual ABI checker requires dst=src-view_start; reject offset mismatch or widened access | Joint S027/S031/ABI019 acknowledged; separate temporaries need explicit conversion |
| L-A8 | The local pair oracle is large enough for the curated identity witnesses | Independent S028 digest comparison | Duplicate-sharing, recursive graphs, noundef and ordered-edge negatives; reject >128 nodes | Bound is reference-only, not a platform limit |
| L-A9 | Shared candidate input bytes remain stable during a focused validation | Current receipt | Hash exact consumed files before/after; any difference invalidates receipt | Observed per receipt, never inferred from historical passes |
| L-A10 | Native host LLVM-only probes identify source/compiler behavior | Power and fesetexceptflag witnesses | Compile actual pin; inspect generated IR; execute finite cases; distinguish mock bitmask primitives from hardware fenv | Host evidence only, no guest/JIT/library qualification |
| L-A18 | INT030 typed inputs retain all source facts needed by the independent layout model | Current ABI3 frontend metadata and nominal hash V3; older ABI2/V2 receipts remain historical | Actual AST traits, numeric align, declaration order, top-CV empty identity, dynamic nonpolymorphic vptr and full six-field metadata witnesses; model-wide comparison remains ABI-owned | Finite isolated AST-tool receipt; not full GenericItanium coverage |
| L-A19 | Source AST fields have an accepted metadata-name representation | Hosted lambda-by-value input production | Pinned BuildCaptureField creates implicit ordinary unnamed captures; actual capture families/order/spelling and reserved-prefix collision tests | LLVM-PROD009REV2 accepted/released; generic shape checks prove no AST origin |
| L-A20 | Pinned source bit-width facts fit the unsigned AST layout API | Frontend layout requests | Full APInt width2^32 rejection before record layout; format retains u64 | Upstream truncation diagnosed; independent model must not emulate it |
| L-A21 | Logical source prototypes do not imply one issued execution signature | Accepted ABI3 source/call-plan split | Actual incomplete by-value pointer size/null/address/copy and C1/C2,D1/D2 hidden-VTT IR witnesses | CodeAddress is unparameterized 8 B/A8; call plans carry explicit execution. Actual portable frontend/runtime implementation remains incomplete |
| L-A22 | Native RTTI emission may retain pre-completion cached information | Draft portable RTTI normalization | Same-TU forward F pointer typeid, then F:B and direct F typeid; actual cached dummy/flags8 persist | Native bytes are not final-source portable RTTI evidence; cohesive normalization contract remains unreleased |
| L-A23 | Native vptr stores and variant names alone do not issue portable lifecycle authority | Draft lifecycle/phase producer mapping | Pinned CGClass early this-initializer vptr stores and D1 function-try-block nondelegating body path | Exact source-point/activation/journal joins remain incomplete; primary source archived by integrator |
| L-A24 | Source ordinary function-pointer values have stable size/parameter/return shape across pointee completion | Stage W source/IR witnesses | Actual incomplete/complete TU assertions and pointer-to-array3 before/after; const/count4 remain distinct | Finite pinned existing-target evidence, not a portable source hash or callable plan |
| L-A25 | Native source char transport is not a portable origin oracle | Stage W char-copy observation | Actual O0 i8 copy loop versus O1 direct pointer forwarding; no b8 emitted | Portable byte transport remains a separate producer contract; ISO legality and runtime provenance are not proved by compilation |

All dependent results above retain these limitations. Unknown ISO C23 clause
attribution for the observed fesetexceptflag difference is explicitly unknown;
INT-010 is the project's exact oracle. No external source retrieval was performed.
Primary source identity/license/checksums reside in sources.json and the
integrator-owned references/provenance.json archive.

## Change surface

| Plane | Effect |
|---|---|
| Existing decode/execute/CPU/MMU/lift/IR/interpreter/optimizer/C ABI | No production changes |
| Parallel memory/runtime, native lowering/JIT/devices | Contracts consumed read-only; no implementation changes |
| LLVM frontend/backend/libraries checkout | Read-only inspection and external tool invocation |
| Compiler docs, reference schemas/tools, conformance fixtures | Only LLVM-owned paths modified |
| Shared registries, module roots and other role outputs | Read-only; changes require owner integration |

## Bounded findings

| Impact | Finding and evidence | Consequence |
|---|---|---|
| High | Pinned ConstantFolding truncates wide powi exponent to int; actual2^4294967296 folds to1 | Mandatory full-width legalization BEFORE optimization/LTO, including hand IR; source integration still later |
| High | Pinned fesetexceptflag clears unselected flags in actual-source controlled witness | Library port correction required to implement selected flag-preservation contract; ISO defect classification unknown |
| High | Source BitInt65 geometry differs from plain LLVM i65, and vector<i1> stride differs from array<i1> | Explicit execution layout plus alias-faithful source binding; no host DataLayout substitution |
| High | Identical numeric IDs in nominal/signature/bridge/journal tables are unrelated | Closed per-helper/contract ABI namespace and actual-record relation validation required before joint admission |
| High | atomic_flag must be lock-free although ordinary atomics may use locks | Dedicated nominal/helper/hot-path progress protocol; all-host implementation not witnessed |
| Medium | LLVM tools in one build tree have mixed versions | opt23 remains an identified independent subset oracle |
| Medium | Pinned Clang/libc++ status tables contain partial/incomplete/unknown entries | Hosted baseline has explicit upstream gaps, independently of missing SMIR ports |
| Medium | LLVM-libc macOS/Windows support is partial in the pinned documentation | Six-host library qualification remains unrun |
| Medium | Callback EH cleanup can suspend after native return | Typed captures, action frontier/journal/leases; no duplicate cleanup or target re-entry |
| Low | Independent pair-elimination agrees with actual partition-refinement type hash on curated graphs | Useful cross-implementation drift detector; finite evidence only |
| Low | Protocol catalog identity differs from file SHA256 | Both are recorded separately; whitespace never changes protocol identity |

Combined qualification belongs to the integrator and its current external receipts.
The published namespace/typed interfaces have independent reference witnesses;
absent frontend/emitter, runtime/JIT/sysroot/foreign-domain implementations remain
later implementation gates.
Failed initial test logs remain in coordination storage rather than being hidden.

CC-L audit addendum: the first constrained-power mitigation draft assumed a
wide constrained overload. Actual TableGen falsified that: constrained powi is
i32-only, ordinary powi arbitrary scalar width. The unnecessary private-call ABI
was withdrawn before dependent implementation (LLVM-CC019 revision2); source
metadata preservation and actual pinned witness replace the assumption. Constrained
integer rounding and fixed-vector libm require a single source-operation flag
frontier; ordinary scalar expansion is not evidence for that behavior. The current
catalog/type binder and named role ACKs are prerequisites for claiming bindings.
C/C++ function linkage-TYPE equality is separately observed in the pinned frontend;
it cannot stand in for ABI030 source boundary compatibility or complete C++23
conformance. Exact primary ISO clause attribution is unknown without an archive.

CC-L storage count correction: a proposed nested-byte-array workaround assumed
array.countu32. Current schema inspection falsified it: count is u64 (vec:T list
framing countu32 is separate). The proposal was withdrawn before adoption.
Canonical source storage is array<raw8,N>, including0, metadataO(1). Source byte
extent <=floor((2^64-1)/8)=2^61-1 keeps bit extents in u64; actual pinned
ConstantArrayType::getMaxSizeBits caps size_t64 addressingbits at61. Positive/
negative x86-64/AArch64 Clang syntax-only witnesses check the exact threshold
without allocating storage. This is a source/format bound; physical runtime
allocation availability and reference materialization quotas remain separate.


Actual projection assumption register (LLVM-CC037):

| Assumption | Dependent result | Falsification probe / status |
|---|---|---|
| All execution records and cross-root identities belong to one completed immutable admission transaction | COMDAT body comparisons have semantic meaning | Actual SEM verify rejects invalid SSA/fields in component fixture; full-root transaction remains integrator gate |
| Identity resolver recomputes admitted source/type/layout/import/program/recipe identity and never returns file-declared hash authority | Public ODR and relocation identity | Missing namespace/recipe rejects; full-root callback composition belongs to runtime/integrator |
| Local source identity is carried in smir.unit.UID namespace, not deployment family | Internal linkage separation and public cross-TU coalescing | Public two-family positive/private two-UID negative reference tests pass |
| Current actual SEM rejects unreachable blocks and admits only ancestor-chain region overlap | Projection order and complete EH coverage | Projector rejects unreachable blocks, retains all region/action metadata; optional computed block addresses explicitly reject |

High-impact correction: public ODR comparison identity formerly included the
resolved deployment-family key. That prevented shared header inline/RTTI entities
from coalescing across independently deployed translation units. LLVM-CC037 and
named root/SEM ACKs remove the family from comparison identity while retaining it
for dependency lookup and runtime artifact/generation ownership. Any/largest/
samesize group members may differ after optimization; common-member ABI checks
and whole-group selection remain mandatory. The earlier assumption is falsified.


| Assumption | Dependent result | Falsification probe / status |
|---|---|---|
| Compiler-private E slots never escape, and first legalization runs before all optimizer/LTO/import paths | E remains opaque SSA without memory | Exact get/set grammar, residual/escape diagnostic, native LLVM parser before/after, nested landingpad expected SSA; production pass not implemented |
| Reaching a get requires assignment on every incoming CFG path | No opaque default is fabricated | Branch with unset incoming edge rejects; loop swap and nested outer restoration agree with independent logical-slot interpreter |
| Fixed-point state expansion is bounded before allocation | Resource failure is explicit and reproducible | 32768 slots*2 blocks accepted,32769*2 rejected;65536*512 encoded declaration rejected before matrices |
| Private E ABI uses independent process-owner proxy protocol for persistent exception_ptr | Ordinary8B pointer source field does not become raw E bits | Published R035REV5/ABI045 exact proxy/current/copy/move/rethrow lifecycle consumed; combined gate separate |

Readonly combined-admission review reproduced symbol/body source-boundary and TLS
signature contradictions. R-owned fixes now reject original freshly hashed inputs
with RT_FUNCTION_SOURCE_TYPE and RT_TLS_HOOK_SIGNATURE, respectively. A separate
actual import-symbol mismatch (execution12 vs imported signature201) was sent to
owner; fresh rehashed input now rejects RT_IMPORT_SIGNATURE. Source call_signature (this/VTT/
sret/byval/varargs/noundef) relation is distinct from function TYPE; R034 adds exact
actual metadata and comparator, while local deployment model consumes only
pre-admitted normalized full-plan identities. No model hash is proof of source ABI.


| ID / assumption | Dependent result | Stress test / falsification / status |
|---|---|---|
| L-A11: LLVM24 retained CE grammar differs from historical LLVM | Finite constant matrix and static/dynamic source classification | Parse actual Constants.cpp supported switches plus Value.def, reject drift;160 actual source compilations and retained IR parsing. Reachability from all optimizers is not proven |
| L-A12: Portable target explicitly selects P2014 aligned coroutine allocation | Coro frame source allocation policy | Default versus flagged actual IR, custom aligned/fallback and matching delete/null paths. Default size128 does not certify align64; actual preaccess checks mandatory |
| L-A13: No present private E value survives source suspension | Ordinary coroutine frame is serializable guest state | Typed recursive pre-Split liveness, phi-edge/cycle negatives, actual catch-suspend rejection; VM sealed safepoints are a separate protocol |
| L-A14: Coroutine current-child lifetimes can cross logical threads without old activation journals | Partial aggregate source support | Actual first Guard constructor before second suspend; published R042 Builder/fresh journal protocol, actual typed capture/resumer witnesses; production guest parallelism unobserved |
| L-A15: Static address-dependent CE evaluation precedes visibility | constinit/read-only/SCC semantics | Multi-symbol Add/Sub/Xor and address-only PtrToAddr actual IR; published R041/S074 programs,27 independent arithmetic/authority/range cases and2 weak-provider snapshot cases |

High-impact findings L-A14/L-A15 have explicit coordinated contracts and reference
witnesses, distinct from later implementation absence. Medium-impact aligned allocation is an explicit
selected source extension with witnessed upstream-default difference. Low-impact
named coroutine policy merge needs semantic typed-value deduplication and source/
destination validation before each import; executable reference tests cover this,
while LLVM24 postlink execution remains unobserved.


| ID / assumption | Dependent result | Stress test / falsification / status |
|---|---|---|
| L-A16: Private retained notes bind actual AST-derived typed facts to exact LLVMValues | Source lifetime/JSSA reconstruction after optimization and CoroSplit | Canonical anchors, real operand bundles, per-view facts, actual typed capture program, duplicate/tampered/unknown provenance and live-deletion rejection; O0/O2/full/Thin prelink actual pin. General AST producer/tracker remains unimplemented |
| L-A17: Capture values are stabilized once before construction and reused at every fresh claim | Cross-resumer Builder environment identity | Actual SEM freeze and runtime Builder use undef/poison source cases; separately freezing each resume or reusing unstable values rejects. Copyable fenv typed freeze precedes32-B packing; branded execution handles never captured |

LLVM051 reference algorithms are bounded by declared note/program/fact resources.
Live compilation exposes initial IR with -O2 -disable-llvm-passes (no optnone),
then actual optimization/prelink runs. Declaration ABI/effects stay exact; only
verified optimizer-added callsite value promises may normalize before consumption.
A generic bitcode file without validated source facts rejects; matching opaque
pointer shape, metadata names or numeric IDs never supplies source authority.

ABI062REV2 source-list scope clarification: source32-B memory record is portable
ordinary storage. The process cookie authenticates original variadic OWNER lifetime,
not executing-visitor affinity. Reference owner-scope API parameters retain their
meaning/behavior. Synchronized borrowed visits and copied cursors do not extend
owner/arena/table lifetime; all copies reject after owner revocation. VM opaque
execution handle transport remains excluded. Exact primary ISO clause unknown;
source/reference witnesses establish only their explicitly recorded finite scope.
