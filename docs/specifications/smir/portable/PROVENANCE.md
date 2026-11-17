# Provenance, assumptions and change surface

Baseline read on 2026-11-05:

| Component | Revision |
|---|---|
| RAX | adda8cfc25047fb2e27455e300d6fea4cb0bfff9 |
| LLVM checkout | 36763294ef639d8a6a4379d81da653dda1c20686 |
| Installed Clang bootstrap | 23.0.0git, b51054818b78dc395cd4d33f17cfb6e98a36a76d |

Product requirements were selected explicitly in the design conversation. New
ABI and encoding values in this package are project design decisions, not claims
that existing Rust structures or ISO standards prescribe those representations.

## Authoritative implementation evidence

- `src/smir/interpret/execution.rs`: constructed functions enter caches directly;
  current Call/Return handling is architectural, not a portable ABI.
- `src/smir/ir/{mod,types,context,ops}.rs`: current module/state/operation shapes.
- `src/user/mm/mod.rs`: immediate frame reuse relies on serialized execution.
- `src/user/{linux,darwin,windows}/`: personality/thread/runtime coupling.
- `.github/workflows/ci.yml`: existing host coverage; not the desired six-host claim.

No external document is needed to establish the envelope's invented byte layout.
When implementing LLVM semantics or foreign ABIs, archive the actual primary
source under this package's `references/` with title, issuer, source URL, source
revision, retrieval date, license and checksum before using it as an oracle.
Do not cite an uncaptured webpage as proof of executable conformance.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Separate portable ABI and lifted-ISA contracts are acceptable | User chose portable ABI | New mode, no source ISA emulation | Existing lifted code | Existing fixtures regress after adding mode | Confirmed requirement; runtime unimplemented |
| A2 | LP64/binary128 defaults are retained | Approved plan | ABI tables | Microsoft LLP64, x86 extended FP | Layout witnesses cannot meet a required descriptor | Retained; comparable native-target layout witnesses only; SMIR frontend absent |
| A3 | Foreign boundaries may require descriptors | User selection | Mixed C++ objects/EH | Incompatible aliases | Required object cannot be represented | Confirmed requirement |
| A4 | Six native qualification hosts can be provisioned | Required endpoint | Release certification | Windows AArch64 JIT | Native lane unavailable | Unknown availability; retained |

## Current change surface

| Plane | Current patch | Planned platform |
|---|---|---|
| Direct decode/execute/CPU state | Unaffected; envelope cannot execute | Guest-ISA adapters participate in mixed domains |
| Memory/MMU | Unaffected | Parallel lifetime/atomicity redesign |
| SMIR lift | Unaffected; compiler bypasses it | Preserve lifted-ISA semantics |
| SMIR IR/interpreter | Isolated framing/static verifier plus independent sequential reference Machine and source-backed registry | Production portable SSA/frame semantics |
| Optimizer/native lowerers/JIT | Unaffected | Explicit portable admission and state maps |
| Backend/machine/devices | Unaffected | User-process platform; no board changes required |
| Oracle/analysis/C ABI | Unaffected | New module inspection/embedding APIs |
| Tests/docs | Independent record/semantic/ABI/runtime witnesses and byte-to-result CLI conformance | Full conformance and host matrix |

## Bounded findings

| Impact | Finding | Blocks |
|---|---|---|
| High | Existing AddressSpace revocation and host fork assume one host thread | Parallel platform, not codec |
| High | Unfrozen executable section and operation grammars | LLVM emitter and executable admission |
| High | Mixed ABI type identity and unwind adapters are absent | Foreign C++ qualification |
| Medium | Current CI does not qualify all six hosts | Release claim |
| Low | Disposable native caches need no external stability promise | None |

## Worktree ownership and current-run evidence

The exclusive role ownership map is in `12-work-packages.md`. The previous
foundation-wide ownership statement does not apply to this shared first wave.
The integrator writes only its assigned files and coordination directory; each
worker owns its stated chapters/schema/tools/fixtures. All other tracked and
untracked content remains preserved. No LLVM write, staging, commit or publication
is authorized for this run.

The integrator observed initial RAX HEAD
`adda8cfc25047fb2e27455e300d6fea4cb0bfff9` and an external advance to
`916968487881520ad71443a224e9012dbd06e405`. Initial owned-file byte snapshots and
diffs remain in the integrator coordination baseline. Receipts must bind content
hashes as well as recorded HEADs; a changed HEAD is not evidence that the current
combined tree was tested. Historical receipts are retained separately in
`validation.json`, with no current validity inferred from their prior success.

## Archived first-wave sources

`references/provenance.json` identifies each source's original path, canonical
URL at the pinned LLVM revision, issuer, retrieval date, license and SHA-256.
Archives were copied from exact `git show REV:path` blobs, without network access
or LLVM checkout mutation. Original LLVM license text is retained. Existing
Instruction.def and LICENSE.TXT keep their archive paths; subsequent source path
`P` maps to `references/llvm-project/P`. Sources requested by the ABI, semantics,
runtime and LLVM roles are deduplicated by source identity and checked against
their requested hashes. These primary source snapshots are design oracles, not
proof of SMIR execution or of the independent witnesses' correctness.

Pinned LLVM source version is 24.0.0git (LLVMVersion.cmake); the separately
installed Clang baseline above is 23.0.0git. Witness receipts distinguish these
toolchains rather than treating an installed compiler as a build of the pin.

## Integrator assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| I-A1 | Claimed roles are independent writers | All five claims and worker outputs observed | Respect file ownership | Concurrent overlapping output | Compare owned snapshots and role handoffs | Confirmed for first wave |
| I-A2 | Local draft reference payloads remain separate from production admission | Existing framing type and role proposals | Codec/reference integration only | Valid envelope with semantically invalid payload | Trace consumers of DecodedEnvelope and production entrypoints | Retained; no portable production engine delivered |
| I-A3 | Archived source bytes represent the exact LLVM pin | git blob retrieval and requested hashes | Primary-source provenance | Worktree differs from committed file | Compare archive SHA-256 to git show at pin | Confirmed for archived bytes; no execution claim |
| I-C1 | Candidate schema snapshots can be tested independently while roles continue contract work | Explicit draft-interface permission and named accepted foundations | Scoped payload-codec results only | Change one shared definition or root field | Reject conflicting definitions; retain exact snapshot hashes and rerun coherent inputs | Retained; no compiler freeze inferred |
| I-C2 | Representation validity and content identity convey no executable authority | Separate unverified types and source consumer trace | Candidate framing and payload wrappers | Correct framing and hash with semantically invalid roots | Whole-module semantic admission must reject before linking or execution | Retained; actual ten-root reference negatives reject; production admission absent |
| I-C3 | Raw scalar type can represent every source allocation | Early source-storage proposal | Global/TLS symbol storage | Source object larger than1MiB | Compare raw width2^23 maximum against allocation extent | Falsified; uniform array<raw8,N> proposal replaces raw scalar |
| I-C4 | Source object extent and bit-offset fields share one representable bound | u64 bit extents and pinned Clang active-size limit61 | Source allocation/layout bindings | 2^61-1B versus2^61B; MMU end2^64 | Independent syntax/layout and arithmetic-bound witnesses | Source bound2^61-1B and distinct MMU bound adopted; exact compiler/reference witnesses delivered, qualification external |
| I-C5 | Physical native CC follows C++ object ABI | Early bridge selection | Native packet entry | MinGW Itanium object ABI on Windows | Independent native_cc and certified bridge_abi facts | Falsified; explicit orthogonal facts required |
| I-C6 | One foreign ISA implies at most one foreign build domain | Earlier domain-count predicate | Native library admission | Two independently built libraries on the same ISA/personality | Compare per-domain compiler/runtime/build/library certificates | Falsified; accepted D034 requires one portable plus multiple independently certified foreign cohorts |
| I-C7 | Handler IDs are entirely alpha-local | Earlier function comparison projection | COMDAT exact comparison | Return the landingpad selector for handlers42 and73 | Compare actual reference outputs with canonical bytes | Falsified; D046 separates semantic selector from local handler identity |
| I-C8 | Object bounds imply an explicit numeric-use restriction | Early TLS/startup pointer models | Raw pointer arithmetic and exposure | Ordinary object pointer versus explicit inrange pointer | Convert/copy both and inspect restriction/exposure separately | Falsified; object extent and explicit inrange remain separate |
| I-C9 | An allocation-only reference loader can ignore segment mutability | Early sequential storage fixture loader | Read-only data/TLS witnesses | Store or failed CAS through a relocated readonly pointer | Require permission rejection before reads, bytes, shadow or result effects | Falsified; S072 adds private initialization then readonly sealing and write guards |
| I-C10 | Four fixed-width relocation kinds cover hosted static initialization | Early candidate linking grammar | C++ constinit vtables and integer address constants | Pinned Clang emits inrange vptr and function ptrtoint globals | Compare actual emitted IR with available record fields and exposure effects | Falsified; R039 revision review adds explicit derivation/range and data/code integer forms before freeze |
| I-C11 | A numeric code-token match is enough to expose registered callable authority | Earlier reference ptrtoint implementation | Integer recovery of code pointers | Guess the bits of an unexposed registered token without its origin/generation | Require no exposure from the guess while a genuinely issued token still roundtrips and calls | Falsified; S076 correction and independent ten-root reference regression preserve the distinction |
| I-C12 | An activation-owned construction journal can persist unchanged across source coroutine suspension | Earlier aggregate lifecycle composition | Partially initialized coroutine frame members | First child completes, await_suspend resumes inline or on another logical thread before returning | Detach before handle publication, adopt authenticated current children, claim a fresh journal and preserve builder-local completion order | Falsified; accepted R042 REV2 requires process partial-object ownership; implementation and coherent witnesses remain open |
| I-C13 | Single-base typed relocations cover all required constant-expression initialization | Earlier static initializer coverage | Multisymbol difference/XOR and wide symbolic GEP | Compare pinned retained ConstantExpr forms against the exact relocation grammar | Execute restricted pure initializer programs against reserved selected facts; reject effects and unverified symbols | Falsified; D051 defines private staging/atomic commit, with actual transaction, quota and alias-selection witnesses delivered |
| I-C14 | A valid source metadata tuple must appear exactly once after linking | Initial coroutine policy marker grammar | Full/ThinLTO policy validation | Link two independently valid translation units carrying identical policy tuples | Validate each source before movement, then canonicalize equal typed values and reject conflicts | Falsified; D056 permits semantic deduplication; pinned24 postlink execution remains unavailable |
| I-C15 | Each LLVM pointer value has one source nominal view | Initial lifetime-fact merge rule | Source lifetime notes across RAUW and cloning | Parent/first base or distinct null pointer signatures share one LLVM Value | Retain independent issued facts by original source identity and note use; reject only conflicting descriptors for the same fact | Falsified; LLVM051 REV5 preserves distinct source views |
| I-C16 | Reusing one undef SSA value stabilizes a saved capture | Initial coroutine capture transport | Builder capture equality at resume | Begin and resume legally refine separate uses differently | Freeze each permitted typed capture once before begin and persist the same defined transport | Falsified; D062 requires one-time refinement, witnessed against actual reference Builder capture equality |
| I-C17 | A derived freeze result can be stored inside the hashed candidate | Initial registry accounting | Publishing final gate results | Flip the result after successful tests | Require unchanged candidate bytes when publishing external status/receipts; reject mutable accounting paths and aliases as artifacts | Falsified; D058 removes the fixed point while retaining computed-status checks |
| I-C18 | Image-size checks alone ensure all preflight precedes cloning | Initial constant staging adapter | Bounded private constant transactions | Small image plus oversized SSA or reserved source-memory facts | Require resource rejection with zero staging/backing clones | Falsified; independent ABI probes confirm both ordering corrections on their recorded source snapshots |
| I-C19 | A source va_list record is the opaque VM va_list value | Broad ordinary-coroutine-frame prohibition | Source variadic cursor storage across suspension | Fixed-parameter coroutine copies a source list into ordinary frame storage | Compare actual32-B source ABI and data_ptr helper signatures with the distinct opaque execution kind | Falsified; D063 preserves actual cookie-owner authentication while permitting synchronized visitors; exact normative paragraph remains unknown |

## Additional observed boundaries

| Impact | Evidence | Consequence |
|---|---|---|
| High | Strict native FP binary32 case 0x007fffff * 0x3f800001 rounds to 0x00800000 with host underflow; selected portable policy detects tininess after rounding | Matching result bits alone cannot qualify constrained fenv; exact flags require a corrected lowering/helper contract |
| High | Pinned LLVM24 raw bN types retain per-bit pointer fragments/poison; raw numeric conversion strips without exposing provenance | Exact shadow/range contracts and independent reference witnesses are required; production shared memory remains a later gate |
| Medium | LLVM build directory contains Clang/TableGen24 but opt/llvm-as23 | Record and verify each binary independently; directory location does not establish compiler revision |
| Medium | Full no-default library validation reports an existing Darwin system-program test failure | A passing reference suite cannot be reported as a passing combined library gate; exact diagnostics belong in current validation receipts |
| High | Pinned LLVM ConstantFolding.cpp narrows wide powi exponents; actual pinned Clang optimized IR witness folds exponent 4294967296 incorrectly | Compiler pipeline must legalize affected calls before optimization and LTO; backend-only legalization is insufficient |
| High | Integration exposed signature/type namespace, source/execution layout, fenv snapshot/handle and cleanup capture distinctions | Exact cross-role schemas and actual-table verifiers must resolve these before compiler freeze |
| High | Actual reference numeric code-token guessing could add registered exposure, and weak absence failed to recheck an unchanged consumer's mutated provider | Issued identity and all proof-input snapshots must be checked at use; corrected focused regressions do not qualify production admission |
| High | Pinned coroutine lowering permits resume before await_suspend returns and partial aggregate construction spans suspension | Source lifecycle metadata must survive optimization/CoroSplit and detach process-owned partial state before publishing the handle; raw frame progress bits do not certify lifetime |

The FP statement is an observed host-witness distinction, not a claim of a
portable production engine or universal hardware behavior. Exact counts and
source hashes are in the semantic reference receipt. The library failure is
outside the first-wave owned implementation paths. A subsequent isolated run
passed (1 test, 10009 filtered); its total reported time was 59.04 s. The test
contains a 30 s deadline per system program. Load sensitivity is an inference,
not a confirmed root cause; retain the failed broad result and isolated pass as
distinct evidence. No Darwin implementation change was made.

## Closure review evidence

The archive now additionally preserves the pinned Clang SemaExpr default-promotion
implementation, LLParser signed inrange checks, Clang SemaType/AST Type source-size
limits and libunwind Unwind-seh implementation. Original paths, checksums and
licenses are in the provenance registry. Clang limits active source-array byte
extent to61 bits so its bit size fits a64-bit integer; this is implementation
baseline evidence, not a claim that ISO C/C++ mandates that bound.

GNU Windows SEH personality accepts four native pointer arguments. The pinned
unwinder explicitly bypasses cleanup for foreign non-GCC exception records; an
admitted cross-domain exception adapter must retain/translate the owner exception
protocol. This source limitation does not establish native Windows exception
execution. A normalized descriptor alone cannot certify loaded code or metadata.


## Record-input audit reopening (INT030)

Actual complete ten-root reference probes accepted three independently rehashed
portable nonunion record mutations: overlapping ordinary members, an unaligned
int member and an unmarked one-bit int member. The unchanged baseline record also
accepted. These are source-descriptor validation false acceptances; no production,
native or guest execution was demonstrated. The production source-record audit
profile remains unavailable. Compiler qualification was reopened; earlier finite
passing receipts remain historical evidence.

I-C20: Output field offsets/widths and physical base adjustments are sufficient
inputs to reconstruct every selected source C/C++ layout. This assumption is
falsified by explicit member alignment, direct source hierarchy/access and pinned
empty-subobject/tail-padding decisions. The accepted INT030 revision 2 interface
adds typed source inputs and checked physical outputs, with ABI payload revision
2 and nominal source hash domain `SMIR-NOMINAL-SHAPE-V2`. Its staged migration is
in progress. Interface acceptance and codec agreement do not qualify the full
record-layout surface or selected C++ dispatch. Independent layout models and
finite compiler witnesses require their own exact-input receipts.
Ordinary source layout restrictions do not apply to packed execution bit layouts.

The archived pinned `clang/include/clang/Basic/TargetCXXABI.h` selects GenericItanium
`UseTailPaddingUnlessPOD03`; `RecordLayoutBuilder.cpp` implements that branch using
`CXXRecordDecl::isPOD()`. Its FIXME explicitly identifies an unimplemented abstract
Itanium POD-for-layout exception for over-wide bit-fields and their arrays.
Witnesses must distinguish this pinned upstream behavior from the abstract ABI
rule and from C++11 POD policies. No additional source trait, native layout
certificate or silent host-target fallback is inferred from this observation.
Source identity, pin, license and checksums are in `references/provenance.json`.

## Additional pinned frontend record limits

I-C21: The pinned frontend supports every record extent allowed by the portable
object-size bound. This is falsified. Archived `RecordLayoutBuilder.cpp` lines
3514 through 3521 reject record size greater than or equal to
`2^min(size_t_width,60)` bytes. Independent syntax-only, header-free C23 probes
with the pinned Clang and existing `x86_64-unknown-linux-gnu` target accept a
single-character-array record of `2^60 - 1` bytes and reject records of `2^60`
and `2^61 - 1` bytes. These compiler diagnostics are distinct from the portable
format's `2^61 - 1` byte object limit and the earlier array-only witnesses. No
allocation or native execution was attempted. The portable limit is unchanged;
the frontend needs an explicit upstream-gap diagnostic until a separately
authorized baseline change addresses this restriction.

The archive also preserves `clang/lib/Sema/SemaLambda.cpp` at the same pin,
SHA256 `43131e28a8fc03b9ad3f2f6810f58e0ddc8a2aca8d9939f64c3b999f0b7a3056`.
`BuildCaptureField` creates implicit ordinary fields without identifiers or
bit-width expressions. A proposed canonical capture-field naming rule separates
the AST producer's origin qualification from the generic ABI validator's
structural checks. The source snapshot proves the AST construction behavior;
it does not by itself prove a complete portable lambda producer or layout model.

I-C22: Separate vcall-offset and virtual-base-offset vectors determine their
negative address-point slots by concatenation. This is falsified by the pinned
Itanium vtable builder's recursive primary-base processing and reverse component
iteration. An actual AST-library witness produces component order
`vbase,vbase,vcall,vbase,vcall` at byte slots -56,-48,-40,-32,-24, before the
retained offset-to-top and RTTI words. INT033 adds explicit ordered component
kinds to the unqualified ABI2 draft; each kind consumes its value vector in
order. For length L and index i, the byte offset is `-8*(2+L-i)` with
`0 <= i < L`. Source virtual-base selection remains separately checked. Neither
this map nor correct object geometry proves final overriders, covariant/deleting
thunks or RTTI authority; those compiler-facing contracts remain required before
freeze. Archived VTableBuilder.cpp and VTableBuilder.h retain exact pin/license
and checksums in the primary-source registry.

I-C23: Every source base offset supported by the selected object-size limit fits
native Itanium RTTI. This is falsified. The pinned RTTI emitter packs a signed
offset into the upper 56 bits of a 64-bit offset/flags word. Its representable
byte range is `[-2^55, 2^55 - 1]`. Independent header-free C++23 IR witnesses use
a one-byte-aligned secondary base: offset `2^55 - 1` round-trips, while offset
`2^55` materializes signed word `-9223372036854775806` and decodes to `-2^55`.
The public-base flag occupies the low byte; the checked equation is
`sign64((offset << 8) | 2) >> 8`. This is compilation and integer decoding only,
with no allocation or source-program execution. Selected native RTTI production
must check representability before packing; object geometry, source format limits
and source vtable-slot range are separate constraints. A normalized portable RTTI
representation would require an explicit contract and library adaptation.

The pinned `clang/lib/Sema/SemaDeclCXX.cpp` source is also archived, SHA256
`c4e51172779c49fcdcf7a84fffa114c9d421ae10c32bbebadbe80ae3419be132`.
Its deleted-override checks reject deleted/nondeleted overrides in both
directions. This is an oracle for selected source-method consistency; the
archive does not establish a portable C++ producer, callable body equivalence,
runtime phase authority or mixed-domain exception execution.

## Additional C++ source and emission boundaries

I-C24: One source function prototype determines one lowered execution signature.
This assumption is falsified by the pinned GenericItanium constructor/destructor
variants. An actual header-free C++23 IR witness for a class with a virtual base
has C1 parameters `this,int32` and C2 parameters `this,VTT,int32`; D1 has `this`
and D2 has `this,VTT`. The source declarations are unchanged. The proposed exact
call-plan execution reference is a compiler-contract repair, not implemented
constructor execution. Source prototypes, issued call plans and actual function
bodies must be checked separately. Archived `CGClass.cpp` and `ItaniumCXXABI.cpp`
retain the pinned implementation and licenses; source witnesses under
`conformance/llvm/record-layout/` reproduce the existing-target compilation.

I-C25: Final source completeness determines the pinned native RTTI bytes. This
assumption is falsified. Separate incomplete/complete `A*` witnesses emit pointer
RTTI flags 8/0 and internal/linkonce-ODR linkage respectively. A single translation
unit that first queries `A*` while `A` is incomplete can retain the cached internal
descriptor after defining `A`, including when `A` acquires a base. Source pointer
identity, available hierarchy and actual RTTI materialization are different
relations. A proposed normalized portable RTTI builder deliberately uses finalized
source declarations; native descriptor issuers must describe actual native bytes.
That normalization is a pending compiler/library port contract and does not
silently certify or rewrite the native cache. Stress probes include same-TU
completion and cross-object incomplete/complete pointer descriptors.

I-C26: Forming or storing a function pointer requires a complete callable ABI.
This assumption is falsified by actual pinned C++23 source/IR probes: with
`struct R; R f(R);`, pointer size, null initialization, copy/load/return and `&f`
are accepted without a complete `R`. The emitted address declaration can be a
placeholder `void()`; it is not evidence that `f` has that source or call ABI.
An unused virtual `R f(R)` is also compatible with complete class geometry while
its by-value call plan remains unavailable. Logical declarations and function
addresses must therefore remain separate from issued callable plans. The exact
address-only execution representation and checked call-plan binding are draft
contracts; no new SMIR type, operation, code token or execution authority is
claimed here. Cross-TU completeness must not silently change the pointer ABI.

These are bounded existing-target compiler/source witnesses. They execute no
source program, allocate no represented huge object and qualify no portable
interpreter, JIT, native C++ bridge or parallel lifetime protocol. The LLVM-owned
witness generator records exact source/compiler/IR identities. HIGH impact:
conflating these relations can reject accepted source forms or accept incorrect
lowered plans. MEDIUM impact: cached native emission differs from final source
metadata. LOW: runtime performance is unmeasured by these compilation probes.


I-C27: Implicit-lifetime eligibility of an aggregate or array proves that every
contained object begins lifetime. This inference is unsupported by the trait.
The pinned `clang/lib/Sema/SemaTypeTraits.cpp` predicate treats arrays as eligible
and independently checks class eligibility. Five actual C++23 static assertions
confirm an eligible aggregate, a noneligible class with a user-provided destructor,
an eligible array of that class, an eligible aggregate containing that class,
and the contained class remaining noneligible. Source-event selection and the
actual implicitly-created subobject set require separate evidence. These are
frontend syntax/trait observations, not object-lifetime or SMIR execution.

The exact Sema source SHA256 is
`c4e6787950457657419ae2bcc030a9b817e000f298cec82dddd216490a7ac452`.
`BuiltinTraits.td`, libc++ `is_implicit_lifetime.h` and its test are also archived
with identity, pin, license and checksums in `references/provenance.json`.
The measured compiler reports Clang 24.0.0git at the pinned revision despite the
executable basename `clang-23`; basename is not version evidence. Its SHA256 is
`192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7`.
The witness selects `-std=c++23 --target=x86_64-unknown-linux-gnu -fsyntax-only`.
This identifies the observed binary and reported revision, without asserting a
reproducible compiler build or normative ISO proof. The exact source and receipt
are retained under `INTEGRATOR/implicit-lifetime-frontend/` in the run directory.

The I-C26 source witnesses above remain historical compilation observations.
The current experimental SMIR contract now implements an unparameterized
`CodeAddress`, explicit `code_bind` and actual source-backed reference calls.
Its active revisions, implementation evidence and remaining admission limits are
recorded separately in `candidate-registry.json` and `status.json`; the original
compiler witnesses do not themselves prove those implementations.

## I-C28: ordinary scalar source calls and conditional lifetime state

The reviewed finite source-call implementation extends the actual public
reference path to ten named C23/C++23 signed/unsigned integer builtin identities
and canonical None-void results. Source nominal identity, signedness, layout,
physical FullFn, call plan and noundef obligations remain genuine owner checks.
Every used plan and body is checked before Machine construction. Default source
function visibility is required; independently reproduced hidden/protected
visibility cases have explicit coverage refusals. Generic source-free behavior
and the encoder/decoder/static-validation prefix remain unchanged.

The SAME retained Long64 before object now completes actual address/binding/
indirect entry and return, preserving eight argument octets in seven guest steps.
Earlier a83 hidden-source acceptance is retained as counterexample evidence; its
expanded qualification was superseded, not reported passing. Corrected source
491d75fe150a069826283f80e29370ffeca2993524394ece2d81c55af81d67ab has
fresh nineteen-method normal/optimized qualification PASS, with 80 consumed
inputs and 55 audited processes per mode, zero drift and correct optimization. The earlier
7+7 byte CLI, 65 format checks and 154 Rust static tests have separate exact
source-cut receipts; their counts do not prove native or production execution.

The independent source-state schema/core has 41 authored cases and 44104 finite
arithmetic oracle comparisons per mode; 89 combined methods pass in each mode
on its captured a83 foundation. Its source labels, history/current ranges and
schedules are conditional hypotheses with unbound/false-authority output. Root
separately checks its seven new methods on the corrected source cut. Actual typed
source membership, C++ alias carriers and live private issuers remain separate
obligations; no source language definedness is inferred from compiler acceptance.

Current provenance refreshes reproduce the original generated SMO bytes before
changing only recorded current codec hashes. Historical cuts and failed or
superseded receipts remain archived under this run. Compiler freeze, production
execution, parallel execution, native JIT, hosted libraries and foreign C++
qualification remain false.


The dependency snapshot callback repair was checked against the actual installed
CPython 3.15.0 `copy.py`: its bound-method deepcopy recursively copies `__self__`.
Exact installed source and bundled license are archived under
`references/local-python/python-3.15.0/`, with local source identity, runtime
version and SHA256 in the provenance registry. This identifies the observed host
implementation; it does not attest an upstream reproducible Python build or
execution on other Python versions. Genuine prepared-owner, mutation-guard and
mutable-data isolation tests provide separate verifier evidence.

Pinned Clang CFG sources are archived at
`references/llvm-project/clang/include/clang/Analysis/CFG.h` and
`references/llvm-project/clang/lib/Analysis/CFG.cpp`, with exact revision, SHA256
and Clang license identity in the provenance registry. At the pinned
revision, `CFGImplicitDtor::isNoReturn` has a declaration but no definition found
across Clang sources. The independently observed failed native link and current
library symbol search have separate worker receipts. Direct destructor declaration
inspection uses a distinct observation field; it is not treated as equivalent to
the missing CFG helper or as proof of C++ lifetime/exception cleanup.

Pinned Clang typed AST observations additionally use exact IntegerLiteral/APInt,
operand-accessor and operation-enumerator declarations. The new unmodified primary
archives are `references/llvm-project/clang/include/clang/AST/Expr.h`,
`references/llvm-project/clang/include/clang/AST/OperationKinds.def` and
`references/llvm-project/llvm/include/llvm/ADT/APInt.h`. Existing ExprCXX, ASTContext,
TypeBase and LLVM/Clang licenses are reused by exact checksum. The registry records
revision, source URLs, licenses and hashes. These sources establish inspection API
behavior; they do not establish source-to-SMIR lowering or runtime semantics.

The typed AST accessor oracle also archives exact `APNumericStorage.h`, `Stmt.h`
and `Basic/Specifiers.h` under the same pinned Clang reference tree. The registry
records the inspected APIntStorage, return operand, expression value category and
calling-convention declarations; stock-target representations remain separate
from the portable ABI. Existing declaration/type headers are reused unchanged.

The finite scalar-alignment compiler/profile oracles add exact pinned
`clang/lib/CodeGen/CGExprScalar.cpp`, `llvm/include/llvm/IR/IRBuilder.h` and
`clang/include/clang/Basic/LangOptions.h` under `references/llvm-project/`.
Existing LangRef, LangOptions definitions, declaration/type headers and licenses
are reused by checksum. They support explicit unsigned integer/cast equations
and observed source conditions; they do not establish complete ISO C++23 source
qualification, source nominal ABI equivalence or an implemented SMIR emitter.

The P1 code-carrier witnesses additionally archive the exact pinned LLVM
IR/Verifier.h, IRReader/IRReader.h and lib/IRReader/IRReader.cpp primary sources.
Existing DataLayout, Type/DerivedTypes, LangRef and LLVM license archives are reused
by checksum. The witness calls the pinned parser and verifier without a native
TargetMachine; this establishes structural IR acceptance/rejection only, not
portable policy enforcement, emission or executable authority.

The source-byte category observation contract additionally archives the exact
pinned libc++ __fwd/byte.h and __cstddef/byte.h with libcxx/LICENSE.TXT.
The existing pinned Clang BuiltinTypes, TypeBase, Decl and Type sources are reused
by checksum. A std namespace/type-name test alone does not prove the actual
pinned library declaration chain; these oracles do not issue source facts.

The source-initialization and union-prestore witnesses additionally retain the
exact pinned Clang `lib/AST/ExprConstant.cpp` and
`test/SemaCXX/constexpr-builtin-bit-cast.cpp` under `references/llvm-project/`.
The existing LangRef, Type.cpp and LLVM license archives are reused by checksum.
These implementation and regression oracles support finite observed lifetime and
bitcast cases; they do not replace the complete language specification or prove
source admission and runtime implementation.

The native byte-category observer additionally retains its exact20-file libc++
header/configuration closure. Nineteen source headers match committed LLVM blobs
at the pin. The generated `__config_site` is archived separately under
`references/native-observations/`, with actual local-build identity, template
identity, checksum and license. It is neither a committed source blob nor the
portable sysroot. This archive supplies reproducible native AST witness inputs;
it grants no portable type/source facts, compiler freeze or runtime authority.

The finite portable TargetInfo prototype additionally uses the archived pinned
`clang/lib/Frontend/InitPreprocessor.cpp`. At that pin, generic initialization
defines `__CHAR8_TYPE__` only for C23; the portable frontend contract requires
its unsigned-char representation macro in both language profiles. Actual C++
char8_t identity remains distinct. The archive identifies the implementation
oracle; executable prototype controls must separately qualify the correction.

The portable type frontend primary request additionally checks eleven exact
pinned Clang implementation/API sources for target factories, CompilerInstance/
FrontendAction invocation, predefines, enum Sema hooks, AST queries and preprocessing
callbacks. Existing matching archives are reused; new copies retain source identity,
license, checksum and primary-source size exemptions. The finite out-of-tree
prototype must separately qualify actual geometry/macros/AST/fragments and all
unsupported source refusals; source archives are not compiler/runtime admission.

R27 archives pinned llvm/lib/Support/JSON.cpp and llvm/include/llvm/Support/JSON.h
from exact LLVM36763294, verified byte-equal to git objects. Native Raw8 parser
controls observe duplicate decoded-key overwrite and integral floating-token
acceptance; these are input-grammar counterexamples, not guest/source authority.
Both source identities/licenses/checksums are recorded; all291 archived objects
verify. LLVM checkout remains read-only.
