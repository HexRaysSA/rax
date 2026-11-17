# Ordinary C++ coroutine compiler contract

LLVM-CC048/050/051 coordinated compiler contract. Named-role acknowledgements
cover allocation, opaque-value, capture typing and partial-construction rules.
This contract implements no compiler pass or guest coroutine runtime.

## Pinned pass order and boundary

All rows use LLVM36763294ef639d8a6a4379d81da653dda1c20686. Install the portable
TargetInfo/DataLayout/source ABI BEFORE frontend frame-related IR or any coroutine
pass. FIRST LLVM041 removes private E slots to SSA; other mandatory preoptimization
refinements run at all frontend, external-IR, O0, full/ThinLTO and import entries.
Before every CoroSplit invocation check transitive present-value E liveness across
suspension, including aggregates/arrays/vectors with present E, excluding pointed-to
objects and code-signature edges. A compiler may prove a zero-element aggregate
contains no present E. No pointer traversal invents a value edge.

The table is the relevant ordered subsequence of the pinned default pipeline;
ordinary optimization passes can occur between entries. CGSCC/function passes can
repeat. CoroElide is an optional semantics-preserving optimization, not a required
runtime operation. Run its actual pinned pipeline placements when optimizing.

| Phase | O0 | O1/O2/O3 coroutine subsequence |
|---|---|---|
| ordinary compilation | Early -> Split -> Cleanup -> GlobalDCE wrapper | Early -> function CoroElide -> CGSCC Split -> AnnotationElide -> Cleanup |
| full-LTO prelink | same O0 wrapper (pinned wrapper ignores phase) | same relevant subsequence as ordinary compilation |
| ThinLTO prelink | same O0 wrapper | Early -> function CoroElide; Split/Cleanup deliberately deferred |
| full-LTO postlink O0/O1 | Early -> Split -> Cleanup -> GlobalDCE wrapper | O1 also uses wrapper; O2/O3 Early -> CGSCC Split -> AnnotationElide -> Cleanup |
| ThinLTO postlink | Early -> Split -> Cleanup -> GlobalDCE wrapper | prelink Early already ran; CGSCC Split -> AnnotationElide -> Cleanup |

Source: PassBuilderPipelines.cpp buildCoroWrapper, buildModuleSimplificationPipeline,
buildThinLTODefaultPipeline, buildLTODefaultPipeline, buildO0DefaultPipeline;
CoroConditionalWrapper.cpp tests actual intrinsic declarations. Full/Thin prelink
outputs are intermediate bitcode; they are never admitted as executable SMIR.
The final portable serializer runs only after Split/Cleanup and rejects residual
coro intrinsics/presplitcoroutine with E-CORO-RESIDUAL. This is an internal compiler
failure for required C++ source. Optional retcon/async/custom ABI intrinsics retain
E-EXT-COROUTINE-ABI. No LLVM23 opt execution certifies these LLVM24 pipelines.

## Exact header and geometry

| Component | Exact portable value |
|---|---|
| frame pointer | ordinary data_ptr in address space0, issued allocation origin/generation |
| resume token at byte0 | code_ptr to the signature below, zero at final suspension |
| destroy token at byte8 | code_ptr to the SAME signature, never a native PC |
| promise byte offset | alignUp(16,A), A the actual source promise alignment in bytes |
| allocation alignment/size | final CoroSplit FrameAlign/FrameSize with portable DL, including explicit alloca alignment and source storage padding |
| cleanup subfunction | compiler index2; internal allocation-elision variant, no third header slot |

Both entries have exact execution signature
`{kind:function,cc:portable,variadic:false,params:[data_ptr(AS0)],results:[],param_noundef:[true],result_noundef:[]}`.
The code_ptr refers to that admitted function entity. No hidden this/return/VTT,
varargs or native CC. FrameAlign/nonnull/dereferenceable(FrameSize) are additional
validated pointer promises, not new signature parameters. CoroShape.h
getResumeFunctionCC returns LLVM CC::C for Switch; CoroSplit.cpp
addFramePointerAttrs adds noundef/nonnull/align/dereferenceable. Normalize C to
portable logical CC consistently at entry, frame token type, load and call.

CoroEarly.cpp lowerCoroPromise computes alignUp(two pointer slots,A), including
reverse conversion; CoroFrame.cpp reserves both header fields before the promise.
Preserve the allocation origin/generation and access range through these GEPs.
CoroCleanup.cpp lowerSubFn loads index0/1 after Split has resolved compiler index2.
CoroEarly lowers done to a null test of the first token. Geometry obtained by
native-target compilation is only an independent comparable witness, never the
portable source layout oracle.

## Allocation, failure and source overloads

The selected portable target explicitly defaults `-fcoro-aligned-allocation=true`
(P2014 Option2 behavior in pinned LangOptions.def/SemaCoroutine.cpp). This is a
recorded source-policy extension: upstream strict C++23 defaults it false. The
frontend contract records the choice independently of the library representation
site hash. Generic IR needs exact policy metadata or independently verified
equivalent allocation behavior; otherwise E-CORO-ALLOCATION-POLICY.

Named compiler metadata grammar: `!smir.coro.policy = !{!N}` with
`!N = !{i32 1, !"switch", i1 true}`. Each canonical producer emits exactly one tuple, no extra operands, APInt
constant operands; this declares selected policy, never certifies allocation
origin/capacity/alignment. The compiler still validates the actual lowering.

Before full-LTO link or EACH ThinLTO import, validate source and destination policy
independently; missing/unknown/conflicting policy is E-CORO-ALLOCATION-POLICY,
not inheritance from a valid destination. Each source module either carries the
selected marker or has separately verified equivalent allocation metadata before
movement. After link, accept repeated semantically identical tuples and canonicalize
to one; equality is typed operand value, not MDNode pointer identity. Conflicting
values reject before optimization/serialization. Import explicitly propagates the
validated canonical policy to its destination, even if a future importer omits
arbitrary named metadata. No pair of valid identical TUs fails due to concatenation.
Pinned IRMover.cpp linkNamedMDNodes inserts mapped named operands with pointer-set
deduplication; FunctionImport.cpp materializes metadata before IRMover.move with
IsPerformingImport=true. These source paths do not replace the portable policy
validation hook. Current llvm-link is23, so no pinned24 postlink execution claimed.

Preserve pinned lookup order and selected promise/global allocation overload,
placement arguments, nothrow policy, get_return_object_on_allocation_failure and
matching selected delete (including size/alignment). A promise size-only custom
allocator can take precedence under the flag and emits the pinned warning; do not
replace it silently with global aligned new. The actual nonnull returned region
must hold FrameSize bytes at FrameAlign before ANY header/promise access. A
violated allocator promise is source UB, diagnosed by an explicit preaccess check;
no invented recovery, extra allocation or alternate delete. Null on a permitted
nothrow route FIRST branches to the allocation-failure return object, without frame
checks/accesses, construction, publication or delete. The ordinary throwing route
propagates its source exception. Proven allocation elision preserves alignment,
capacity, storage lifetime and source cleanup obligations.

The source witness observes alignas64 promise, FrameSize128 and promise+64.
Upstream default emits new(size128)/delete(ptr,size128); selected flag emits
new(size128,align64)/delete(ptr,size128,align64). Custom aligned and size-only
fallback cases retain their respective promise operators and null-first branch.
These are IR observations, not native allocation/unwind execution evidence.

## Suspension, lifetimes and logical threads

A source handle is nonowning. Allocation/lifecycle lowering registers an inactive
frame owner lease for its module and all resume/destroy code generations; absence
of an active VM call frame never permits their unload. A live suspended source
frame retains ordinary storage, current child lifetime certificates and code
leases until its actual destruction. Runtime access/code-token checks retain their
own bounds/generation authority; copied header bytes alone grant none.

The source suspension index and initialized flags are ordinary guest frame data.
Commit continuation state and detach any partial construction journal BEFORE
entering await_suspend or otherwise publishing the handle, not merely at the
later llvm.coro.suspend instruction. Another logical thread may resume while
await_suspend has not returned. A boolfalse await_suspend continuation reacquires
a fresh journal on the same activation; a throwing await_suspend follows original
source EH and actual current-E partial cleanup, without resurrecting old journals. Resume/destroy
use checked code-token calls; symmetric transfer uses the admitted musttail recipe.
Final suspension nulls the resume token; done observes that value. Resume after
final suspension/destroy, double destroy and unsynchronized concurrent resume/
destroy are source UB; no implicit serialization is promised. Destroy follows the
selected active suspension cleanup exactly once, then matched deallocation revokes
storage and releases inactive-frame leases. Failure/termination preserves exact
cleanup frontier and does not replay a constructor/destructor.

A different logical guest thread can resume/destroy a suspended frame. Its dynamic
TLS/fenv/errno/current-catch/uncaught state applies; no creator ambient state is
captured. Host-worker migration of the SAME logical thread preserves that logical
state. Private E and present E aggregates cannot be spilled: E-CORO-OPAQUE-SPILL
for extension hand IR, internal compiler failure for required source. Source
co_await/co_yield inside a handler is rejected by SemaCoroutine.cpp
checkSuspensionContext; a nested coroutine called from a handler is a new function
using the resumer's dynamic state. An exception_ptr ordinary8-B owner-proxy pointer
can persist with its source retain/release lifecycle after the catch finishes.
Sealed VM safepoint state may contain E and activation-owned journals under its
own continuation protocol; it is distinct from ordinary guest coroutine storage.

## Partial source construction across suspension

Run CoroSplit before logical construction-journal instrumentation. Native Clang
source cleanup/progress metadata must survive optimizations and cloning until
consumed; ordinary raw flags are not lifetime authority. No thread/activation-owned
journal, stack mark, VM opaque va_list execution handle or E-containing state is serialized as an
ordinary coroutine field or retagged to another thread.

Actual header-free `Pair{Guard(co_await a),Guard(co_await b)}` IR proves the first
Guard constructor returns before the second suspend. Therefore banning suspension
in catch handlers alone cannot close journal migration. Completed child objects
use R042REV2 process-owned authenticated current-lifetime certificates. Its exact
candidate factory/helper interface is:

| Helper | Fixed instantiated execution signature |
|---|---|
| journal_begin | (data_ptr, ordered actual cleanup_program.params execution values)->journal |
| journal_detach | (journal)->void |
| journal_adopt_child | (journal,u32 slot,u64 element,data_ptr child)->void |
| journal_claim_partial | (data_ptr)->journal |
| journal_fail_partial | (data_ptr,E actual current unwind)->journal |

All use portable CC, all param/result noundef false, ABI namespacejournal with an
actual SELF cleanup_program, no target and no source/runtime varargs. Catalog
journal_captures is a metadata expansion into actual source nominal.execution
formals in declared order. None is missing metadata, [] is a verified zero-formal
environment. bind_context/actualRootContext resolves this graph; no name, private
ID or equal pointer shape supplies source identity. LLVM050's exact reference
reader/instantiator checks that typing and grants no runtime journal authority.

Begin issues a fresh activation/thread journal. Fully completed children publish
process certificates; adopting checks source type/program/slot/element/object/
generation/address/extent/current lifetime under one owner, including parent/first
child sharing an address. It atomically invalidates the prior independent child
claim without ending/restarting that source lifetime. Detach consumes J and stores
a process partial Builder with actual typed capture values, counts, historical
initial completion order and CURRENT child lifetime graph. No real constructing
child, native/foreign in-flight effect or pending ticket may be detached. Begin
on a suspended Builder claims a fresh current-thread/activation instance and
checks that saved environment; no old event owner is rewritten.

Builder completion ordinals advance monotonically across resumer threads from
max retained order+1, independently of per-thread event clocks. Full parent
publication occurs only after source initialization completes; it transfers current
child ownership once into the completed parent certificate, with no synthetic
constructor event or unconstructed-parent destructor. Claim/fail_partial destroys
ONLY current completed children in reverse historical completion order (even for
ordinary coroutine destroy), then retires Builder. Replacement/end changes current
lifetimes without reviving historical completion; stale/cyclic/duplicate adoption
fails. Captured pointer leases preserve identity/storage metadata and code lifetime,
never extend source pointee lifetime or manufacture ownership by copying bytes.
Actual exception_ptr captures retain/release through their source library lifecycle.

The published runtime schema/catalog/factory/registry and their ownership witnesses
are RUNTIME-owned. The LLVM reference also exercises actual admitted capture
typing and fresh Builder claims across logical resumers. Whole-module composition
and qualification remain external integrator checks. Production parallel guest
execution is not established. Existing sealed VM safepoint state is distinct.

## Executable witnesses and bounds

`test_coroutines.py` runs actual pinned O0/O2/full/Thin prelink pass traces, exact
header/promise/proxy geometry, custom allocation/fallback/delete/null ordering,
source partial aggregate and catch-suspension rejection. The independent
`opaque_suspend_check` computes SSA block/phi-edge liveness before Split;
B<=512/V<=65536 are reference resource bounds, not source ABI limits. Its caller
supplies recursively present E types from admitted types, not code signatures.
Worst-case time O(B*(B+E)*max(1,V)), space O(B*V+E), excluding type classification.
Postlink pipeline order is verified from pinned primary source; no LLVM24 postlink
optimizer binary is available. No portable guest execution is observed here.

The early-publication ordering has a direct pinned primary witness:
CGCoroutine.cpp emitSuspendExpr emits coro.save BEFORE await-suspend wrapper call;
CoroSplit.cpp1586..1592 replaces that save with the resume-index store. Its
1262 comment explicitly treats intervening calls as potentially resuming the
coroutine. Journal detach/lifetime metadata must remain bound to that save/state
commit through cloning/optimization, not relocated after the callback. The actual
partial-Pair source test checks first child constructor < save < second await
wrapper < second suspend < second child constructor.

`coroutine-immediate.cpp` additionally executes a controlled native-host source
oracle with pinned Clang at O0/O2 and explicit Apple SDK/P2014 mode. await_suspend
records1, directly resumes its own suspended coroutine (body records2 and destroys
its guard once), records3 after that resume returns, then caller records4. Both
executables require order1234, one guard destruction, done=true and explicit frame
destruction before exit0. coroutine_host.py records source/compiler/binary hashes
and linked images. This is same-host-thread inline reentry, not actual parallel
guest execution or a peer-thread result. System runtime binary identity is unknown;
there is no pinned libc++/SMIR/JIT qualification. The initial missing-SDK link
attempt failed to locate libc++; the recorded successful command supplies SDK.


Source va_list is DISTINCT from the excluded VM opaque execution kind. The portable
source ABI uses an ordinary32-B array-of-one record (arena,cursor,limit,cookie),
operated on by data_ptr va_start/va_copy/va_arg/va_end helpers. That source storage
may live in a coroutine frame; copying existing bytes is not an implicit va_copy.
Every use resolves the original cookie in the process owner registry and checks
that ORIGINAL variadic-owner activation/generation, arena/backing and nominal table
remain live. The actual registered visitor may be a different thread or fixed-
parameter callee, with ordinary source synchronization for shared cursor mutation.
ABI062REV2 preserves reference Cursor.arg thread/activation/generation keywords as
explicit COOKIE OWNER identity; they are not executing-visitor affinity checks.
The runtime source helper resolves that owner independently of its actual visitor.
No retagging or lifetime extension: owner return/unwind/nonlocal exit globally
revokes all copied cursors. va_copy has an independent cursor and the same owner.
A fixed-parameter coroutine may va_copy a source list and suspend while that owner
stays live. The pinned existing x86 witness compiles this and spills its native
24-B va_list_tag; it proves frontend acceptance, not portable32-B layout or guest
execution. Exact ISO paragraph attribution is unknown; the clarification follows
actual source/reference behavior without inventing a standard citation.

The exact retained source lifetime interface is [lifetime-markers.md](lifetime-markers.md)
and its executable [contract](lifetime-marker-contract.json). LLVM051's named
reviews require all process-safe captures frozen once before begin, typed recursive
snapshot transport and source facts, not a raw counter or debug annotation.
