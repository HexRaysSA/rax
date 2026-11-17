# Portable compiler-private C++ exception ABI

The root-selected direction uses LLVM `target("smir.exception")` (`E`) as the
exception carrier. This chapter records compiler contracts and witnessed source
integration points. The production frontend/runtime are absent. R035REV5, S070 and ABI045 are published with named LLVM/root/SEM/ABI review;
the actual helper catalog is consumed by generated bindings. Combined verification
still determines adoption. This chapter does not declare the compiler
profile frozen.

Native Itanium `__cxa_*`/Microsoft runtime pointer/header ABIs remain foreign
profiles or explicit extensions. Their Clang IR is an independent source oracle.
Portable compilation cannot infer exception identity from an arbitrary pointer,
name spelling, integer or allocation size. No ordinary memory operation sizes,
loads, stores or bitcasts `E`.

| Source operation | Portable compiler contract |
|---|---|
| throw T allocation | Actual admitted nominal T and source layout; bytes/alignment exact, `eh_allocate` returns E |
| constructor target | `eh_object_address(E)` issues original bounded payload pointer before construction |
| constructor failure | Partial subobject cleanup then release unconstructed allocation; no complete T destructor |
| trivial initialization | Typed initialization-complete publication after stores, even without a user constructor |
| initial throw | Completed typed certificate and owner destructor validated before raising E; no normal result |
| landingpad | Exact result `{E,i32}`; selector follows admitted source EH metadata |
| saved lexical exception | Compiler-only constant-ID get/set, eliminated to SSA before all optimization/LTO/import paths |
| catch-copy source | `eh_catch_object(E)` returns selected adjusted source without catch/count/copy side effects |
| catch-copy destination | Original entry-allocated storage, captured at PRE protected invoke; phase2 sole copy writes it |
| begin/end catch | Exactly one transition for actual selected handler and current exception |
| throw; | Dynamic current ACTIVE CATCH, including calls from functions without a lexical catch; no-catch invokes source terminate |
| resume | Actual saved unwind E, no hidden host TLS substitute or reuse of normal-edge results |
| persistent exception_ptr | Source8-B/align8 shadow-preserving data pointer to registered process-owner proxy, no E bits |
| owner rethrow | Fresh current-thread facade for the same process owner; zero normal results when the helper raises |

The exact allocation metadata at the compiler-private allocate call/invoke is
`!smir.eh.type !N`, with one of these closed tuples:

```llvm
!N = !{i32 1, !"nominal", !"self", i32 typeID}
!N = !{i32 1, !"nominal", !"dependency", i32 consumerSlot, i32 declarationID}
```

Integer operands denote u32 APInt bitpatterns, not private table namespaces inferred
from matching numbers. The resolver obtains actual ABI nominal/layout metadata
from the same admitted roots. Unknown revision/namespace, missing definition,
wrong source domain, size or alignment is an explicit metadata error. The tuple
contains no authority certificate by itself. eh_metadata.py independently checks
the exact MDTuple operand grammar and preserves qualified IDs; maximum-u32 grammar
acceptance is not proof that such an ID exists in the admitted module. Runtime imports after legalization
use actual qualified references in the existing candidate schema.

[eh-slot-contract.json](eh-slot-contract.json) defines the exact private get/set
signatures, function metadata and bounded independent logical schema. The
mandatory first pass constructs SSA and removes all get/set calls and metadata.
Residual/escaped/dynamic/uninitialized forms reject. It runs at O0 too, before
ordinary optimization and before full/ThinLTO/import optimizations. The reference
algorithm uses pruned block parameters, definite-assignment analysis and trivial
phi removal. Values on phi edges are read simultaneously, including loops and
duplicate predecessor edges. No default opaque poison/undef is manufactured.

Reference time is conservatively O(N^6), space O(N^2), with pre-expansion slot/block
and phi quotas. The earlier O(N^4) estimate omitted alias-chain traversal within
repeated phi scans and was corrected. Addressed blocks/indirect branches use the
explicit optional computed-label diagnostic in this profile. Dead unaddressed
blocks can be removed by first CFG normalization; no addressed label is discarded.

The production LLVM integration must replace the following actual pinned paths:

| Pinned integration point | Required portable change |
|---|---|
| CGException.cpp438/450 | Exception slot getter becomes a compiler logical-slot load; no addressable E alloca |
| CGException.cpp868/871 | Landingpad type changes to `{E,i32}` and save uses logical-slot set |
| CGException.cpp1069 | Every other exception-slot write uses the same closed logical-slot operation |
| CGException.cpp1564 | Termination landingpad uses the same E carrier/result type |
| ItaniumCXXABI.cpp1486..1526 | Portable CGCXXABI emits typed allocation/payload/constructor/raise flow, retaining E SSA |
| ItaniumCXXABI.cpp5117..5150 | Selected adjusted source, PRE destination capture and sole phase2 copy before begin-catch |
| CodeGenFunction.h exception-slot state | Distinct IDs for simultaneously live saved lexical contexts, including nested catch |
| libc++ private exception_ptr shim | Ordinary pointerfield current/copy/move/destroy/rethrow operations use registered owner proxy |

These are source integration requirements. The source files remain untouched.
Private allocation/landingpad/begin/end/rethrow interfaces can be emitted directly
by CGCXXABI as LLVM IR; no public C++ opaque-E keyword is required. Source library
builtins expose only ordinary source values such as owner-proxy pointers and
`void` noreturn wrappers. Native cxa_exception.cpp header arithmetic is excluded
from the portable private implementation. A retained cookie's numeric header
never grants authority without actual proxy registry provenance/generation checks.

Catch-copy normalization uses the admitted S026 action exclusively. The compiler
removes the original copy call after capturing the original destination, with
all recipe operands dominating the PRE trigger. It does not capture an invoke
normal result on unwind or invent a destination action result. Pinned source
witness shows entry alloca, protected invoke, `__cxa_get_exception_ptr`, copy-ctor
invoke, then `__cxa_begin_catch`. The adjusted getter supplies the source only.

`make_exception_ptr<T>` can use ordinary throw/catch plus the retained current
owner in the portable library baseline. It does not require native
`__cxa_init_primary_exception` header initialization. Copy/allocation failure is
captured by that source algorithm. Persistent owner operations are process scoped;
active dispatch/catch facades are thread scoped and never retagged across threads.

The controlled [termination-context.cpp](../conformance/llvm/termination-context.cpp)
host witness distinguishes implicit termination catches. Observed on Darwin
arm64 with Apple system libc++abi, using both Apple Clang21 and LLVM24 frontend
with explicitly selected Apple SDK headers:

| Cause | uncaught count in handler | current_exception | Observed owner type |
|---|---:|---:|---|
| unhandled Cause | 0 | present | Cause |
| noexcept escape Cause | 0 | present | Cause |
| catch-copy throws CopyFailure | 1 | present | CopyFailure |
| rethrow without an active catch | 0 | absent | none |
| explicit terminate inside catch after handler swap | 0 | present | Cause, original handler |
| bare rethrow after handler swap, then terminate in catch | 0 | present | Cause, original handler |
| retained-owner rethrow after handler swap, then terminate in catch | 0 | present | Cause, replacement handler |

Original handler exits73; replacement handler exits74. Bare rethrow inherits the
active caught facade handler snapshot, while retained-owner rethrow snapshots
current process handler in a fresh facade. Explicit terminate selects an active
caught snapshot when present, otherwise current global handler. These observations do not qualify the pinned
LLVM libc++abi binary, portable SMIR, native guest or JIT. The runtime's exact
portable contract must specify implicit-catch owner/count updates, termination
handler registration/leases and captured-handler selection, plus abort on handler
return/throw without recursively invoking the handler. Forced unwind/exit remains
a distinct protocol. Header/compiler hashes and native observation limits are
included by termination_witness.py in current focused receipts.


## Function-local semantic selectors

S070 separates private handler.id from observable handler.selector. Typed catches
and catch_all use positive1..INT_MAX, cleanup/no-match0. The same actual ABI-normalized
RTTI type in a function uses one selector; distinct types/null catchall do not
collide. Negative legacy filters are E-EH-FILTER for this private C++23 profile.
Keep llvm.eh.typeid.for symbolic through optimization/inlining/LTO. At FINAL
serialization traverse LLVM Function block-list order, each landingpad clause-list
order, then remaining live typeid calls in block/instruction order; assign each new
actual nominal representative the next positive number. No selector-dependent
canonical-region ordering is used before assignment. Unknown source RTTI metadata
rejects instead of inventing a type from a numeric ID. eh_metadata.TypeSelectors
provides the bounded independent oracle with actual admitted ABI equality.

After serialization these numbers are ordinary observable i32 values. COMDAT body
comparison retains selector values while alpha-normalizing private handler IDs.
Actual Machine witnesses return7 for different IDs42/73 with selector7, and8 after
changing the selector; invalid zero catches reject before comparison. Numeric
constants are never guessed to be references or silently renumbered.
