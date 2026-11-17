# LLVM refinement boundary

Authority: pinned `llvm/docs/LangRef.md`, sections Poison Values, Byte Type,
integer instruction semantics, select, freeze; `UndefinedBehavior.rst`. Sources
and checksums are in sources.json. This document preserves the original integer-reference evidence; CC-L required full typed contracts and precise pointer/FP/helper bindings are now in closure.md and lowering-contracts.json. No universal semantic proof or production admission is inferred.

## Scalar bitvectors

For width w in1..65535, concrete unsigned bits u satisfy0 <= u < 2^w.
Signed value is u if u < 2^(w-1), otherwise u-2^w. Arithmetic without promises
wraps modulo2^w. This has no byte/host-width truncation ambiguity.

`reference.py` evaluates concrete/poison/undef integer values. Undef is refined
to zero per use; this chooses one legal refinement and is not an enumeration of
all nondeterministic behaviors. Freeze refines poison/undef to zero once per
dynamic evaluation and preserves a concrete input. Distinct freezes may choose
the same value; all uses of one dynamic freeze observe the same chosen bits.
The evaluator has no host architectural register or floating-point dependency.

| Operation or event | Required effect |
|---|---|
| nsw/nuw arithmetic overflow | Deferred poison; discarded result does not trap |
| shl/lshr/ashr count >= w | Deferred poison; no host count masking |
| exact division with remainder / exact right shift dropping a1 bit | Deferred poison |
| or disjoint with overlapping1 bits | Deferred poison |
| trunc nuw/nsw, zext/uitofp nneg, icmp samesign | Exact CC-L poison transfer rules; the original scalar witness covers only its declared subset |
| executed div/rem divisor0 or poison | Immediate UB trap before ordinary poison transfer |
| executed sdiv/srem MIN,-1 | Immediate UB trap, including mathematically zero remainder |
| executed sdiv/srem poison,-1 | Immediate UB: poison can be MIN under pinned poisonvalues rule |
| ordinary poison dividend / nonexceptional divisor | Poison result |
| select with poison condition | Poison result; no immediate branch UB until a sink |
| select with concrete condition | Propagate only selected operand |
| phi | Propagate only predecessor-selected input; simultaneous snapshot |
| executed poison/undef branch condition | Immediate UB trap at that operation |
| poison callee/address/noundef argument or result | Immediate UB at executed sink, once those operations exist |

Division/remainder trap rules apply when the instruction executes, even if its
result is unused. A compiler cannot eagerly evaluate an unreachable division
and cause an earlier runtime trap. Signed division truncates toward zero:
`q = sign(a)*sign(b)*floor(abs(a)/abs(b)); r=a-q*b`. Example a=-7, b=3 gives
q=-2 and r=-1. Python's `%` uses a different sign convention, so witnesses test
the mathematical identity and remainder sign rather than copying Python `%`.

Immediate UB has no source-defined observable result. The draft chooses a
precise explicit diagnostic trap at the current logical operation; preserving
prior side effects is a project behavior, not a guarantee LLVM grants after UB.
The compiler policy does not claim reverse equivalence for source UB programs.

## Aggregates, bytes, memory and floating point

Vector/aggregate poison is per lane/field. Scalarizing a select must not evaluate
an unselected poison arm as a branch condition. Freeze preserves concrete
components and freezes each poison/undef component. Frozen poison/undef pointers
remain non-dereferenceable; concrete zero bits do not create provenance.

LLVM24 raw `bN` values track integer bits, pointer provenance and poison per bit.
The pinned LangRef documents ordinary LLVM IR-to-MIR conversion to same-width
integer scalars, but that backend convention does not define portable SMIR
memory/shadow semantics. The original draft diagnosed ByteTyID; CC-L now maps it to candidate raw values up to2^23 bits with sparse per-bit origin/poison state. A direct
IR emitter must either implement this exact representation/refinement, use a
proven legalizer preserving all required observable behaviors; the candidate chooses per-bit raw semantics, without a missing-type diagnostic.
Treating bN as an ordinary iN without analysis is not a source-backed contract.

The original scalar reference evaluator has no memory. Coherent candidate raw/memory/pointer records and CC-L pointer_contract.py now specify these surfaces; bindings reference exact profile operations. A stored poison value
cannot silently become an all-zero valid value and later authorize a pointer
dereference. Byte copies, padding, unions and mixed-width loads make a whole-SSA
poison bit insufficient. Whole-module admission must verify those exact shadow/layout bindings before compiler freeze.

Ordinary LLVM FP assumes its default environment; constrained FP carries distinct
rounding/exception metadata. Scalar IEEE types, binary128, signaling NaNs,
exceptions, subnormals, fast-math refinements, conversions and guest fenv need
exact accepted helpers. Required FP instruction/intrinsic rows now map to exact typed FP recipes and explicit helper/import contracts. There is no host-FP fallback claiming equivalent semantics.

## Independent evidence and complexity

Fixtures include known boundary/rejection cases,10 LLVM folding functions,
18 independent DataLayout geometries and exhaustive8-bit signed division
identities (65279 legal operand pairs). Pinned Clang24 and independent opt23
both fold the10 functions; only opt23 supplies the generic DataLayout oracle,
with its input layout preserved explicitly. Those original folding/layout
witnesses execute no native output. CC-L separately executes generated LLVM-only
power functions and an actual-source fenv bitmask probe on the current host;
neither executes SMIR or qualifies a portable guest/JIT. No RAX evaluator is
used as its own oracle.

For scalar width w, value storage is O(w) bits. Add/shift/bitwise operations are
O(w); the conservative bit-complexity upper bound for multiplication/division
is O(w^2). These are algorithmic bounds, not measured performance claims about
Python's big-integer implementation. For a type tree of n nodes and nesting d,
layout is O(n) node visits, O(d) recursion plus output field offsets; count/size
arithmetic uses arbitrary precision. Generated LLVM fixtures contain O(n) fields.

For the independent S028 oracle with V reachable nodes, E ordered edges and
serialized label length L, pair elimination stores at most V^2 pairs. A sweep
visits at most O(V*E+V^2) work; at least one pair is removed per nonfinal sweep,
so a conservative time bound is O(V^3*E+V^4+L), space O(V^2+E+L). The128-node
quota bounds this reference implementation only. Production partition refinement
has its own separately specified complexity and is checked independently.

Full-width power with exponent precision w performs at most w square/multiply
iterations and one reciprocal, regardless of exponent magnitude; state is
O(w+p) bits for FP precision p. Mathematical bit-cost using schoolbook rounded
FP multiplication is O(w*p^2); these bounds do not claim particular host latency.
Freezing exponent before control avoids introducing branch UB from source poison;
the reference's concrete choice is one refinement, not a universal equality proof.
