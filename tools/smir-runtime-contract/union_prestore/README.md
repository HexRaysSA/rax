# Quiescent union pre-store reference

This executable reference tests one scalar assignment protocol over a single tracked
physical allocation and separate bounded source-initialization data. It uses the
existing independently verified execution `Machine`, `Raw`, `Memory` and canonical
`SourceQueryBudget`. Its local execution fixture is authored here and verified before
use. It imports no execution test module and decodes or executes no envelope.

From the checkout root:

```
PYTHONPATH=tools/smir-runtime-contract python3 -B -m union_prestore.reference --check --selftest
PYTHONPATH=tools/smir-runtime-contract python3 -B -O -m union_prestore.reference --check --selftest
PYTHONPATH=tools/smir-runtime-contract python3 -B -m union_prestore.fixtures --check
```

`--check` compares both fixture products byte-for-byte without writing, validates
the closed JSON Schema, and executes 14 authored scenario observations. `--selftest`
runs the explicit reference test module. The CLI emits a single JSON report; test
progress goes to stderr. Zero exit means these finite checks passed. It grants no
source facts, semantic admission, runtime authority or registered cost profile.

Discovery uses an inert package `load_tests` hook and a fresh child interpreter,
preserving parent `candidate`, `codec`, `common`, `schema` and sys.path identities.
The child retains actual Python optimization, bytecode flags and cache prefix. It
places the execution candidate first before imports; an already loaded different
candidate raises `UNION_REFERENCE_NAMESPACE` instead of deleting/replacing modules.
In an existing Runtime candidate session, use the child registration or CLI.

The protocol reserves model budget and checks physical write permissions before
changing a source generation/cursor; it performs one real scalar store and one
completion. Park/resume/cancel cannot replay a committed store. Same live arm keeps
its initialized sibling; a fresh arm/restarted lifetime has separate indeterminate
source value state while actual physical bytes/shadows remain. Prospective handles
bind their first modeled birth and cannot retarget a later generation.

Source loads project indeterminacy onto returned Raw values without physical writes.
Freeze preserves the source-init mask; source stores replace destination state from
that mask. Full storage copies transfer actual physical Raw, including origin spans,
and snapshot the initialization plane separately. Overlapping memmove is compared
against independent byte and initialization-byte array snapshots. Numeric conversion
checks source initialization, requires explicit actual matching Int type, then uses
actual core `from_raw`, preserving its range/origin/poison/undef behavior.

The sole supported source-phase assumption is a quiescent union. All bits are modeled
as value bits, <=32768 bits per physical object. Other allocations and missing
initialization entries reject before access/effects. No AST eligibility, private
phase/event/source/init/cleanup issuer, nested/array candidate transaction, trivial
call/expanded group, production atomic transaction, guest parallelism, JIT/LLVM
emission, hosted-library or native-guest qualification is implemented. Logical
reservation costs are illustrative. CPP union01+mandatory02/03/04 and canonical
ABI09+10 remain the source-facing drafts; initializing-phase source behavior is a
required gap and cannot be inferred from this model or native constexpr controls.

Assumptions and falsification probes: tracked allocation only [extra allocation,
missing map, forged added key]; quiescent whole-object arm [nested/padded/construction
cases unsupported]; separately retained actual input init [frozen indeterminate
store and numeric rejection]; sequential core operation [real permission change
after prepare]; exact core numeric conversion [inrange, origin, poison/undef
controls]; illustrative cost [exact/one-less each canonical budget dimension].

The two historical owncoord model counters (unknown allocation default and independent
numeric extraction) are covered by negative/core-comparison regressions. All authority
flags stay false. The fixture schema is local reference data and has no public SMIR
record ID or admission role. Regeneration, when explicitly owned, is
`python3 -B -m union_prestore.fixtures`; this writes only cases.json/provenance.json.
