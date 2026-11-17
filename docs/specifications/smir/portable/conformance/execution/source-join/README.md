# Original typed source join reference

Run from tools/smir-format/execution:

```
python3 -B -m unittest test_candidate_source_join -v
python3 -B -O -m unittest test_candidate_source_join -v
```

The exact closed grammar is schema/execution/source_join.json. The reference
candidate/source_join.py consumes a separate source-program ABI descriptor and
actual original RootContext owners on the canonical cumulative SourceQueryBudget.
Every context names its actual family, ABI site, executable schema digest and all
present sorted wire-root digests. These coordinates are separate identity domains;
legacy source_unit/abi_source/execution_source fields are not reinterpreted.
At least one original context is required. OriginalOwnerInput and prior bindings
are bounded to 256; every selected context is checked by the real deferred ABI
source-association verifier, then its original stamp is checked again before output.
Same-byte fresh owners are separate legitimate inputs; prior bindings cannot move
to a fresh owner. Cached function indexes are not original source evidence.

Direct one-edge non-array member/nonvirtual-base cells require exact declared
nominals, record/slot references and explicit geometry. Members use the real ABI
original-field checks; nonvirtual bases additionally compare actual original
base declaration index, class identity and selected portable layout. Nonliteral
base type aliases remain unavailable after represented identity/geometry checks.
A cleanup program must exhaust its principal slot coverage. Root cells never
stand for slot zero. Nested/array/virtual/alternative paths are traversed and
checked for represented errors but remain unavailable in this direct binder.
Identical full syntactic selectors within one program reject as duplicate cells,
including unavailable selectors. Distinct array indices/nested cells sharing a
principal slot are not duplicates; their extended proof is still unavailable.
Virtual canonical equality is not inferred by this binder.

A known descriptor/requirement/source mismatch rejects before selected missing
metadata or extended-selector unavailability. Unselected context deferrals remain
explicit in a successful immutable report. Successful reports are always UNBOUND;
constructor invariants prevent overriding authority flags. No SourceFacts, source
aliases, object/scope generations, source traits, live journals, runtime admission,
native execution or compiler freeze is issued. The older conditional source-state
and lifetime schemas are unchanged and are not converted into live facts.

The reviewed schema is SHA-256 pinned before parsing and rechecked after the real
original-source guards. Input copying, schema I/O, indexing, digesting and before/
after guards charge the same cumulative real ledger. Schema resource exhaustion
remains a resource diagnostic. The test quota delegates the real original guard;
there is no producer callback or fabricated source verifier. A changed schema
copy is genuinely read and rejected; an exhausted ledger performs no schema read.

Ten authored cases specify independent positive/rejection expectations. Other
methods cover original nonvirtual geometry disagreement, exact owner/stamp reuse,
unsupported root duplication, afterguard quota, original mutation, zero budgets
and schema depth. Inputs include actual canonical source-path source.smo roots;
their selected portable layouts are static original-source evidence, not native
execution. Codec import uses a separate module name to preserve execution.codec.

Complexity is bounded by captured input rows, traversed paths and selected real
ABI checks. The local base check currently rebuilds type/layout indexes per direct
base: O(B*(T+L+D)) work and O(T+L+D) transient space; the external ABI verifier and
wire-root/schema guards have their own charged costs. Arrays are not expanded.

Assumptions: genuine current original roots and matching schema (mutation/hash
probes); exact ABI deferred API (missing-path then later bad-Journal counter);
finite direct subset (unsupported roots retain unavailability); independent
identity domains (wrong schema/site/all-root rejection); cumulative ledger and
atomic result publication (zero/depth/afterguard tests). High: descriptor agreement
alone cannot prove original base geometry. Medium: selected Unknown must not hide
known later errors. Low: these static joins leave live source carriers unresolved.
