# Conditional source lifetime reference checks

This directory is a first-wave, UNBOUND compiler contract fixture package.
The verifier is executable Python; its result is static obligations, never
SourceFacts, ObjectClaim, JournalView, Scope, J/E, live registry permits or
portable execution admission. No active candidate payload root includes this
new grammar. Public versions/IDs and CppSourcePath/CppCoverage namespaces remain
unassigned. A successful check does not establish actual C++ object lifetime.

Run from the checkout root:

```sh
python3 -B -m unittest discover -s tools/smir-format/execution -p test_candidate_source_lifetimes.py
python3 -B -O -m unittest discover -s tools/smir-format/execution -p test_candidate_source_lifetimes.py
```

The local API is `candidate.source_lifetimes.verify(document, budget=ledger)`.
The ledger must be the genuine canonical SourceQueryBudget, with explicit
caller limits; a counterfeit/foreign/resettable stand-in is rejected. The
frozen result always has binding=unbound, runtime_authority=false and
source_fact_authority=false. These checks never execute an envelope.

`cases.json` is GENERATED serialization of the hand-authored `cases()` table in
`tools/smir-format/execution/test_candidate_source_lifetimes.py`, with complete
input documents and independently specified expected outcomes. Regeneration
uses that table only, never verifier outputs; the tests compare stored cases
exactly with the table. Its expanded size/line count reflects self-contained
fixtures, not hand-maintained implementation source. Keep the source table and
serialization in the same exact reviewed cut.

| Surface | Checked condition | External obligation still retained |
| --- | --- | --- |
| Source bindings | Original Function/context/SSA/nominal/path and explicit origins | Actual final CFG/SSA/source producer and opaque retained alias issuer |
| object_end | Observing activation, object generation, allocation generation, exact effect/stage | Actual exclusive call-preentry claim and admitted effect |
| Replacement | Fresh generation, explicit selected alias rebinding | C++ transparent-replacement/launder/reachability and original source truth |
| Implicit set | Eligible-parent closure, symbolic counts, explicit union selection | Actual source-created-set event proof; trait flags are hypotheses |
| Programs/views | Original Journal/class/context/view, assumed geometry/coverage | Genuine ABI descriptor/program/coverage identity and bounds proof |
| Cleanup | Per-complete-owner cells, current J, reverse completion, exact E | Actual runtime cell masks/completion ordinals and private issuer |
| Delegation | Separate child J/ticket/outcome; pending coverage cannot be mutated | Actual retained claim/subobject/worker synchronization |
| Scope exits | Six literal declarations, current scope/generation/J/E conditions | Actual helper execution/continuation/propagation |
| Frontiers | Supplied vector order/cursor, suspend/resume/cancel/nonlocal/trap | Actual complete CFG vector, effect outcome and concurrency protocol |

The protocol initial state, cell_models, program_models and actions are explicit
hypotheses. Source trait booleans, hashes, qrefs and integer generation fields
cannot authenticate actual runtime state. Cells are indexed by complete-owner
identity plus pattern and object generation, so distinct objects do not share
completion. Repeated elements remain checked symbolic counts; no allocation or
loop is proportional to byte extent or array length. Coverage is assumed
source-cell selection, never inferred from pointer bits or a byte interval.

Normal.with_journal has an exact compiler grammar but its actual normal
completion/transfer action returns Unavailable SL_EXIT_NORMAL_JOURNAL_OUTCOME.
The live outcome adapter is absent. Zero nonvirtual extent is explicitly
rejected in this local draft; no guessed zero-byte program is created. Missing
implicit union selection is Unavailable after graph validation. Actual source
alias/program/coverage/claim/view/current-J/Scope issuers, original DEP Journal
declarations and actual source-created-set event binding remain unavailable.
These gaps block whole C++/compiler freeze. This is not a native/parallel/JIT or
host qualification test.

Bounds: closed JSON Schema 2020-12; exact integer types exclude bool; u32 IDs
exclude UINT32_MAX; checked u64 multiplicities and address arithmetic; at most
200000 input nodes, depth<=64 and caller depth, strings<=4096, 8 MiB string-copy
bound and schema<=256 KiB. Table/action maxima are explicit in the schema.
Canonical cumulative work/edge/copy quotas are charged before bounded traversals
and state copies. Input is not mutated. Host allocation failure/asynchronous
termination is outside this logical budget model. Pattern closure uses O(V+E)
space/work with bounded parent depth; protocol scans are bounded by actions
multiplied by tables and selected coverage, with no sizeof/array-extent loop.

Assumptions and falsification probes:

| ID | Assumption | Probe |
| --- | --- | --- |
| SL1 | ABI/source-program references remain unbound | Reject consumption as actual descriptor/factory result; require separate original-context join |
| SL2 | Static protocol results are not runtime authority | Result flags immutable/false; no issuer/factory dependency |
| SL3 | Source and allocation generations differ | Same address/reuse rejects old object alias; release must advance allocation generation separately |
| SL4 | Trait/union/replacement truth comes from actual source | Nonimplicit descendants absent, unknown union unavailable, two selected arms reject |
| SL5 | Existing locators and six literal helpers are retained | Wrong locator/options/SSA overlap/original E and consumed J reject |
| SL6 | Views share cells only under exact owner, never current J | Two-object isolation, child failure keeps parent virtual work/J, duplicate outcome rejects |

Provenance is recorded in provenance.json. Exact proposal/review receipts and
observed test/dependency hashes are run artifacts under the SEMANTICS run
coordination directory; they do not turn draft expectations into runtime facts.
