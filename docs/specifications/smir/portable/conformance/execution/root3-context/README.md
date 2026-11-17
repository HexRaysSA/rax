# Original Root3 context reference witnesses

Run from the project root:

    python3 -B tools/smir-format/execution/test_candidate_root3_context.py
    python3 -B -O tools/smir-format/execution/test_candidate_root3_context.py

Each case runs in a separate process with canonical format, execution, ABI and
runtime imports. The fixture is a real 8710 B SMO with all ten original roots and
embedded source contract. `manifest.json` records exact bytes/hashes and the two
source-authored foundation inputs; no native C/C++ behavior is inferred.

The complete-pipeline case uses the genuine RootContext, original canonical
SourceQueryBudget, real ABI factory and body verifier, then the public runtime
source checker. The runtime original-v3 checker companion is a required separate
integration input. No report, stamp callback, owner subclass, edited success flag,
revision 2 projection or replacement budget stands in for those factories.

Coverage includes original root3/schema hashes, complete unchanged body/source
custody, source-call inspection, old revision 2 schema identity and Type/Layout
parity, budget identity through actual deep copies, negative authority/cache/input
mutations, UTF-8 and graph/cardinality boundaries, and quota before original copy,
ABI/body/type/targets/uses/internal-helper work. Observing wrappers delegate real
facts. Quota exhaustion consumes the actual immutable ledger; it never resets or
mutates budget policy. Expected refusal does not count as guest execution.

Assumption Register:

| ID | Dependent result | Stress test / falsification probe |
|---|---|---|
| C31 canonical original owner, schema and ledger remain stable | original-v3 custody | changed embedded contract, replacement B, root/schema hash checks |
| C32 actual optional-budget kernels preserve original predicates | body/type/layout parity | old None regressions, actual plain-v-metered digests/layouts, same-B deep copy |
| C33 finite profile bounds expansion before inherited factories | logical cost envelope | wide raw/array, dynamic record, pointer width, list/parameter/UTF-8 overflow, quota entry controls |
| C34 body/static constraints are partial | authority boundary | immutable false fields, execution_checked remains None, source registry/execution unavailable |
| C35 isolated canonical imports resolve actual factories | composed evidence | subprocess source audits, optimization flag controls, complete original body/source result assertions |

High: full source closure, observer execution, lifecycle/frontier/EH/admission and
portable runtime remain incomplete. Medium: initial flat SELF profile excludes
inheritance, DEP/native/foreign and general helpers; logical accounting is not a
CPU/RSS limit proof. Low: CLI and Rust format migration are separate work packages.

Implementation costs are proportional to actual captured bytes/trees and kernel
work. For a body with b blocks and e CFG edges, the dominator fixed point performs
at most O(b^2) monotone bit removals plus scans; explicit loop/collection charges
precede each scan. Coinductive type equality visits finite ordered type pairs;
shape hashing uses the actual bounded quotient algorithm. Its explicit graph
reservation is O(V^3(V+E+L)) work and O(V^2(V+E+L)) copied bytes for vertices V,
edges E and serialized labels L. Physical expansion is checked iteratively before
recursion. Helper parse/digest charges use actual source sizes/structure and fixed
read multiplicities: candidate.json three reads, helpers-v1.json five reads per
validate call. Basic node/collection charges also precede enclosing shell work.
These deliberately conservative logical units exclude allocator capacity and
host instruction counts. No compiler-freeze conclusion follows from this suite.
