# Original source-path witnesses

These inputs exercise the accepted local ABI-CANONICAL-SOURCE-PATHS-02 static
resolver. They do not execute SMIR, create private source facts or certify a
dynamic virtual adjustment. `source.smo` is an explicitly authored ten-root
fixture; `generate.py --check` reproduces it from the closed native AST report.
The generator is not a production LLVM/SMIR emitter. Actual decoder fields are
never filled or upgraded. `records.json` contains fixture-local selectors only.

`paths.cpp` was inspected by pinned Clang and the existing AST tool. The normalized
`clang-records.json` preserves those observations, with byte/source identities and
limitations in `oracle-provenance.json`. Fourteen record geometries are separately
checked with the portable mathematical layout model. The comparable native subset
uses int, ordinary records, bases, fixed arrays, empty/NUA fields and unions.
No long-double/vector/BitInt/native calling-convention oracle is inferred.

Run from tools/smir-abi:

    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest record_layout.test_source_paths -v

Each test runs in a separate process to preserve tool namespaces and canonical
SourceQueryBudget/RootContext identities. Tests cover source/declaration/layout,
SELF/DEP namespaces, diamond/nested/array identities, symbolic range relations,
private units, complete/nonvirtual views, original context/ledger/source guards,
coverage joins, later semantic errors after unavailable metadata and exact quota
refusal. A nonvirtual root with unknown enclosing most-derived class produces no
virtual key/geometry; a known complete member/record-element domain can resolve its
own virtual bases. Equal static cell shape never converts a view or creates a
runtime object, lifetime generation, alias, SourceFact, Journal or Scope.
