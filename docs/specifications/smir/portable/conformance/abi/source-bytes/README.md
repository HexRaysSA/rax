# Source-byte ABI epoch controls

Draft reference package. No full source, executable or runtime admission.

`epoch2-byte-free.source.json` is source-authored original ten-section syntax;
`epoch2-byte-free.smo` is independently Python-encoded syntax. The Rust test takes
these exact bytes through real decoding, ObjectContext construction and type
verification, then checks that ABI2 returns typed unavailable evidence even for a
byte-free function. It does not execute this object or issue ABI2 facts.

`unsigned-char-original-roots.json` supplies the actual immutable RootContext for
`unsigned-char-projection.json`. Context0 in this standalone descriptor binds ONLY
the exact owner argument; it is not a registry/context-table index. The positive
descriptor verifies a declared Raw8 unsigned-char projection and original root
digests. It returns an UNBOUND descriptive result with every authority/admission
flag false. Actual canonical original source-category evidence remains required.

| Fixture | Required symbolic rejection |
|---|---|
| reject-duplicate.json | ABI_BYTE_DUPLICATE |
| reject-nonlocal-context.json | ABI_BYTE_LOCAL_CONTEXT |
| reject-omitted-table.json | ABI_BYTE_CATEGORY_TABLE |
| reject-wrong-category.json | ABI_BYTE_CATEGORY_TABLE |
| reject-wrong-root.json | ABI_BYTE_SOURCE_ROOTS |

Regenerate only this owned prefix using `tools/smir-abi/source_bytes/fixtures.py`;
`--check` is nonwriting. The two epoch2 byte-free artifacts are byte-exact between
normal and optimized Python. Other fixtures are canonical authored JSON assertions,
not a genuine source producer's private facts. Independent native AST association
witnesses and source-init algorithms are separate coordination artifacts.

Coverage: exact original site1/site2 recognition and identities, legacy noarg API,
unknown/duplicate/wrong-state/mismatched-identity rejection, bounded plain-tree
checks and canonical-B exact/one-less/zero site tests; original root/category/
execution/layout checks; real Raw8 and numeric Int8 storage bindings sharing an
actual source nominal; actual allocation-origin fragments lost by numeric
conversion. Limitations: no qualified all-path cost model for projection checker,
no source-category issuer, enum-library membership proof, full array/vector/plan
coverage, source-init runtime, LLVM emission, native execution or compiler freeze.
