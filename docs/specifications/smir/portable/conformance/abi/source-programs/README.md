# Independent source-program descriptors

The closed draft grammar is `schema/abi/source_programs.json`. The executable
reference verifier is `tools/smir-abi/record_layout/source_programs.py`.
The document-local IDs and original SELF/DEP references describe compiler
requirements. Reports have `binding=unbound`, `runtime_authority=false`, and
`source_fact_authority=false`.

Local revision 2 names `context.abi_site`, the original ABI-site configuration
label. It agrees with `root2.manifest.site` and `root10.identity`; it conveys
neither translation-unit identity nor complete ABI-site semantic admission.
Private source translation-unit UIDs remain per `Nominal.identity.unit`.
Old revision-1 `unit` has no alias or default. A shared cumulative source budget
can prepare several original contexts, each retaining its own source stamp and
anchor. Root payload digests and descriptor-content digests have distinct roles.

From the repository root:

```sh
(cd tools/smir-abi && python3 -B -m unittest record_layout.test_source_programs -v)
(cd tools/smir-abi && python3 -B -O -m unittest record_layout.test_source_programs -v)
```

`verify(document, *, budget)` takes the canonical nonresettable
`SourceQueryBudget`. It checks source class/method associations, complete versus
nonvirtual cleanup schedules, distinct original Journal programs, delegation,
checked symbolic array progress, and implicit-created source patterns.

`check_source_associations(document, owner, context_id, *, budget)` additionally
compares represented original references against a genuine `RootContext` and its
original S-PROD014 source stamp on the same ledger. Its output enumerates checked
raw source joins and remaining producer/CFG/runtime obligations. Extended class
traits and actual CPP source-cell coverage need their own original producer.

`compare_ast(document, ast_report, *, budget)` requires nonempty explicit mappings.
It checks all neutral AST relations and the mapped class/method/program/slot
schedule. Partial mappings retain exact unmatched obligations. Original nominal
parameter types, class traits, source ownership and body behavior remain separate
binding obligations.

`delegating.cpp` is a project-owned copy of the LLVM-role witness with an explicit
constructor, a delegating constructor and a destructor. `delegating-ast.json` is
fresh output from the pinned native Clang AST witness tool. `delegating.json` is
an independently authored descriptor/mapping. `oracle-provenance.json` records
source/output/tool/build identity and observed limits. The six matched variants
are complete/base constructor, delegating complete/base constructor, and
complete/base destructor. The AST body remains opaque.

Array counts stay symbolic. `completed` is a conditional prefix bound; pending
construction uses index `completed`, pending cleanup uses `completed - 1`.
These records do not encode the actual current live-cell mask or issue effect
completion. Uniform union selection is explicit per source pattern. Nonuniform
per-element union selection and zero-size nonvirtual views remain unavailable.

The source-authored physical constructor fixture passes current ABI and
execution verification with its actual `this` entry plan and public SourceProgram
implementation association. The `physical_entry_association` case checks these
relations without replacing a verifier. Historical `physical_execution_gap`
receipts retain the earlier `function_default_ordinary` rejection. Entry
association does not admit an ordinary source call, callable address or reference
execution profile. Actual CPP object claims, Journal views, source alias
generations and coordinated foreign execution remain separate implementation
gates.
