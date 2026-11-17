# Checked nonordinary entry associations

These source-authored descriptor fixtures exercise actual ABI admission, public
SourceProgram association and execution-body verification. They are not compiled
Clang/native C++ bodies or witnesses of object lifetime execution.

Four cases: constructor, explicit VTT constructor descriptor, destructor and a
nonconstructor aggregate-result method with hidden `[sret,this]` arguments. Each
contains raw source JSON, its ABI SourceProgram descriptor and reproducible SMO
bytes. The implicit roles remain outside the explicit source parameter list. The
VTT case declares its VTT explicitly; it makes no inference about C1/C2 variants.

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/smir-format/execution/nonordinary_entry_fixtures.py --check
cd tools/smir-format/execution
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_candidate_nonordinary_entries
PYTHONDONTWRITEBYTECODE=1 python3 -O -m unittest -v test_candidate_nonordinary_entries
```

The generator checks real ABI and execution factories before producing bytes.
`--check` changes no fixture files. Negative tests reject missing associations,
wrong FullFn/parameter types/noundef, wrong hidden argument order and VTT without
this. They retain the distinct source noexcept/body escape/no_return contracts.
Actual ordinary source plans and CLI execution still refuse nonordinary methods;
the CLI test measures zero Machine/CodeRegistry constructors, both wrappers fully
delegate if invoked. No replacement verifier or successful producer is installed.

Assumptions: actual original ABI descriptors and public SourceProgram association
are the structural oracle; mutation/role/noundef negatives falsify mismatches. A
structural entry association issues no source-call, incoming lifecycle, S/J, alias
or production execution permission. Runtime exception propagation, source object
lifetime/private issuers, parallelism and native implementation remain separate.
