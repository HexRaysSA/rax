# Independent metadata manifest cases

These ABI3/V3 source cases exercise the actual Python ABI, execution, and
runtime metadata validators and the complete Rust `smir-inspect verify` factory.
They do not select providers, admit execution, emit native code, or construct
runtime authority. All wire bytes have genuine content identities.

The source seed is an exact copy of the public
`conformance/envelope/candidate/reference-execution/source.json` at package start.
The generator removes its indirect caller and independently authors mutations;
it does not import the R metadata fixture generator or reuse its expected results.
Local numeric IDs are fixture data, not public IDs. `observed-python.json` records
exact independently observed results, checked against explicit diagnostic pairs
in `test_metadata_manifest.py`; generation cannot redefine those expectations.

Run from repository root:

```sh
python3 -B tools/smir-llvm-contract/metadata_manifest_cases.py generate
cd tools/smir-llvm-contract
SMIR_METADATA_RUST_CLI=/absolute/path/to/smir-inspect python3 -B -m unittest test_metadata_manifest -v
```

The strict comparison requires 16 verified objects, 23 exact semantic rejections,
and two explicit unavailable-evidence controls. The latter are valid hidden
visibility metadata and valid C source linkage reaching the existing Rust ABI
profile boundary. They are not semantic rejections or positive Rust coverage.
The Python contracts accept 18 cases and reject 23. Dependency cases validate
original consumer expectations without provider selection. Recipe positive
coverage is absent because the actual preceding ABI phase cannot issue a
recipe in this bounded profile; the recipe namespace rejection is exercised.

The test hashes semantic sources, fixture bytes, schemas, tools, and the actual
Rust executable before/after the run. It does not attest that a supplied Rust
binary was compiled from a particular source cut; build provenance and combined
qualification remain integrator responsibilities.

Assumptions and falsification probes:

| Assumption | Probe | Dependent result |
| --- | --- | --- |
| Source seed is current ABI3/V3 | Genuine schema round-trip and same-context ABI/execution validation | Every case |
| Original consumer expectations require no selected provider | Actual static runtime validator, no deployment binding | DEP cases |
| Unsupported Rust phases remain unavailable | Exact error class and code; no framing/resource substitute | Two controls |
| Python/Rust diagnostic order can differ | Explicit per-case diagnostic pairs and semantic error class | 23 negatives |

Bounded findings: high: no production admission claim follows from static
verification; medium: C/hidden/recipe positive coverage remains bounded by
existing phases; low: local IDs deliberately collide between entity namespaces
so incorrect namespace lookup cannot pass the tested negative cases.
