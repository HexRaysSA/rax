# Independent generic function conformance

This corpus contains35 ABI3/V3 whole objects, authored independently of the R
fixture generator. The seed is the preserved compiler public identity source.
The generator uses actual schemas and the genuine Python ABI/execution/runtime
validators; tests invoke the complete Rust factory. Static verification never
grants execution authority or serializable opaque arguments.

| Rust static outcome | Count |
| --- | --- |
| Verified object |18 |
| Exact semantic rejection |13 |
| Explicit unavailable evidence |4 |

The Python contracts accept22 and reject13. The four Rust controls preserve
wide DEP expectations, hidden/weak symbols, and genuine C++ LP64 long64 source
ABI coverage limits. The CPP64 fixture uses nominal references for lowered
values/results and an independently checked execution Function reference.
Names and integer IDs do not select an ABI or substitute for original facts.

`expected.json` is the explicitly reviewed outcome mapping; generation never
changes it. `observed-python.json` records observations and object hashes.
The exact mapping was acknowledged by ROOT/R via
GENERIC-FUNCTION-INDEPENDENT-02 (coordination records). All original41 metadata
fixture bytes and their Rust outcomes are protected by these tests.

```sh
python3 -B tools/smir-llvm-contract/generic_function_cases.py generate
cd tools/smir-llvm-contract
SMIR_GENERIC_RUST_CLI=/absolute/path/to/smir-inspect python3 -B -m unittest test_generic_functions -v
```

The separate executable witness `wide-internal-call.smo` has two integer64
arguments and results, with a genuine SELF internal call. It returns
(sum, square(sum)) modulo2^64. For arguments2^64-3 and17 it returns14 and196 in
7 reference-machine steps, using original registry/Machine admission. Normal
and optimized children are invoked explicitly; the witness does not execute
native/JIT code or grant production admission.

```sh
python3 -B tools/smir-format/smir.py run   docs/specifications/smir/portable/conformance/llvm/generic-functions/wide-internal-call.smo   --entry-function 0 --argument-bits fdffffffffffffff   --argument-bits 1100000000000000   --reference-policy docs/specifications/smir/portable/conformance/llvm/generic-functions/policy.json
```

Tests cover three wraparound vectors in both modes, Int1/Int9 canonical padding,
void, and nine exact refusal inputs per mode. Oversized9B input is an argument
syntax error; Int65 with8B and DataPtr bodies are type-scope errors; CodeAddress
entry and ordinary source-planI64 are signature-scope errors. Negative-only
observers delegate to original Machine methods, assert zero construction/start/
run calls, and restore them. Successful facts and comparators are never replaced.

Assumptions/probes: existing actual type/program rules admit the shapes (full
factories and malformed arity/type/noundef tests); opacity stays separate from
execution (actual refusal observers); existing41 remain unchanged (hashes and
factory comparisons); integer arithmetic preserves width (exact normal/O result
bytes). Generation/time/space scale with total source-case bytes plus the owner
validators' bounded graph work. Arrays remain symbolic in the type records.

High scope limit: metadata facts do not discharge runtime admission. Medium:
source-linked and nondefault guard limits remain explicit. Low: this finite
reference suite makes no host performance, parallel guest, JIT or native claim.
Compiler freeze depends on complete contracts/schemas/witnesses and resolved
interfaces; missing live runtime issuers alone belong to later runtime admission.
