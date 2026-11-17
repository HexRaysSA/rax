# Isolated V3 Rust reference

This standalone workspace independently normalizes raw source fragments under
HASH-V3-EXISTING-01 REV2. It does not read producer preimages or digests, invoke
Python, execute an envelope, register a profile or construct ABI/runtime proofs.
The active V2 and P2 crates are unchanged. Record geometry, actual execution/plan
bindings, native evidence and source-language truth require separate admission.

Use an output directory owned by the current caller, outside RAX and LLVM:

```sh
export CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/ABI/v3-rust-target
export SMIR_ABI_V3_REFERENCE_TMP=/tmp/rax-portable-smir-01/ABI/v3-rust-check
export CARGO_NET_OFFLINE=true
cargo test --offline --locked --manifest-path tools/smir-abi/function_address/rust_reference/Cargo.toml
cd tools/smir-abi
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest function_address.test_rust_reference -v
PYTHONDONTWRITEBYTECODE=1 python3 -O -m unittest function_address.test_rust_reference -v
```

Those example paths belong to the ABI role. Other roles must substitute their own
directories. `SMIR_ABI_V3_REFERENCE_BIN` selects an independently built executable
and prevents the harness building. `CARGO_TARGET_DIR` selects a separate build
cache. `SMIR_ABI_V3_REFERENCE_TMP` (or existing `SMIR_ABI_TMP`) selects persistent
build logs and the differential receipt. Without overrides, a new caller-owned
temporary directory is used and removed afterward. Outputs/binaries within either
checkout reject. Missing tools, executable or cached dependencies fail; no skip
or successful fallback substitutes for independent Rust execution. Dependencies
are exactly cached serde_json 1.0.151 and sha2 0.10.9, with a locked offline graph.

The binary accepts two JSON frames on standard input. The first is one line of
at most 1024 bytes with ALL seven unsigned limits:

```json
{"max_work":1000000000,"max_edges":1000000,"max_bytes":512000000,"max_depth":128,"max_nodes":4096,"max_input_bytes":1048576,"max_output_bytes":1048576}
```

The remaining bytes are one JSON request with exactly these fields:

```json
{"documents":{"main":{"types":[],"layouts":[],"domains":[]}},"expectations":[],"owner":"main","root":{"module":{"kind":"self"},"id":1},"view":"DEF","ignore_top_cv":false}
```

Empty tables in that shape are explanatory, not a positive hash fixture. Use the
seven committed raw-source vectors in the project file
`docs/specifications/smir/portable/conformance/abi/function-address/hash-v3-vectors.json`.
An expectation row is `{owner,slot,declaration,target}`; it maps only to a LOCAL
nominal in that original consumer. No selected-provider SELF transplant occurs.

The 1 KiB header has a fixed, bounded bootstrap parser (depth 4, 128 KiB payload,
finite work/edges). It supplies no operation defaults. The actual caller ledger
exists before body allocation; its full input capacity is reserved up front and
charged. Source parsing rejects duplicate keys, floating numbers, malformed UTF-8,
unpaired surrogate escapes and out-of-range integers. All source shapes and named
kind/arity/flag/reference/completeness/layout-association predicates run before
normalization. Parser depth and graph depth are separately checked against the
same explicit limit; `max_nodes` bounds DEF/EXPR graph states. Resource refusal is
controlled, and failed multidimensional ledger charges do not partially update.

Canonical output uses an independent ASCII writer and BTree signature partitions
with ordered child edges. It does not use a source digest to decide equality.
The full preimage includes the exact 22-byte V3 NUL separator. Success reports
preimage, SHA-256, state/edge counts and logical work/allocated payload usage.
Output bytes and transport JSON expansion are preflighted. Errors use a fixed
bounded diagnostic response independent of the operation's output allowance.
Counts measure logical work/edges/cumulative payload allocations, not allocator
capacity, elapsed time or private runtime authority. Rust and Python resource
costs differ; semantic preimages must agree while numerical budget thresholds
need not match across implementations.

The model captures no concurrent mutable graph: Rust holds immutable references
to its independently parsed request. Source maps, quotient storage and copies
are charged before allocation as applicable. Partition refinement has at most
the finite node count of strict splits; comparisons include label/edge byte work.
Compiler freeze, parallel/native execution, full ABI admission and actual module
profile migration remain unqualified by this reference.
