# Portable SMIR production subsystem

This standalone Rust crate decodes and statically verifies portable SMIR objects,
lowers verified objects to a typed IR, and interprets the scalar subset. It is
under development and is not yet integrated with the RAX engine. Its own
workspace avoids changes to the parent Cargo workspace and existing lifted-ISA
paths.

## Interpreter

`ir::Module::load` runs the static verifier described below and then lowers the
object once into typed functions, blocks and operations. `interp::run` executes
one function of a loaded module. What executes today:

- integers of 1 to 128 bits: arithmetic with `nsw`/`nuw`/`exact`, shifts,
  rotates, bit counts, `abs`, byte and bit reversal, comparisons, `trunc`,
  `zext`, `sext`, `select`, `copy`, `freeze` and constants, with poison and
  undef;
- `return`, `jump`, `cbranch`, `switch`, `trap` and `unreachable`, with phis
  committed simultaneously;
- direct calls, and indirect calls through a code pointer obtained by
  `address_of` and `code_bind`; null data pointers compared for equality.

A valid module that uses anything else (memory, floating point, aggregates,
imports, exceptions, dependencies) is refused as a whole with error class
`unimplemented` before any of it runs. Undefined behaviour and traps end a run
with a fault that names the function, block and operation.

```sh
cargo build --offline --locked --manifest-path crates/smir-portable/Cargo.toml
crates/smir-portable/target/debug/smir-run \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/call42.smo \
  --entry-function 1 --argument-bits 2a000000
```

prints `{"status":"return","steps":7,"values":[{"bits_le":"2a000000"}],...}`.
Arguments are little-endian hex of exactly the parameter's byte size. Exit
status is 0 when the program ran, whatever its outcome, 1 when the object or
request was rejected, and 2 for a usage error.

The interpreter is compared with the Python reference machine report for
report (status, result values, step count, and the code and location of every
fault):

```sh
cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml --test interp
```

This needs Python 3. It runs about 5,500 cases over the programs authored in
`tests/interp/programs/build.py`, and every function of the existing
conformance objects that both engines accept. The reference machine executes
about five thousand steps a second, so the test takes a minute or two. To
change the programs, edit `build.py`, run it, and reassemble:

```sh
python3 -B crates/smir-portable/tests/interp/programs/build.py
python3 -B tools/smir-format/smir.py assemble \
  crates/smir-portable/tests/interp/programs/programs.json \
  --output crates/smir-portable/tests/interp/programs/programs.smo
```

## Static verification

The independent compiler-contract references have separate, versioned receipts;
earlier candidate qualification is historical during the ABI revision 2 migration.

The current public representation APIs are `decode_object` and `canonical_bytes`.
They check candidate0.2/profile2 framing, all ten ordered payload roots, revision,
aggregate limits and exact content identity. `ParsedObject` is unverified syntax;
it provides no executable admission or guest execution method.

Build from the repository root with locally available pinned dependencies:

```sh
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target \
  cargo build --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --bin smir-inspect
```

Inspect canonical encoding:

```sh
/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target/debug/smir-inspect \
  roundtrip example.smo
```

The result is one JSON object with `status:"decoded-object"`, content identity,
`executable_admitted:false` and canonical bytes. Optional metadata bytes survive
the roundtrip. Exit0 is inspection success; exit1 is a rejected object/resource
request; exit2 is an invocation or IO failure. No instruction executes.

`verify PATH` calls the actual type, ABI, metadata, program and cross-root static
verification phases. Successful inputs must satisfy both the semantic predicates
and explicit, finite ABI/metadata coverage predicates. The source-function profile
uses portable signed `int32(int32)`, with separately checked optional pointer,
canonical C23 variadic/jump-state, storage, service and internal-helper forms.
These extensions do not admit arbitrary records, imports, C++ metadata or data/TLS
symbols merely because their sizes match. The exact current restrictions are in
`src/abi/audit_profile.rs` and `src/metadata/audit_profile.rs`. Names and IDs are
checked through actual references. Every present record is checked, including
unused records. Valid forms outside the audited coverage reject as unavailable
evidence; full production P2 qualification remains incomplete.

A successful result has `status:"verified-object"`, `executable_admitted:false`
and seven lossless owner-root inspection entries. Its private `VerifiedObject`
retains all ten source roots and every phase's checked facts and requirements.
Inspection JSON cannot construct a proof. Providers, capabilities, native
evidence and runtime lifetimes require a later process-bound admission stage.

The draft compiler contracts and independent oracles are under
`../../docs/specifications/smir/portable/`. Current compiler qualification is
computed by `../../tools/smir-format/check_spec.py`; observed counterexamples
reopen that gate. Production implementation and host qualification are separate.
No portable interpreter, JIT, LLVM emitter, hosted library, foreign C++ engine or
six-host qualification is supplied by compiling this crate.

Focused core tests use the same production files:

```sh
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target \
  cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --lib core_tests::
```

The independent Python generator in `tests/integration/` records exact wire
fixtures and node counts. It is a test oracle only; production Rust does not
invoke Python. The separately owned differential suite compares real Rust output
against unchanged Python/C++ references and contract-derived semantic negatives.
