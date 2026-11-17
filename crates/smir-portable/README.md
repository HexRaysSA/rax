# Portable SMIR production subsystem

This standalone Rust crate implements the production verifier in P2. It is under
development and is not yet integrated with the RAX engine. Its own workspace
avoids changes to the parent Cargo workspace and existing lifted-ISA paths.
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
