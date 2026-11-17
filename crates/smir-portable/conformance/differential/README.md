# Portable object differential acceptance

These P2 static-object and wire tests never execute guest instructions.
`VerifiedObject`, reference validation and runtime admission remain distinct.

The current ABI2 corpus contains229 targeted recipes and241 automatically
enumerated record/variant witnesses reachable from all ten object roots:470
objects in total. Roots1..9 have payload revision1; ABI root10 has revision2.
Default wire specimens prove representation only and have no semantic validity
claim. Live-state/deployment-only records are outside object-root scope.

`cases.jsonl` stores deterministic independent fixture/mutation recipes, not bytes
produced by the Rust implementation. The Python encoder and separately compiled
C++ decoder use the actual owner schemas; generated C++ tables contain data only.
Outputs, binaries, exact commands/hashes and failure reproducers belong in an
explicit external scratch directory. Existing source files and old receipts are
preserved during interface migration.

The frozen-input manifest still names historical candidate005 (762 inputs), which
was withdrawn before ABI2 migration. Its unchanged pin deliberately fails on
current source drift. A fresh root-reviewed candidate is required before a new
complete differential-target qualification. There is no automatic repinning.
Candidate002/003/004/005 receipts remain historical evidence only.

After a reviewed candidate publication and root registration, run:

```sh
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/LLVM/p2-cargo-target \
SMIR_DIFF_SCRATCH=/tmp/rax-portable-smir-01/LLVM/p2-differential \
PYTHONDONTWRITEBYTECODE=1 \
cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --test differential -- --nocapture
```

Use the role's assigned external directories. Root owns registration and combined
validation. `PYTHON` selects an executable Python3; `CXX` selects one executable
path, with no shell fragments. Darwin uses an explicit SDK. Missing tools,
timeouts, crashes, malformed reports, unmapped diagnostics, frozen-input drift
and incomplete predicates fail; they never silently skip.

A whole-object decode reports executable_admitted=false. Static verification also
retains false admission and the exact seven owner contract records. Input bytes
cannot supply native/provider evidence. Wider deployment/foreign/registered/used-
dependency predicates require actual independent adapters; unavailable evidence
is not negative agreement or a guest execution result.

`verify-static-reference` validates original unprojected roots through actual ABI,
execution and local runtime predicates. It selects no providers, calls no
runtime deployment binder and invents no always-true evidence callbacks. Its
local static scope includes unused declarations with no dependency use; actual
unsupported evidence remains unavailable. Runtime memory policy is independently
configured, never copied from module requests. Actual P2 production qualification
and complete-grammar obligations remain separate from this bounded adapter.

Positive recipes cover source identity, services, storage/TLS, metadata, UTF-8,
integer/FP/cast/aggregate/vector/pointer operations, phi/control flow and terminal
frontiers. Invalid siblings isolate shape, SSA/CFG, ABI plan, nominal hash,
visibility, capability, reserved-ID and source/symbol category predicates. Their
operations and recursive call recipes are not executed. Independently valid
objects outside the finite production proof profile expect unavailable evidence,
not semantic rejection; invalid siblings must reject before coverage assessment.

Raw payload mutations preserve valid framing while changing revisions, lengths,
tokens, UTF-8, extents or content identity. Before-bytes are guarded; only framing
offsets/lengths are repaired, never the content digest. Accepted
LLVM013-CORPUS-REV1 corrects only the historical expected diagnostic of the
three-byte section1 revision prefix to WIRE-REVISION. All emitted bytes remain
identical. Whole-wrapper prefixes shorter than4 bytes reject WIRE-REVISION;
generic ordered-record partial integers retain WIRE-TRUNCATED. No alias is used.

The C++ `--candidate-records` probe validates framing, revisions and canonical
ordered roots, explicitly excluding content-digest validation and semantic
admission. The two digest-corruption cases therefore have no C++ identity oracle.
The Python whole codec and Rust roundtrip check the independent content digest.
Individual C++ `--record` comparisons establish syntax only.

Boundary recipes include integer/raw widths1,65535,65536,65537 and8388608 bits;
8388609 rejects type_width. A65536-element root9 vector is paired with the65537
count rejection. These finite recipes avoid giant literals and do not grant
source ABI layouts or semantic validity to arbitrary repeated tokens.

Prior narrow predicate repairs and profile changes are documented in immutable
INT024..027/ABI-PROD016/R-PROD005REV2 decisions and archived receipts. Current
counts and outcomes must be obtained from exact current bytes. Passing these
methods does not implement portable interpretation, JIT, hosted libraries,
foreign C++ engines, launchers or six-host qualification. Full P2 and compiler
freeze remain explicit root gates.
