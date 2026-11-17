# Portable execution contracts and reference witnesses

Run focused checks from the repository root (Python3.11+, Rust2024, C++20):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/smir-format/execution -p 'test_*.py' -v
rustc --edition 2024 --test src/smir/portable/execution/mod.rs -o /tmp/rax-portable-smir-01/SEMANTICS/integer-reference-tests
/tmp/rax-portable-smir-01/SEMANTICS/integer-reference-tests
```

Candidate0.2/profile2 compiler records reside in candidate/ and
`schema/execution/candidate.json`. They are separate from the legacy integer
module/FP-request/EH-protocol interfaces retained at this directory's top level.
No reference connects an unverified envelope to the production RAX engine.

| Candidate module | Contract/reference responsibility |
|---|---|
| schema_build.py, wire.py | exact ordered record grammar, strict common primitives |
| type_system.py, layouts.py | qualified types, coinduction/shape hash, physical bit/byte layouts |
| operations.py, verify.py | operation typing, CFG/SSA/phi/invoke edges, regions/PRE captures |
| context.py, bindings.py | actual section roots, ABI owner verification, exact catalog/table namespaces |
| host.py | independently registered scalar-only host descriptor graph and digest |
| values.py, raw.py, memory.py | component poison, sparse bN origins, sequential typed memory |
| ranges.py | canonical clipped/empty inrange intervals and range-only pointer taint |
| fp.py, fenv.py | exact sqrt/frem/conversions/powi/integer-round and source snapshots |
| machine.py | reverified component execution, call/cleanup continuation tickets |
| initializers.py | restricted straight-line constant evaluation, Raw8 results and private exposure |
| live.py, liveness.py | typed registry-backed snapshot structure and canonical SSA frontier use set |
| ssa_probe.rs | independent path-exclusion dominance witness |
| fp_probe.cpp | independent native binary32/64 sqrt/frem witness |

`RootContext(sections, IndependentEvidence(...))` derives real tables from
sections1/2/3/4/6/8/10. `verify_abi()` calls the ABI-owned candidate verifier;
`verify_execution()` validates all imports and code against those tables;
`component_result()` explicitly requires subsequent runtime link admission.
`execution(ref)` gives real type references plus recomputed identity;
`abi_execution(ref)` gives normalized child shape identities for ABI consumers.
No caller-certified string is used instead of graph admission. Native evidence
must come from independent registered inspection, not the same declaration read
back as its own certificate. The complete ten-root combined reference verifier is
integrator-owned; component success is not a compiler freeze or executable module token.

External TLS joins use `install_external_tls({(slot,decl):(registry,binding)})`
after ABI verification and before execution verification. The registry and issued
binding come from the actual runtime owner package; cloned consumer contexts and
producer-built bindings reject. `TlsTarget` preserves provider-owned SELF refs and
rechecks metadata/generation instead of copying authority. The independent
two-module witness uses actual content hashes, ABI comparators, deployment,
definition selection, all-root validation and private initialization leases.
It observes source initialization once per logical thread before raw lookup,
distinct slots for two threads, and stable lookup after a host-worker change.
These are reference protocol observations, not production parallel execution.

`candidate.initializers.evaluate_initializer` evaluates the accepted23-operation
constant profile on actual verified context/function/layout and private selected
runtime reservations. It returns typed value, Raw8 bytes/shadow/origins and separate
data/code exposure sets without modifying inputs. Cumulative object+all-SSA+output
logical bytes and present-value nodes are checked before literal expansion.
Runtime destination ownership, TLS binding, weak absence and atomic publication
remain independently checked; returned bytes confer no executable authority.

Live validation returns a checked value dictionary, never authority. Full restore
requires a private one-use scheduler handoff over exact snapshot bytes/epoch.
Known pointer tombstones survive as values; use still checks liveness. Journal
captures select exact activation/action/formal live instances, never just program
IDs. The sequential Machine's imported functions are explicit test adapters;
preflight rejects unbound imports/symbols/cleanups/dependencies before any operation.
Local direct tail targets are its reference limit, checked before execution.

`candidate_fixtures.py` regenerates only SEMANTICS-owned candidate cases, portable
identity, source service wrapper and global pointer/relocation/TLS fixtures.
It reads the ABI owner's current witness,
records its checksums and retains only portable declarations; its domain hashes
are explicitly synthetic fixture labels, not native execution provenance. Never
regenerate another role's files. Unit cleanup map tests isolate admitted interfaces;
actual combined-context tests use real ABI/runtime roots, not fake Deps evidence.

The Rust arithmetic witness covers widths1..128, while legacy Python arithmetic
covers1..65535 and candidate int/raw up to2^23 subject to explicit reference resource
bounds. Independent Rust SSA uses a different graph algorithm. Strict native FP
probes cover binary32/64 finite sampled arithmetic/status; host tininess-before
policy differences and NaN-result exclusions are counted, not silently skipped.
Other formats and NaN policies use mathematical/golden fixtures. CXX defaults to
/usr/bin/clang++; missing compiler/SDK is failure, never skipped/native fallback.

The focused harness does not prove production parallel execution, JIT, hosted
libraries, native foreign unwinding or six-host qualification. Exact contracts,
assumptions, source identity and complexity are in portable/02-execution.md and
05-encoding.md; current receipt hashes delimit the observed resulting tree.
