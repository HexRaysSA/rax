# Clang source-event reference witness

This working host tool builds against LLVM revision
`36763294ef639d8a6a4379d81da653dda1c20686` and observes the original Clang
AST and CFG of a finite, header-free C++23 translation unit. Its closed format is
[the reference schema](../../../llvm/source-event-witness.schema.json),
`urn:rax:smir:llvm:source-events:reference:1`.
It supports compiler-contract investigation; it does not emit or execute SMIR.

Canonical declaration IDs intern actual `NamedDecl::getCanonicalDecl()` identity
within one AST. They are local IDs, not names, offsets, source-object identities
or runtime handles. Canonical and definition coordinates use the actual Clang
locations, including `VarDecl::getDefinition()` for forward globals. Null means
no represented main-file coordinate. `end_token_offset` is the start of the last
source token, not a byte extent. Parent links distinguish semantic, canonical
lexical and definition lexical declaration contexts.

The native observer supplies an empty `InMemoryFileSystem` to Tooling, which maps
only the captured main buffer. The fixed target is `x86_64-unknown-linux-gnu`,
with C++23, exceptions, 8-bit bytes, 64-bit pointers and `long`, little-endian,
`-nostdinc -nostdinc++ -pedantic-errors -fno-trigraphs`. These inspection settings
are not a portable ABI call plan. Raw `#`, `%:`, `??=` and backslash/newline
splices, including intervening horizontal whitespace, are conservatively rejected
even in comments or string literals. External header files are unavailable.

Function rows preserve original AST nodes, syntactic containment regions,
parameters, local declaration references, construction and temporary properties,
NRVO observations, and ordered native CFG elements and successor/predecessor
pairs. The Python verifier checks closed types, local reference namespaces,
property applicability, AST closure/cycles, and exact CFG edge multiplicities
against pinned `CFGBlock::addSuccessor` semantics. AST regions are not complete
Clang Sema scopes. CFG scope/lifetime/destructor observations are not complete
C++ object, subobject or exceptional-cleanup semantics.

In `control.cpp`, the actual CFG represents a throw-to-catch path without the
local object's automatic destructor. The separate stock-Clang CodeGen witness
recorded in the run handoff emits and verifies a landingpad cleanup invoking the
actual destructor on that object's debug storage. No source-event field silently
fills the CFG gap. `traits.cpp` retains the I-C27 counter: an array can satisfy
Clang's implicit-lifetime trait while its contained class does not. Array trait
truth cannot establish implicit creation of those class subobjects.

The public Python API is `observe(source, oracle, *, budget) -> EventWitness`.
`budget` must be the original canonical `SourceQueryBudget` class, supplied
explicitly. `report()` returns a detached JSON value; the witness data is deeply
immutable. Every result remains `binding="unbound"`, `runtime_authority=false`,
`source_fact_authority=false`, `executable=false`. There is no previous-report,
private SourceFacts, source-access, active-union, S/J, runtime or ABI-plan input.

From the repository root, build into a fresh directory outside both checkouts:

```sh
python3 -B tools/smir-llvm-contract/source_event_witness.py build \
  --llvm /Users/int/dev/llvm-project --output /tmp/smir-source-event-build
```

Create an explicit budget file with exactly these four nonnegative integer fields
(`max_depth` must be 1..128; the other counts must fit unsigned 64 bits):

```json
{"max_work":1000000000000000000,"max_edges":1000000000000,"max_copied_bytes":1000000000000000000,"max_depth":128}
```

```sh
python3 -B tools/smir-llvm-contract/source_event_witness.py observe \
  --oracle /tmp/smir-source-event-build/source-event-oracle \
  --source docs/specifications/smir/portable/conformance/llvm/source-events/control.cpp \
  --budget /tmp/source-event-budget.json
CEW_ORACLE=/tmp/smir-source-event-build/source-event-oracle \
  python3 -B -m unittest discover -s tools/smir-llvm-contract -p test_source_event_witness.py
CEW_ORACLE=/tmp/smir-source-event-build/source-event-oracle \
  python3 -B -O -m unittest discover -s tools/smir-llvm-contract -p test_source_event_witness.py
```

`CEW_TEST_DIR`, `CEW_SCRATCH` and `TMPDIR` select existing isolated test, observation
and compiler temporary directories. `CEW_REFERENCE_PROJECT` is an explicit
copied-tree root for independent qualification; installed defaults locate the
repository root. Full tests require an actual `CEW_ORACLE` build receipt. The
`SourceEventPureSchema` and `BuilderPureGuards` classes run without an LLVM checkout
or oracle; their eight tests validate a frozen genuine historical report and
negative builder preflight paths. They do not attest a current native build.

The 29-test suite covers branches, aggregate returns, temporaries, lifetime
extension, loops, overloads/shadows/forward declarations, base/member destructors,
parallel CFG edges, real EH omissions, immutable results, source/schema/native
mutation, unsupported syntax, header/digraph/splice rejection, resource limits,
closed budget bootstrap, typed graph rejection, and actual normal/optimized CLI
and builder guards. One negative drift test performs a real native compilation,
then mutates a copied C++ source and requires build rejection. Its exit-zero
compiler result is not a successful build qualification.

Source is limited to 1 MiB; declarations to 4096; functions to 64; AST nodes to
8192 per function and 32768 total; AST depth to 128; CFG blocks to 4096 and elements
to 16384 per function. Native observation has a 30 s timeout and 64 MiB combined
stdout/stderr cap. Budget bootstrap reads at most 4097 bytes and rejects files
larger than 4096 bytes or lexical nesting above eight before constructing the
canonical ledger. Subsequent capture, hashing and graph work charge that ledger.
For V represented vertices, E edges and S AST traversal seeds, graph verification
takes O(V+E+S log(S+1)) work and O(V+E) storage, plus source/input hashing and
bounded schema/string processing; no complexity bound on Clang parsing or CFG
construction is inferred. Compiler memory and the OS scheduler are external to
the logical budget.

| Assumption | Falsification probe | Observed boundary |
| --- | --- | --- |
| SE1: actual pinned compiler/configuration and captured input custody | Rehash genuine build inputs and source/schema/binary before and after; mutate inputs; reject headers | Unsigned local provenance, not full OS/SDK/shared-library attestation |
| SE2: IDs are original local canonical declarations | Overloads, shadows, forward declarations, parent and nullable-coordinate cases | Equal names/offsets never join identities |
| SE3: observations confer no object/lifetime authority | Actual EH gap and I-C27 trait counter | Source/IR witnesses remain separate from runtime proof |
| SE4: graph relations preserve actual compiler representation | Wrong callee kind, nonreciprocal and parallel edges, AST cycles | No edge reason or complete cleanup relation is inferred |
| SE5: bounded failures return no report | Exhaust budgets; malformed/duplicate/deep inputs; source/native drift; unsupported forms; actual -O guards | Unsupported input fails explicitly; no fallback execution |

High-impact remaining work is full source-language lifetime/EH grounding and the
original verifier/runtime protocol that can authorize it. Medium-impact limits
are the finite main-file profile and external compiler resource use. Low-impact
inspection strings remain display data. No compiler-freeze, backend, guest-body,
JIT or host-platform qualification follows from these tests.

The frozen `native-control-r6.reference.json` and its provenance describe an actual
historical native/reference observation for pure wire/graph tests. Their hashes
are evidence of those bytes, not an issuer of current native or runtime facts.
