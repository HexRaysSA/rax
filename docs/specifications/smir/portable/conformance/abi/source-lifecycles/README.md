# Strict portable source lifecycle association witnesses

These are source-authored static compiler-contract fixtures, not emitted/native
C++ execution evidence. Each JSON holds original decoded v3 sections, the exact
embedded/external source carrier, and an expected association or rejection.

From the repository root:

```sh
PYTHONPATH=tools/smir-abi:tools/smir-format/execution:tools/smir-runtime-contract:tools/smir-format python3 -B -m unittest record_layout.test_source_lifecycles record_layout.test_source_program_cost -v
PYTHONPATH=tools/smir-abi:tools/smir-format/execution:tools/smir-runtime-contract:tools/smir-format python3 -B -O -m unittest record_layout.test_source_lifecycles record_layout.test_source_program_cost -v
```

The suite actually encodes/decodes all ten fixtures and checks original owner,
ABI, body, source records and full embedded carrier using one original canonical
SourceQueryBudget. Five positives cover C1/C2/D0/D1/D2 with no bases or VTT;
five saved negatives cover wrong access/role/this SSA/selector/external carrier.
Additional tests cover stale owner/wrong ledger, profile rejection, exact quotas,
one-less/zero before real factories, closed token/B/key guards and separate
referenced prototype costs. No tests infer origin from equal integers.

The fixed flat_lifecycle_v1 profile requires original revision3 (revision2
rejects before factories), SELF/direct scalar members, bounded tables/geometry,
no bases/arrays/implicit/progress/AST expansion. Those richer inputs are explicit
unavailable boundaries. Records<=4, methods/programs/cleanups<=8, slots<=8,
method parameters<=16, program steps/cell maps<=8, links/physical scopes<=4;
source tables<=256. Input depth<=64/nodes<=16384, text and keys<=256 characters,
ASCII upper bound<=1MiB; object geometry<=4096octets/32768bits. The schema does
not by itself prove these semantic conditions or admit execution.

Root accepted the complete finite route's logical work/edge/payload-copy schedule
after independent source review and normal/optimized tests. Successful strict
results report cost_profile_qualified=true; this descriptive marker is not an
issuer, permit or independently trusted admission fact. The carrier class can be
constructed by callers: consumers must retain original verification/context
checks and must never use this marker as authority. All source/runtime/executable/
active-v3 flags remain false. The remaining obligations cover source-body legality,
CFG/publication/EH, incoming runtime tickets, source semantic admission and VTT
contents. No full C++/foreign compatibility, runtime/JIT/parallel/host qualification
or compiler freeze follows.

Assumptions: canonical dependencies retain their inspected source identities;
profile guards run before excluded expansions; every stage uses the same B;
actual source-expression/native/copy charging is separate from CPU time/RSS;
old cost_profile=None SourcePrograms behavior and exact counters remain unchanged.
Stress probes include forged token/foreign B, long keys before JSON, prototype
stages, v2 before factories, initial base-walk allocation, boundary geometry and
actual original-v3 mutation. Source changes require renewed scoped qualification;
old receipts and fixture observations remain as-run, never silently repinned.
