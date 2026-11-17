# Execution source-role conformance

Accepted INT032/ABI-PROD030REV6 gives exact source meanings for17 helper names/19
contracts. R008REV2 supplies snapshot-checked original SELF/DEP expectation
callbacks. ABI034REV2 supplies unsealed declaration fragments; callers merge,
seal actual V2 definitions, then run actual verification.

From repository root:

```
python3 -B tools/smir-format/execution/source_roles/generate.py
python3 -B tools/smir-format/execution/source_roles/test_graphs.py
python3 -B -O tools/smir-format/execution/source_roles/test_graphs.py
python3 -B tools/smir-format/execution/source_roles/check.py --receipt /tmp/rax-portable-smir-01/SEMANTICS/source-role-check.json
```

The generator writes only execution/candidate/source-roles:55 complete objects
and cases.json,26 positive/29 source-negative. Every generated source graph is
checked by the real ABI reference verifier before encoding. Imports remain
unused; code is not executed. `check.py` invokes the actual combined ten-root
CLI. A negative passes only with its exact assigned source-semantic diagnostic;
Wire/resource/unavailable-evidence outcomes cannot satisfy it. It returns nonzero
for any differing outcome or source-input drift. Receipt contains commands,
stdout/stderr, interpreter identity and before/after input hashes.

Ten unittest methods exercise actual graph/ABI/execution verification, independent
versus released ABI-builder source fingerprints at portable domain19, alpha
renaming in three namespaces, original DEP integer collisions, topcv versus
pointee cv, isolated returned layouts, ABI-stage/snapshot rechecks, missing source
callbacks and known wrong-kind priority. Callback omission tests retain actual
ABI-verified roots; they do not construct successful production facts.

sem_fixtures.py independently declares reserved c23 VA/jump records/array-one
wrappers, flag and portable reference cells. It is a fixture producer, not AST
recovery. Reserved normalization does not relabel ordinary C++ records. Source
fingerprints do not prove provider selection, live object ownership or registry
associations. ABI034 differential use runs its pure builder in an isolated process
and seals the actual merged graph; unsealed fragments are rejected.

The fixed builtin fragment builder is O(1) space/work; alpha-renaming test is
O(types+layouts+edges). CLI comparison work is55 independent bounded verifications
plus O(total tracked input bytes) hashing; no performance qualification follows.
Current production Rust ABI record/array proof profile is closed, so valid
canonical operation fixtures can still return UnavailableEvidence before the
SEM phase. This is a production coverage gap, not a source-negative expectation.
No guest/native/parallel/JIT/library/unwinder execution is established here.

## Declared source-data reference API

S-PROD014REV2 exposes explicit `RootContext.prepare_source_data(budget=...)` and
`source_data(symbol, offset, length, budget=...)` before ABI verification. One
caller-created cumulative `SourceQueryBudget` is retained for that context;
preparation is optional and adds no eager work for existing non-CPP consumers.
`source_stamp` is read-only. Actual active grammar and all actual present roots
are rehashed under the same budget before each query and bounded read. Canonical
bytes and frozen records come from the same grammar walk.

Run the composed tests from `tools/smir-format/execution`:

```
python3 -B -m unittest test_candidate_source_data -v
python3 -O -B -m unittest test_candidate_source_data -v
```

Tests decode the actual Rust INT023 metadata fixture bytes and compare source
symbol/storage/range/alignment, initialized prefix plus symbolic zero tail, full
original leaf/constant records and absolute patch intervals. Dependency results
retain the original consumer declaration/owner and have no provider bytes.
Local queries require whole-backing fully-defined readonly storage and actual
root5, including for tiny slices. Direct defined weak/COMDAT is a declared input,
not a selected winner. Constants remain unexecuted; returned bytes are raw.

Quota work includes actual canonical encoding/hashing, schema file parsing,
field traversal and backing/patch scans. Schema JSON allocations use conservative
source-byte bounds before parsing; depth is scanned before tree allocation.
Initialized hex is processed in bounded chunks; a huge zero tail remains symbolic.
Immutable cache reuse avoids duplicate frozen records, never snapshot validation.
Concurrent mutation of the Python reference context is unsupported. This API
issues no production facts, relocation/native proof or execution authority.
