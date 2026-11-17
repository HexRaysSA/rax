# LLVM contract witnesses

No compiler backend, production verifier or runtime admission is implemented here.
Use Python3.11+; dependencies are standard library only. LLVM sources and explicit
tools are external read-only inputs. No packages are installed.

```sh
SMIR_LLVM_ROOT=/Users/int/dev/llvm-project \
  python3 -B -m unittest discover -s tools/smir-llvm-contract -p 'test_*.py' -v
python3 -B tools/smir-llvm-contract/inventory.py \
  --llvm /Users/int/dev/llvm-project
```

The first command runs mathematical/reference and external compiler witnesses.
The second regenerates in memory and compares twelve generated contracts/matrices/manifests;
`--write` updates only the LLVM-owned outputs in portable/llvm/. Set
`SMIR_LLVM_BIN` or `--tblgen` for explicit binary selection. Use an isolated
`TMPDIR` when running alongside other roles. Missing tools fail; no self-skips.

- policy.py assigns every source opcode a deliberate lowering/diagnostic rule.
- inventory.py expands TableGen and hashes actual dependencies, reads source
  status tables, and generates reproducible matrices. It never edits LLVM.
- reference.py is an independent integer refinement/DataLayout subset model.
- gate.py validates exact request metadata and rejects every emission attempt.
- test_contract.py compares model/known fixtures and actual LLVM/Clang outputs.
- contracts.py/frontend_contract.py specify required lowering and compiler choices.
- bindings.py checks actual candidate core names, helper signatures and the exact
  domain-separated all-fields catalog identity; file SHA256 remains separate.
- canonical.py/deployment.py model alpha-normalized COMDAT/content/SCC binding.
- candidate_projection.py projects actual admitted execution/EH/type roots;
  projection_witness.py and test_projection.py verify actual SEM records before
  checking alpha renaming and independent runtime comparison bytes. Cross-root
  identity callbacks still require actual whole-module admission.
- eh_slots.py validates the compiler-private exception-slot logical schema and
  supplies a bounded independent pruned-SSA oracle; exact grammar/quota contract
  is portable/llvm/eh-slot-contract.json. Actual LLVM before/after and nested
  landingpad witnesses execute no guest and implement no production compiler pass.
- pointer_contract.py/fp_contract.py supply independent mathematical witnesses.
- constant_contract.py exhaustively audits actual retained ConstantExpr opcodes and
  all Constant ValueIDs; global_initializers.py generates160 header-free source
  compilation witnesses across language/architecture/optimization/LTO modes.
- coroutine_contract.py/test_coroutines.py check exact pinned pass ordering,
  frame/promise geometry, allocation policy and opaque suspension liveness.
  Compiler-private allocation policy is explicit P2014 aligned mode; ordinary
  partial-aggregate current-child adoption uses the published typed Builder protocol.
- shape.py uses bounded pair-elimination to independently check execution type
  identity against the semantic verifier's partition-refinement implementation.
- witness_ir.py generates LLVM-only full-width power expansions before optimization;
  test_closure.py covers source gaps, finite native host probes and joint bindings.
- termination_witness.py records controlled native host implicit-catch/count
  observations, explicit SDK header hashes and compiler identity; no pinned runtime
  or SMIR qualification follows from that host probe.
- life_markers.py validates the exact private LLVM051 schema/actual source facts;
  life_marker_witness.py checks actual pinned optimization/coroutine retention,
  typed capture freezing, same-Value source views and runtime Builder stability.
- validate.py records tool/artifact/input hashes before/after the focused suite;
  dependency drift invalidates a receipt even if individual tests pass.
- record_layout/ supplies an isolated actual Clang AST-library source witness;
  run its separate discovery command in that directory's README. It extracts
  INT030 source facts and raw existing-target layout/vtable metadata, with
  explicit unbound runtime symbols. It is not a general nominal producer or
  SMIR TargetInfo; actual lambda capture names follow accepted LLVM-PROD009REV2,
  while other unsupported implicit ordinary field names reject.

The bootstrap opt executable may differ from the source pin; it is a subset
oracle, and the exact binary version/hash belongs in each receipt. Clang's
reported commit must match the source pin for frontend tests. Frontend fixtures
use x86_64-unknown-linux-gnu with -mlong-double-128, freestanding/no headers.
Their native ABI coercions are observed evidence and cannot be emitted as the
portable calling convention. The absent smir64 frontend is tested as a rejection.

Stage W source function-address witnesses in record_layout/test_fnaddr.py add
actual pinned source/static-assertion/AST/IR observations to the combined receipt.
They distinguish an address-only native void() placeholder from a completed call
ABI and retain O0/O1 character transport evidence. They do not implement S016,
LLVM program address spaces, pointer provenance, a successful legacy reader or
portable execution. The complete validate.py command registers this directory
and guards actual owned/consumed source hashes before and after all tests.

The candidate DataLayout is independent of host ABI. The layout oracle asserts
that opt preserves it. The source ABI BitInt storage exception needs explicit
alignment/padding; plain i65 field geometry is deliberately different. The
mathematical model chooses one undef/freeze refinement, not all legal choices.

See portable/llvm/{integration,frontend,refinement,assumptions}.md for exact scope,
interfaces, primary provenance and external qualification boundaries. Passing this local
suite does not execute SMIR or qualify hosted/foreign/native runtime behavior.
Native host execution is limited to the explicitly described LLVM-only power
and actual-source controlled-primitives witnesses. Historical28-test receipts
are superseded when current owned artifacts or shared candidate inputs change.
