# Draft scalar Raw8 atomic reference witnesses

This package implements the scalar Raw8 exchange predicate in the Python and
independent Rust static checkers. It exercises the existing sequential Python
Machine and real guarded guest memory. ABI-SOURCE-BYTE-TRANSPORT-01 plus mandatory
02/03/04 defines the reviewed draft semantics; this package is not a source ABI
epoch2 compiler, source-expression admission or production parallel runtime.

The existing ordered `atomic_rmw` record remains unchanged. Only the additional
exchange predicate `storage.type == scalar Raw8` is admitted. A vector of Raw8,
including elementwise mode, and every other raw width remain rejected. Existing
integer, floating-point, pointer and integer-vector exchange behavior remains.
Raw add/sub/and/or/xor remains rejected; its numeric physical view is Int8.

`cases.json` has 67 independently authored execution-local cases: 48 positives
and 19 rejections. Five Raw8 exchange orders, all 15 independently selected CAS
success/failure pairs in both weak and strong forms, eight existing exchange
category controls, and five numeric Int8 views are positive. Invalid widths,
Raw8 vectors, Raw8 numeric actions and invalid order members reject. Generic CAS
success is relaxed/acquire/release/acq_rel/seq_cst and failure is independently
relaxed/acquire/seq_cst. The obsolete failure-not-stronger restriction is absent.
The existing Machine chooses no spurious weak failure, an allowed refinement.

Each case includes independently decoded full ordered object bytes so the Rust
checker can consume the same authored data without a Python predicate result.
Only execution types/layouts/body are claimed by this corpus. The enclosing
ABI/site/source tables are framing input and do not imply whole-object admission.
The 775169-octet JSON repeats that framing and hexadecimal objects to keep each
case standalone; sizes, SHA-256 and canonical re-encoding are checked. No old
fixture corpus or expected outcome is rewritten by this producer.

From the repository root, with a fresh `PYTHONPYCACHEPREFIX` for each run:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/raw8-test-normal PYTHONPATH=tools/smir-format/execution python3 -B -m unittest test_candidate_atomic_bytes -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/raw8-test-optimized PYTHONPATH=tools/smir-format/execution python3 -B -O -m unittest test_candidate_atomic_bytes -v
python3 -B tools/smir-format/execution/atomic_bytes/generate.py --check
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/SEMANTICS/cargo-target cargo test --manifest-path crates/smir-portable/Cargo.toml --offline --locked --lib execution_tests::atomic_bytes -- --nocapture
```

Twelve Python methods exercise actual typed SSA verification and Machine bodies.
Exchange returns actual old fragments/masks and stores distinct desired state,
including equal bits with different actual guest allocation generations. Eight
real byte exchanges reconstruct one complete ordered pointer origin; mixing one
byte from another allocation defeats reconstruction. Ending the pointed-to
lifetime does not revive it through preserved bytes. CAS compares per-use
zero-refined numeric bits, returns the original old state and never borrows
expected origins for desired. Readonly, bounds, alignment, lifetime and restricted
range faults occur before an observable atomic read or update in these tests.

Numeric witnesses use an actual original full module, ABI and body verification
under the existing site. The source nominal is Raw8 unsigned char; two separately
checked `object_bytes` bindings use Raw8 and Int8 physical layouts, each one octet
and alignment one. Numeric RMW selects the actual Int8 binding, observes the
argument numerically, and returns/stores originless values even for add0, and255
and other identity operations. Add/sub wrap modulo256 with no overflow-poison
flag. Reusing the raw binding for the Int8 layout or returning Raw8 directly
rejects. These witnesses validate the represented original ABI/storage join;
they do not prove a genuine new source-expression/category producer or that an
anonymous generic storage operation enforces the future source-byte projection.

Failure writeback is a separate ordinary store of returned old Raw8. Fuel
suspension after CAS preserves its old/success SSA results and PC, then resumes
the branch/store without repeating the atomic operation. Success does not write
expected, including an actual alias with the target. A fault at failure writeback
retains the committed atomic observation and old SSA result. The current Machine
has a terminal fault result and no fault-resume API; the test records that exact
limitation rather than clearing internal state and claiming successful retry.

Production gates remain open: actual parallel atomic bits/shadow commit,
precommit SAME-B data/span/output reservation, asynchronous safepoint/cancellation
and fault-resume protocols, source-byte compiler projection and private helper
extraction. Sequential value tests and static Rust checks do not qualify those
capabilities. No native guest, JIT, host matrix, full compiler freeze or runtime
admission follows. No Machine or memory implementation is changed here.

Assumptions and falsification probes:

- ATO1 existing Raw8 transport preserves actual fragments: distinct old/desired
  and expected allocations, masks, full-pointer reconstruction/mixed byte tests.
- ATO2 existing CAS uses the independent order sets and numeric comparison:
  all 30 weak/strong forms, invalid orders and per-use masks.
- ATO3 the numeric Int8 view is separate from source value shape: actual original
  ABI/body checks, exact binding joins, old/new/argument origin stripping and wrap.
- ATO4 completed effects retain their frontier: fuel stops, readonly failure
  writeback, old SSA/PC retention and explicit missing fault-resume boundary.
- ATO5 only the reviewed predicate changes: before-source Raw8 rejection control,
  unchanged legacy categories, independent Rust corpus, source/owned-path hashes.

High-impact unresolved production findings are atomic shadow partial commit,
resource failure after mutation, and replay across a resumable fault. Medium
findings are the missing source epoch2/AST/importer projection and exact metering.
Native execution, performance and host qualification are outside this package.

Primary oracles are the checked-in `candidate/raw.py`, `values.py`, `memory.py`,
`machine.py`, `operations.py`, the ABI storage binding verifier and the independent
Rust execution memory checker. Exact source and contract hashes, historical
failures, commands and observed results are recorded in the SEMANTICS run handoff;
successful fixture decoding alone is never executable admission.
