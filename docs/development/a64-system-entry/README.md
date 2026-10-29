# AArch64 public system entry and observation publication

`AArch64Cpu::step_system` and `step_system_with_fault_exit` attempt at most one
original instruction. A hot native instruction returns through the bounded
entry described in [bounded native execution](../a64-bounded-native/README.md).
They poll the existing interrupt/timer state on each attempt. A public call
cannot enter an ordinary multi-instruction region or run a newly promoted loop
after retiring an interpreted backedge.

The software adapter shares one entry-selection and retirement-publication
helper between `VCpu::run` and instruction stepping. A system batch permits at
most 65,536 attempts; an exit can return earlier. Waits, exceptions and other
nonretiring transitions need not consume a retirement, so attempts and retired
instructions are different quantities. Access recording selects interpretation
to preserve the existing fetch/data observation stream.

## Observation and checkpoint contract

The private CPU instruction count and the adapter observation count are saved
separately. An accepted context can retain an offset between them. Each system
attempt reads the private count before execution and adds its retirement delta
to the adapter count before mapping an exit, handling firmware, or returning an
error. Both subtraction and atomic addition use arithmetic modulo 2^64:

```text
delta = private_after - private_before (mod 2^64)
observed_after = observed_before + delta (mod 2^64)
```

This preserves restored observation phase and publishes instructions completed
before shutdown. It does not add a wire field, change the C ABI, or serialize a
native cache. The private AArch64 context remains `RAXA6403`; caches remain
derived state and are reconstructed after restoration.

The legacy multi-instruction compiler and generic region runner are compiled
only into library tests. Existing lowering tests can invoke those helpers
explicitly; ordinary production system entry cannot. The existing EL0 PAuth
path calls its checked single-instruction executor directly.
The existing [EL0 embedder regression](../../../src/backend/emulator/aarch64_user_tests.rs),
`pauth_user_native_frontier_preserves_single_step_memory_recording`, requires
one actual native entry after recording is disabled and verifies exact fetch
records while recording is enabled. The complete library run covers this caller.

## Evidence and reproduction

The group receipts are retained at
`/Users/int/dev/rax-audit-work/four-findings-aarch64-cluster/a64-system-entry`.
`preflight-v1.json` records the parent source hashes, owned paths and change
planes. `parent-negative-v1.json` records five tests executed against the parent
production bodies: zero passed and five failed. The fixtures cover an injected
legacy region, every hot loop frontier and attempt tick, early shutdown, the
full batch attempt limit, and a restored observation offset including wrap.
The baseline source archive and failure output are retained unchanged.
An additional negative control disables only the candidate's recording-selection
branch, reproducing the parent batch route's omission while retaining the other
repairs. Its test requires a hot load followed by shutdown to produce exactly
two fetch records and one data-read record without entering native code.
`recording-negative-source-v1.json` and its archive identify this deliberate
reversal; it is not labeled as an unmodified parent revision.

The physical AArch64 comparison reuses the separate C/assembly executable and
the 1,536 original-instruction samples committed with bounded native execution.
Its provenance and finite-sample limits remain as recorded there. The adapter
comparison must enter native code for each final sampled instruction; equality
obtained solely by interpretation cannot satisfy it. This group changes the
public entry route used by that comparison, not the captured native expectations.

For a focused run from the repository root, set an explicit disposable Cargo
target directory and scratch directory, then run:

```sh
cargo +stable test --locked --offline --lib --no-default-features \
  --features x86_64-suite,smir-jit,hvf ::system_entry \
  -- --test-threads=1 --nocapture
```

Final acceptance also requires the complete owning library and integration
binaries, C API checks, workspace build/Clippy/format, interpreter-only and
x86-64 compile checks, verified frozen sources, an exact-path commit, and idle
build-directory cleanup. A focused pass alone is not completion evidence.

## Assumption register and remaining boundaries

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| SE1 | A public system step attempts at most one original instruction; native entry must preserve that boundary. | Inject a runnable legacy loop; check every hot frontier, attempt tick and batch limit. Any additional instruction inside one call falsifies it. | Confirmed within the recorded public-entry, batch and clock matrix. |
| SE2 | Separately saved private and observation counts can retain a valid offset. | Restore unequal counts, execute one instruction, and test observation wrap. Replacing the offset or reporting more than one retirement falsifies it. | Confirmed within the recorded restored-phase and wrap cases. |

High impact: hardware and other-ISA native entry, complete private/in-flight
state, external-writer quiescence, late host-failure rollback, full event/wait
profiles, and physical Intel HVF validation remain open. This publication helper
does not establish a transaction spanning device effects and host failures.
The original observation-counter fixture did not qualify private-counter
overflow in cold interpreter paths. The subsequent
[private-counter repair](../a64-retirement-counters/README.md) covers that
separate boundary through actual restored records and both arithmetic profiles.
Medium impact: instruction-sized native execution retains dispatcher overhead;
there is no throughput claim. Lookup and publication use expected O(1) time and
O(1) auxiliary space per attempt; the existing cache cap bounds retained entries.

All four full findings, A32-FP, C-STATE, C-SMP and C-HVF, remain incomplete.

Original system-entry qualified source: 11,263 library tests passed with two ignored;
47,694 integration tests passed across 22 complete binaries; 223 C API tests
passed. Workspace Clippy/build/format, interpreter-only and x86-64 compile
checks, frozen-source checks and the recorded targeted matrix passed. Doctests
ran zero cases with five ignored. Physical Intel runtime validation did not run.
