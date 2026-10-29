# A64 profile allocation before FP access

The represented A64 CPU profile now rejects unallocated FP/SIMD encodings before
checking execution-time FP access. Reserved encodings previously reported an FP
access trap when FP was disabled; some also reached execution or an implementation
frontier with FP enabled. The new check also rejects original words before native
optimization can remove their source-PC carrier.

This is a profile-scoped execution rule. The neutral stateless decoder has no
selected-profile argument and retains its original source bytes. Newer encodings
accepted by QEMU `max` are not claimed to be permanently unallocated. The selected
base profile cannot represent all of those extensions.

## Derivation and authoritative sources

`tools/execution/a64_fpsimd_allocation.py` parses 562 encoding descriptions from
the pinned Arm ASL, including repeated shared encodings. Backward slicing retains
only assignments and branches reaching `UNDEFINED` or an encoding redirect.
Unknown dependent constructs and runtime-dependent conditions stop generation.
All original guards are TRUE; no unpredictable directives occur in this subset.
Feature predicates are true during structural derivation. Selected feature and
version policy is enforced separately.

Every assignment of every dependent instruction bit is enumerated: 73,718
assignments, with at most 14 variable bits per description. Exact cube merging is
checked exhaustively against those assignments. The resulting 510 primary cubes
are supplemented by 13 separately qualified BF16/I8MM diagrams. Other optional
feature diagrams do not reintroduce broader reserved forms into the primary table.
The generated result has 523 distinct cubes, 1,886 bucket entries and at most 21
entries per bucket.

The older ASL scalar-conversion decode admits extra FJCVTZS variants. The existing
scalar-conversion refinement is retained in the new allocation module and agrees
with Arm DDI0602 ID032025: FJCVTZS fixes the source to D, destination to W and its
opcode. The complete unchanged March 2025 primary reference, checksum, source URL
and relevant page numbers are retained under `primary/`.

The already implemented indexed FP8 FMLALB/FMLALT class is an explicit newer
structural supplement. Its existing RAX V9_4A selection policy now precedes FP
access and native optimization. This is RAX selection policy, not a claim that
every Arm v9.4 CPU implements FEAT_FP8FMA. The current primary bit diagram and 32
independent LLVM MC encodings qualify its operand-field allocation.

## Validation and reproducibility

The actual parent `bedb938f54006cd8a84a43a065ca31f533badf71` failed both initial
regressions on the original 4,144-word independent corpus. That observation is not
represented as a parent run over the later expanded corpus.

The frozen successor corpus contains 26,978 words: the complete sliced primary
field assignments, the qualified newer neighborhoods and seeded free-operand
variations. QEMU 11.1.2 ran 161,868 events across Cortex-A53, Cortex-A76 and
Cortex-A710 at EL0/EL1 with FPEN=0. The represented Cortex-A710 comparison matches
all 53,956 reference events. Both direct RAX execution and a real bare-metal
exception-handler kernel match those events. The kernel checks saved mode, fault
ELR, syndrome and an X0 sentinel. These are independent emulator comparisons,
not physical Arm execution.

Six new CPU tests cover the expanded corpus, complete private checkpoints in the
tested flat-memory states, repeated faults at saturated counters, replacement
execution exactly once, original-word native requirements before optimization,
22 newer-profile boundaries, and the preserved indexed-FP8 version/access policy.
The FP8 execution controls use zero operands and do not qualify general arithmetic.
Eight Python tests cover reaching assignments, unknown/runtime dependencies,
uninitialized variables, redirects, uncovered cases, irrelevant runtime values
and exact cube merging. Parser-driven regeneration reproduces every output.

Exact commands, frozen sources, raw oracle output, parent failures and terminal
process receipts are retained in
`/Users/int/dev/rax-audit-work/four-findings-aarch64-private-state/a64-fpsimd-allocation/`.
The initial full-library run exposed the missing existing FP8 supplement and the
old scalar-SDOT direct-result expectation. Both failures and corrections remain
recorded; they are not converted into successful runs by retrying unchanged code.

Build the standalone ASL parser with its `serde` feature and an explicit task
cache, then check the generated outputs. Use the toolchain and offline dependency
set recorded in the qualification environment when reproducing that exact run:

```sh
RAX_AUDIT_TARGET=/absolute/path/to/task-cache
CARGO_TARGET_DIR="$RAX_AUDIT_TARGET" CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
    cargo +stable build --locked --offline \
    --manifest-path tools/asl-parser/asl-parser-rs/Cargo.toml --features serde
python3 -B tools/execution/a64_fpsimd_allocation.py --parser "$RAX_AUDIT_TARGET/debug/asl-parser"
python3 -B tools/execution/a64_fpsimd_allocation_tests.py
python3 -B tools/execution/a64_fpsimd_oracle.py \
    --work-dir "$RAX_AUDIT_TARGET/fpsimd-oracle" \
    --llvm-bin /path/to/llvm/bin \
    --qemu /path/to/qemu-system-aarch64
```

The replay tool consumes frozen input words, retains raw outputs and binaries,
and never changes checked-in expected events. It checks Cortex-A710 against the
frozen events and captures older models separately. The `--ast` generator option
accepts only the checksum-pinned qualified intermediate; final qualification also
uses the current parser executable.

Final frozen-source qualification: 11,241 library tests passed, 2 ignored; 47,694 cases
passed across 22 complete owning integration targets; 223 C API tests passed; and 4
profile tests passed in the x86-64 interpreter build under Rosetta. Formatting,
workspace all-target Clippy/build, interpreter-only compilation and whitespace checks
passed. Documentation: 0 passed, 5 ignored. These results do not establish physical
Intel HVF or physical A32 execution.

## Assumption register and bounded scope

| ID | Assumption / dependency | Stress test and falsification probe | Status |
|---|---|---|---|
| FA1 | Pinned legacy ASL plus explicitly qualified supplements define allocation within the represented profile domains. | Exhaustive dependent-field enumeration and independent full-corpus QEMU comparisons; an allocated reference word rejected in that domain falsifies admission. | Confirmed within the recorded source/profile/finite corpus; newer full profiles remain outside it. |
| FA2 | Decode rejection depends on instruction bits, not architectural runtime data. | Backward slicing fails on dependent unknown/runtime inputs; every retained field assignment executes the sliced program. | Confirmed for all 562 primary descriptions. |
| FA3 | Preserve the existing indexed-FP8 RAX selection policy at V9_4A and later. | Version boundary, EL0/1, FPEN, Q/register/index boundaries and original-word native rejection. | Confirmed as existing RAX policy; not full architectural FP8 qualification. |

For fixed tables, lookup is O(1), with at most 21 generated mask comparisons plus
explicit refinement/profile checks. The generated arrays contain
4097 × 2 + 1886 × 8 = 23,282 bytes of element storage, excluding alignment and compiler
metadata. Derivation is exponential in the number of relevant bits: this source
is bounded at 14. Cube compression remains a generation-time operation; no ASL
program is interpreted on the guest execution path.

**High impact:** older-model comparisons retain 286 A53 and 166 A76 differences per
EL and execution path. They map exactly to 120 RDM and 166 SHA-512/SHA3/SM3/SM4
words. Only the eight selected FP feature controls were projected onto RAX in
those comparisons; other advertised defaults differ. These expose remaining
profile/selection coverage and are not presented as pure structural failures or
as proof of whole-CPU identity.

**High impact:** the retained indexed-FP8 executor has unresolved source-register
and element-index interpretation, fixed-format/scaling behavior, intermediate
rounding and FPMR support. `fp8-policy.json` records these separately. This group
preserves existing admission; it does not close FP8 data/state semantics.

**High impact:** complete A32/SVE/SME/security/debug profiles, backend/in-flight
checkpoint state, bounded SMP native execution, replay/debug coordination and
physical Intel HVF validation remain open. All four complete audit findings stay
partially validated.

**Medium impact:** five documentation examples remain ignored where reported;
physical Intel/A32 execution is not established by Apple Silicon or Rosetta tests.

No C ABI, private-record layout or wire version changes. The 62 earlier Undefined
samples now fail at decode admission with `Err(UndefinedInstruction)` rather than
reaching the old `CpuExit::Undefined` result. Their non-retirement, diagnostic,
normal-delivery and retained legacy-context invariants remain tested. Original
checkout files and running guests are preserved. The task build cache is deleted
after the exact owned-path commit.
