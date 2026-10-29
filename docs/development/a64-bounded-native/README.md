# AArch64 native execution at scheduler instruction boundaries

The software AArch64 adapter admits hot instructions through a separate native
cache when the scheduler calls `run_retirement_budget`. Each compiled entry
contains one original instruction. Every branch target, including a self-branch,
is a dispatcher exit stub. Native execution therefore returns before a second
guest instruction, timer poll, interrupt check, or platform request can be skipped.

This extends the existing software multi-CPU scheduler. It does not complete
C-SMP, C-STATE, A32-FP, or C-HVF. Public software system entry and finite batch
publication are covered by the subsequent
[system-entry repair](../a64-system-entry/README.md). Hardware virtualization entries, other guest ISA
native tiers, additional startup profiles, debugger AP selection, full replay,
external-writer quiescence, and physical Intel HVF validation remain separate
requirements.

## Instruction and fault contract

- Bounded and legacy region entries use distinct cache keys. The memory policy
  is also part of the key, alongside the existing mode and FP capability fields.
- Strict lifting, original-word FP requirements, existing native clobber gates,
  and code-byte/mapping revalidation precede entry. PAuth retains its existing
  checked single-instruction helper path. Unsupported native forms remain at
  the interpreter frontier; no guest-controlled address becomes a host branch.
- Original-word admission keeps WFE/WFI, timed waits, SEV/SEVL, and CLREX at
  the CPU interpreter boundary in both native tiers. Generic NOP or register
  state cannot replace their modeled wait, event, or local-monitor effects.
- Optimization sees only one source instruction. A dead operation cannot erase
  the original word's feature/access requirement or its successful retirement.
- Success publishes the native register image, advances instruction and cycle
  counts once, clears ordinary BTYPE, and records the attempted guest PC.
- A memory-helper failure captures its actual `ArmError`. The failed native
  register image is discarded, while completed memory effects remain. The
  instruction retires zero times and its access is not replayed by interpretation.
- Pair operations remain outside the existing AArch64 native helper gate.
  Admission rejects them before effects; their interpreter fallback preserves
  pair-load destinations on a second-access abort and retains a completed first
  pair store exactly once. This is fallback coverage, not native pair execution.
- Private context capture rejects an active bounded native instruction. Its
  host register image and synchronous callback are not serializable state.
- The owning system step still polls timers and interrupts before entry. The
  retirement clock is published by the existing budget wrapper exactly once.
- Explicit access recording selects interpretation because compilation and
  source checks perform extra fetches. Disabling recording permits cached native
  entry again. This preserves the existing access-observation contract.

The pair-access rule is independently specified in the pinned
[Arm ASL source](../../architecture/arm/asl/arm_instrs.asl),
`aarch64_memory_pair_general_post_idx`: its load sequence reads both operands
before destination assignment; its store sequence writes the first operand
before attempting the second. The original source checksum is
`3c91ece6d0509f7ce9e8b2d8fa623787d7c7acb4cb24040a75cec5aa2789e611`.
The fault fixtures observe access order and abort the second access; they do
not infer an architectural abort syndrome from a generic callback failure.
The same pinned source, `aarch64_system_hints`, distinguishes event consumption,
waiting, `SendEvent`, and `SendEventLocal`. This repair preserves current CPU
effects; it does not qualify every architectural wait trap or cross-PE event
broadcast profile.

Cache lookup is expected O(1). Each native entry has O(1) instruction work and
auxiliary storage, apart from the instruction's memory translation/access.
Cold compilation and cache admission remain bounded by a single source word.
There is no native throughput claim.

## Independent physical AArch64 fixture

`oracle.c` and `oracle.S` execute original instructions without RAX. The retained
capture contains 1,536 samples: 16 encodings, six integer operand partitions,
and all 16 NZCV inputs. Each sample executes its original instruction 128 times
on an Apple M4 Max, for 196,608 original instruction executions. The assembly
preserves the host FP control/status state and records X0-X3, NZCV, the selected
guest branch destination, V0-V1, FPCR, and FPSR.

RAX runs 254 retired instructions of the corresponding instruction/return loop,
then one final sampled instruction: 128 sampled instructions and 127 return
branches. The final instruction must increment the native-entry observation
counter; interpreter-only equality cannot satisfy that assertion. The 503,619-byte
capture is experimental evidence, not a generated expectation from RAX.

From the repository root, choose an explicit disposable output directory:

```sh
oracle_dir=/absolute/path/to/disposable-oracle-output
mkdir -p "$oracle_dir"
/usr/bin/clang -arch arm64 -O2 -Wall -Wextra -Werror \
  docs/development/a64-bounded-native/oracle.c \
  docs/development/a64-bounded-native/oracle.S \
  -o "$oracle_dir/oracle"
"$oracle_dir/oracle" > "$oracle_dir/native-vectors.json"
if cmp "$oracle_dir/native-vectors.json" \
  docs/development/a64-bounded-native/native-vectors.json; then
  rm "$oracle_dir/oracle" "$oracle_dir/native-vectors.json"
  rmdir "$oracle_dir"
fi
```

The command requires physical AArch64 macOS. It does not qualify Intel HVF,
AArch32 hardware, arbitrary FP inputs, all admitted native instructions, or
concurrent code modification. `provenance.json` records the observed host,
compiler, original artifact names, checksums, and executed sample count.

## Validation

The semantic group's external execution receipts are retained under
`/Users/int/dev/rax-audit-work/four-findings-aarch64-cluster/a64-bounded-native`.
Final acceptance requires a parent-negative run, complete owning library and
integration binaries, C API coverage, workspace build/Clippy/format gates,
source-hash verification, an exact-path commit, and idle-cache cleanup. Preview
results alone do not satisfy these gates.
The original parent failed the native-entry and PAuth counter-wrap regressions.
The additional pre-guard control tests observed legacy native acceptance of
WFE and SEV. Early pair-native tests failed because the existing gate declines
those forms; they are not evidence of executed native pair operations.

The targeted matrix covers one-instruction and zero budgets, infinite guest
self-branches, both conditional edges, native load faults, pair access faults,
tier policy changes, exact access recording, code replacement, attempt clocks,
and private checkpoint reconstruction. Pair faults qualify interpreter fallback;
the pre-indexed scalar-load fault qualifies actual native register rollback and
the captured access count. The actual VMM test uses two and four
online CPUs, verifies equal retirement quanta and nonzero native entries on each,
saves a file checkpoint, restores cold native caches, and compares subsequent
architectural state and coordinator state against uninterrupted execution.

## Assumption register and remaining scope

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| BN1 | One source instruction with only dispatcher exit edges satisfies the coordinator's budget-1 contract. | A self-branch, both conditional edges, and 2/4-CPU quanta; any second retirement inside one entry falsifies it. | Covered by the recorded targeted matrix; full qualification receipt controls acceptance. |
| BN2 | Native memory callbacks identify failures without requiring a repeated access. | A second pair access aborts; register changes, repeated callbacks, or a lost first store falsify it. | Covered by the pair-fault matrix; initial candidate failures remain retained. |
| BN3 | The physical fixture executes the supplied original encodings independently of RAX. | Rebuild the C/assembly fixture and compare its nonempty capture and checksums. | Observed on the recorded Apple Silicon host; finite sample only. |
| BN4 | Stateful system words must retain CPU-owned effects even if their lift is NOP-shaped. | Hot wait/event instructions, both WFE event states, and original-word rejection before O2; native NOP admission falsifies it. | A pre-guard failure is retained; the final qualification receipt controls acceptance. |

High impact: hardware entries, complete private/in-flight rollback,
all-writer quiescence, other startup profiles, full replay, and physical Intel
validation remain open. The cache revalidates source bytes before each entry;
this is not an atomic exclusion protocol against concurrent external writers.
Medium impact: instruction-sized native entries retain dispatcher overhead and
do not establish a throughput improvement. No additional worktrees or per-test
Cargo target directories are required.

Original bounded-entry qualified source: 11,257 library tests passed with two ignored; 47,694
integration tests passed across 22 complete binaries; 223 C API tests passed.
The 16 targeted tests passed. Workspace Clippy/build/format, interpreter-only
and x86-64 cross-compilation, and source checks passed. Doctests ran zero
cases with five ignored. Physical Intel runtime validation did not run.

The subsequent [software event repair](../a64-events/README.md) implements the
cluster SEV/SEVL distinction and conditional A32 event effects at this existing
interpreter frontier. Its typed native PAuth merge preserves an event arriving
during a memory helper; event instructions themselves remain outside native
admission. The broader wait/trap and physical-hardware boundaries remain open.
