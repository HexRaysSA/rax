# A64 optional half-precision instruction admission

An A64 instruction requiring FEAT_FP16 now becomes Undefined when the selected
CPU profile lacks FP16. Decode rejection precedes FP access-control traps,
instruction retirement, and data effects. Previously `FADD H0,H1,H2` executed
with both advertised half-precision ID fields zero. The retained parent probe
observed one retirement and H0=0x4000 even though the feature was disabled.

Half register names alone do not identify an optional FP16 arithmetic
instruction. Legacy scalar precision conversions, vector widening/narrowing,
half storage, and integer vector operations remain admitted without FEAT_FP16.
Their ordinary FP access controls still apply. Reserved scalar conversion and
FP reduction fields reject before those controls, including when FP16 is
present. This preserves the Undefined syndrome and the original fault PC. The production default profile
is unchanged; positive semantic fixtures explicitly select their capabilities.

## Execution planes

| Plane | Change or boundary |
| --- | --- |
| Direct decode/execute | Reject absent FP16 and represented reserved fields before FP access and retirement |
| CPU state/checkpoints | Feature flags and IDs retain the existing layout; stopped-context fault and retry tests cover continuation |
| Memory/MMU and machine/devices | No translation, memory-helper or device implementation changes; rejection follows instruction fetch and precedes data effects |
| SMIR lift/IR/interpreter and static oracle | Abstract operations retain their existing stateless contract; CPU profile requirements come from original guest instruction PCs |
| Optimizer/native/JIT | CPU dependencies are collected before optimization and checked at build, lookup and entry; no new FP16 lowering support |
| Emulator backend and C API | Existing Undefined/stop behavior is exercised through saved contexts; no public ABI change |
| Hardware backends | No KVM/HVF implementation change or physical Intel execution claim |
| Tests/docs | Positive fixtures select FP16; the Linux-only whole native-reference suite remains unrun on macOS |

## Primary encoding coverage

[`a64_fp16_admission.py`](../../../tools/execution/a64_fp16_admission.py) derives
the table from the local Arm ASL instruction source
[`arm_instrs.asl`](../../architecture/arm/asl/arm_instrs.asl). Its upstream
revision is unknown; the exact pinned SHA-256 is
`3c91ece6d0509f7ce9e8b2d8fa623787d7c7acb4cb24040a75cec5aa2789e611`.
The generator rejects any other source hash or unrecognized predicate.

There are 64 distinct A64 encoding descriptions with explicit
`HaveFP16Ext()` requirements in this snapshot. They use four predicate shapes:
unconditional, scalar type=11, complex arithmetic size=01, and fixed-point
conversion immh=001x. [The corpus](encodings.json) records each source encoding,
predicate and derived mask. The existing separate FHM admission policy retains
its dependency on both FP16 and FHM.

Arm's [instruction-set architecture guide](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Armv8-A%20Instruction%20Set%20Architecture.pdf?revision=af73a2a4-620d-4f86-86b0-2987dc04e154)
describes optional half-precision arithmetic introduced in Armv8.2-A. Arm's
[ACLE specification](https://developer.arm.com/documentation/101028/0009/Advanced-SIMD--Neon--intrinsics)
distinguishes the arithmetic capabilities. The local encoding predicates and
independent oracle determine the detailed admission boundary here; no whole-CPU
identity with a QEMU model is claimed.

Reproduce the generated outputs from the repository root:

```sh
python3 tools/execution/a64_fp16_admission.py
```

The command checks both generated files without changing them. `--write`
regenerates the two owned outputs. Parsing is linear in the source size; the
runtime classifier uses a fixed table of 64 masks and constant additional
space. It skips instruction classes outside the scalar/AdvSIMD FP groups.

## Native and checkpoint behavior

The CPU native builder collects original FP16/FHM dependencies before IR
optimization. Native admission, cached lookup and entry check the selected
features independently of optimized result liveness. The cache key includes
FP16 and effective FHM support, preventing a denied memo from suppressing later
admission. PAuth regions have no guest FP instruction dependency merely because
their host implementation may use FP/SIMD helpers.

The parent sampled 64 original half-precision encoding descriptions and rejected
all sampled native region shapes. This is an existing interpreter boundary,
not proof that native FP16 execution occurred. Guard tests execute real integer
native code with explicitly synthetic feature metadata and preserve that
distinction. The change does not introduce native FP16 instruction support.
Stateless SMIR operations remain abstract operations; the CPU builder owns the
selected processing-element profile policy.

No serialized field or public ABI changes. Native dependencies and cache keys
are derived state; the software A64 private checkpoint tag stays `RAXA6402`.
Backend tests save before/after the Undefined exception, restore the disabled
profile, observe zero retirement, and resume the handler once. C API tests
restore the stopped context, enable FP16 through the trusted host state path,
and retry one instruction. This adds no new public feature-configuration API.

## Independent oracle and focused checks

[`guest.s`](guest.s) and [`guest.ld`](guest.ld) use the same explicit EL3 entry
and semihosting convention as the [FP control oracle](../a64-fp-control/README.md).
Its X0 sentinel is a mapped RAM address, permitting storage controls as well as
arithmetic and conversion forms. It verifies target EL, syndrome class,
instruction/return PC, saved mode, and denied X0 effects.

The QEMU 11.1.2 run contains 169 distinct words, 676 guest images and 1,352
executed cases across EL0/EL1, FPEN=0/3, Cortex-A53 and max. It includes 12
legacy controls. Without FP16, optional arithmetic reports `100I`: EL1, EC=0,
original instruction PC. Admitted forms reach `115A`, the subsequent SVC.
With the feature present and FP access denied, legal forms report `107I`.
Reserved variants remain distinguishable as Undefined. The original max run
also includes newer instructions outside the selected RAX profile. In
particular, 0x1eea0020 is `FCVTNS S0,H1`, requiring FEAT_FPRCVT. The
[retained Binutils primary patch](primary/fprcvt-binutils-2025-06.html)
corroborates its encoding; [provenance](primary/provenance.json) records the
unmodified source and hash. Cortex-A76 rejects this word, max admits it, and
RAX correctly rejects it for its represented profile. The max outputs remain
retained as profile-difference evidence. A separate Cortex-A710 run reuses all
676 original guest images for the positive-profile comparison. Raw inputs, outputs,
commands and hashes are retained with this semantic group's evidence.

Focused CPU tests cover 8,192 class/register/control combinations, including
maximum counters. Separate checks cover illegal-state priority, legacy forms,
reserved-encoding positive fixtures, native cache behavior, checkpoint
continuation and the C API. QEMU is a software oracle, and Rosetta does not
establish physical Intel Mac HVF behavior.

## Reserved-field corpus

[`batch.s`](batch.s) and [`batch.ld`](batch.ld) execute an immutable list of
82,679 distinct words through a freshly synchronized instruction slot. Each
word produces one `U` (Undefined), `D` (FP-access denial), or `P` (executed then
SVC) event. The exception handler checks the saved mode, syndrome, fault or
return PC, and denied X0 sentinel. It returns to an EL1 driver between words.
The list enumerates non-register controls from the 64 source descriptions,
scalar half prefixes and all 4,096 bits[21:10] combinations, scalar conversion
controls, and additional SIMD reduction, comparison and indexed holes. Exact
word-list and raw guest hashes are retained; this is finite admission coverage,
not an exhaustive proof over 32-bit instructions or numerical FP semantics.

Three QEMU profiles execute four batches each (EL0/EL1 and FPEN=0/3), totaling
992,148 instruction events. The Cortex-A710 comparison includes FCMA and
JSCVT, which the tested RAX guest IDs currently advertise. Cortex-A53 and
Cortex-A76 provide earlier-profile negative controls. The selected RAX
configuration flags and advertised FCMA/JSCVT IDs are not fully coherent;
that pre-existing profile defect remains open. Consequently an earlier-profile
mismatch is recorded explicitly rather than treated as an admission match.

The intermediate engine admitted 22 reserved reduction forms under denied FP
access. Twenty produced Undefined only after an incorrect access trap would
have taken priority; two reserved FADDP forms also executed with access enabled.
The correction validates the full/half reduction sizes, .4S-only vector forms,
and fixed FADDP selector before access checks. The retained intermediate engine
and oracle outputs establish the failing side of this regression.

The corrected engine matches all 330,716 Cortex-A710 events. It retains four
Cortex-A53 differences at the JSCVT word and 244 Cortex-A76 differences
(61 distinct words across four control profiles: JSCVT plus 60 half-precision
FCMA forms). No other mismatch remains in this finite corpus. Every difference
and every original max output is retained; the capability-coherence defect is
not marked resolved by this comparison.

The reserved predicates cite the pinned ASL instruction classes
`aarch64_float_convert_fix`, `aarch64_float_convert_int`, scalar/vector FP16
rounding and comparison, scalar/vector FP reduction, and complex by-element
multiplication. Scalar FJCVTZS's fixed double-to-W shape is additionally defined
by `FJCVTZS_32D_float2int` in the local
[`fpsimd/encodings.pl`](../../architecture/arm/opcodesDB/db/aarch64/fpsimd/encodings.pl).
Unknown/newer instruction support remains a separate capability boundary.

## Qualified historical fixture correction

The owning suite exposed two historical generated tests for `0x1e070000` that
expected an allocated instruction. In the pinned `aarch64_float_convert_fix`
decode, sf=0 with scale[5]=0 is Undefined; the opcode/rmode combination is also
reserved. Eight exact-word QEMU cases across Cortex-A53/Cortex-A710, EL0/EL1
and FPEN=0/3 all report `100I`. The earlier generated allocation expectations
characterized the previous RAX decoder; they are not independent ISA evidence.

The [qualified input](legacy-conversion-correction.json) retains the old output
hash, exact case names, primary source and raw oracle hashes. The focused owner
[`a64_conversion_expectations.py`](../../../tools/testgen/a64_conversion_expectations.py)
changes only those two expectations and updates the corpus manifest hash:

```sh
python3 tools/testgen/a64_conversion_expectations.py
```

`--write` applies the focused correction idempotently. Full historical corpus
inputs and generator revision remain unknown; this command does not claim full
regeneration. Its source scan takes O(N) time over the selected output and O(N)
space. It never invokes RAX to decide the corrected expectation.

The full library run also exposed the lowering test's CPU reference executing
emitted half arithmetic with FP16 disabled. The reference helper now selects
FP16 explicitly and is extracted from the oversized parent test module. This
is CPU interpretation of emitted code, not a new native guest FP16 execution
claim. The observed old fixture failure and its exact compiled binary hash are
retained. The interrupted qualification logs remain failed/incomplete evidence.

## Assumption register and remaining scope

| ID | Assumption / dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| HA1 | The pinned predicates identify the optional FP16 requirement in this snapshot | Explicit decode-time checks; fixed source hash | All 64 descriptions, register/control variations and QEMU samples; an absent-feature arithmetic execution falsifies admission | Confirmed within tested classes |
| HA2 | Legacy half conversion/storage is independent of optional FP16 arithmetic | Absence of the optional predicate in those encodings; independent Cortex-A53 controls | Twelve legacy controls with FP access enabled/denied; accidental feature rejection falsifies the distinction | Confirmed for selected controls |
| HA3 | Native source dependencies survive optimization | CPU builder captures them from original instruction PCs | Cold admission, integer native control with synthetic metadata, denied entry and cache transition | Confirmed within represented native boundaries; no native FP16 execution claim |
| HA4 | Checkpoint capture occurs between execution calls | Existing stopped-CPU ownership and derived caches | Capture/restore around delivery, zero retirement, single handler/retry execution; duplicate or lost execution falsifies continuation | Confirmed at tested boundaries |
| HA5 | Normal execution with masked FP numerical traps suffices to compare decode admission | Reset FP control state and U/D/P exception harness | Reserved/valid pairs with FPEN=0/3; unexpected exception, modified denied sentinel or wrong return PC fails the harness | Confirmed within retained guests |
| HA6 | Earlier QEMU profiles differ from the RAX guest IDs for FCMA/JSCVT | Raw A53/A76/A710 outputs and selected RAX IDs | Preserve every mismatch; isolate 0x1e7e0020 and complex forms; an unexplained mismatch blocks qualification | Retained profile boundary |

High-impact remaining work includes broader capability/profile coherence,
unrepresented and newer encoding controls, complete SVE/SME and halting-debug
behavior, and complete backend/in-flight/platform state, bounded native
execution, debugger/clock/replay coordination and physical Intel Mac HVF
qualification. All four full audit findings remain partial. The whole Linux
raw native-reference suite and physical A32 behavior remain separate runtime
boundaries.

## Qualified implementation evidence

Current engine replay matches 1,352 original single-word guests using Cortex-A53
and Cortex-A710 references. The current CLI matches all 24 retained kernel
guests. Full owning integration: 47706 passed across
23 targets. C API: 214 passed;
18 C/C++ consumers and 6 strict ABI checks passed.
Library: 11211 passed, 0 failed,
2 ignored. Doctests: 5 ignored.

The earlier group retains an unchanged Darwin ptrace transport failure and
its independent-parent reproduction. A passing new run does not establish a
fix for that unchanged source or resolve its unknown root cause.

Formatting, workspace Clippy, all-target compilation, interpreter-only
compilation, and selected x86-64 interpreter tests under Rosetta passed. The
Linux-only whole native-reference suite and physical Intel Mac HVF execution
were not run on this Apple Silicon host. All four full findings remain partial.
