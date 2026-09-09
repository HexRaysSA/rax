# RAX Agent Engineering Guide

## 1. Purpose and scope

This file is the root execution contract for autonomous and interactive coding
agents working in this repository. It applies to the entire tree unless a deeper
`AGENTS.md` supplies more specific instructions. It is optimized for changes
whose correctness depends on exact CPU, memory, exception, floating-point,
vector, ABI, or JIT behavior.

RAX is a Rust 2024 multi-ISA emulator and virtual-machine monitor. Its central
correctness problem is not only implementing an instruction once; the same
architectural behavior may be represented in the direct ISA interpreter, SMIR
lifter and interpreter, native lowerers, backend adapters, static analysis API,
and differential tests. An agent must identify every affected representation.

Do not duplicate the README's volatile instruction-coverage claims here. For
current advertised capabilities, consult `README.md`; for implementation truth,
inspect source and executable tests.

## 2. Instruction priority and truth hierarchy

Apply instructions in this order:

1. System, developer, and current user instructions.
2. The nearest applicable `AGENTS.md`.
3. Repository configuration and executable behavior.
4. Current source and tests.
5. Current CI workflow definitions.
6. Derived design documents and historical reports.
7. Comments, issue prose, and names.

When sources disagree, do not silently select the convenient one. Record the
conflict, determine which source is authoritative for the task, and update stale
documentation in scope. If the answer remains unknown, state `unknown`, list
the assumption required to proceed, and provide a falsification probe.

Repository-specific examples:

- `Cargo.toml` is authoritative for feature names and Cargo test targets.
- `.github/workflows/*.yml` is authoritative for current CI commands.
- `src/lib.rs` and `src/README.md` are authoritative for canonical module
  ownership and compatibility re-exports.
- Rust source is authoritative over the dated SMIR markdown baseline in
  `docs/specifications/smir/`.
- ISA manuals define architectural behavior; tests and code must not redefine
  specified behavior merely to agree with each other.
- A successful command is not evidence that an oracle or host-specific test ran;
  inspect test counts and skip output.

## 3. Universal operating contract

### 3.1 Technical rigor

- Do not fabricate paths, APIs, feature support, test results, references, or
  architectural semantics.
- Separate facts, inferences, assumptions, and unknowns.
- Use exact architecture nomenclature and fixed-width types. Express sizes in
  bytes or bits explicitly. Use SI units for time/rate and hexadecimal for
  addresses, masks, encodings, and architectural bit fields where it improves
  auditability.
- Show calculations stepwise when a result depends on widths, masks, address
  arithmetic, scaling, timing, or layout. Include units, truncation rules,
  overflow behavior, significant figures, and error bounds where applicable.
- For algorithms, state relevant time and space complexity when it informs the
  implementation or review.
- Make technical tradeoffs from evidence. Do not provide ethical opinions. If a
  request cannot be completed without an ethical judgment, output `ETHOUT`.

### 3.2 Assumption Register

Maintain an Assumption Register for every nontrivial task. Each assumption must
have:

| Field | Required content |
|---|---|
| ID | Stable identifier such as `A1` |
| Assumption | Precisely what is being treated as true |
| Basis | Source evidence or reason it is necessary |
| Dependent result | Which design, edit, or conclusion depends on it |
| Stress test | Boundary or adversarial case |
| Falsification probe | Concrete observation or command that would disprove it |
| Status | confirmed, retained, revised, or falsified |

Do not invent assumptions to populate the table. If none materially affect the
result, report `None`. Revisit the register after implementation and testing.

### 3.3 Bounded scope

Complete the requested behavior rather than the smallest change that happens to
make one test pass. At the same time, do not mutate adjacent systems without
authorization.

Record discovered out-of-scope items separately:

| Impact | Meaning |
|---|---|
| High | Can invalidate correctness, safety, ABI, or the requested result |
| Medium | Material maintainability, performance, portability, or coverage issue |
| Low | Local cleanup or optional improvement |

For each item, cite evidence and state whether it blocks the task. Do not
implement a non-blocking opportunity merely because it was discovered.

### 3.4 Worktree ownership

Assume the worktree may be shared with humans or other agents.

Before editing:

1. Run `git status --short --branch`.
2. Resolve the repository root with `git rev-parse --show-toplevel`.
3. Inspect diffs for every tracked file already modified in the intended scope.
4. Treat all pre-existing tracked and untracked content as user-owned.
5. Record the baseline HEAD and the files this task will own.

During work:

- Re-check status before broad formatting, generation, testing that writes
  fixtures, or any Git operation.
- Never use `git reset --hard`, `git checkout -- <path>`,
  `git clean`, `git stash`, or destructive recursive commands to obtain a
  clean tree.
- Never stage with `git add -A` or `git add .`. Stage or commit only when
  explicitly requested, and then use an exact path list.
- Do not overwrite, reformat, delete, or include unrelated concurrent edits.
- If another edit overlaps the same lines, inspect and integrate it deliberately;
  do not choose a winner by timestamp.
- A build from a dirty shared tree validates the combined tree. Do not attribute
  it solely to your change without isolating or accounting for the other diffs.

### 3.5 Evidence-first task loop

Use this loop:

1. Translate the request into explicit acceptance criteria.
2. Locate applicable instructions and authoritative sources.
3. Inspect the current worktree; never rely only on earlier conversation state.
4. Search definitions, call sites, exhaustive matches, tests, feature gates, and
   source-path coupling with `rg` and `rg --files`.
5. Build a change-surface map across execution planes.
6. Capture baseline behavior for a bug or behavior change.
7. Plan implementation and validation together.
8. Make the smallest complete semantic change.
9. Add strategic tests in the same change.
10. Run targeted checks, then the broadest relevant gates.
11. Review the final diff adversarially.
12. Audit every acceptance criterion against direct evidence.

Tool-output truncation is not evidence of absence. Re-run a narrower query if
output is truncated. An exit status of zero is not sufficient when a test may be
`cfg`-elided, ignored, filtered out, or self-skipped.

### 3.6 Authorization and autonomy

Interpret the requested action precisely:

- For review, explanation, diagnosis, or status, inspect and report; do not
  modify code merely because a fix is apparent.
- For fix, implement, change, or build, complete the code, tests, and relevant
  verification within the authorized scope.
- Commit, push, publish, send, delete, regenerate large corpora, or change
  external state only when explicitly authorized.
- Make reversible, evidence-backed in-scope assumptions when they do not change
  the requested outcome; record them in the Assumption Register.
- Stop for user input when a missing choice would materially select a different
  API, architecture contract, destructive action, or external side effect.

Do not return a plan, TODO, or suggested patch as a substitute for authorized
implementation. If genuinely blocked, report the exact blocking condition,
evidence already gathered, and the smallest user or external action that would
unblock it.

## 4. Durable repository facts

Verify these facts when changing their owning files:

- The root package is `rax`, edition 2024.
- The Cargo workspace contains `capi`, whose package name is `rax-capi`.
- The workspace default member is the root package. A root `cargo test` does
  not establish C API coverage.
- `microkernel` and `tools/asl-parser/asl-parser-rs` are standalone,
  workspace-excluded packages with independent build requirements.
- `autotests = false`; every integration-test binary must be declared with a
  `[[test]]` entry in `Cargo.toml`.
- Default features are `kvm` and `smir-jit`. KVM code is additionally
  target-gated to Linux x86-64.
- Optional features are `hvf`, `trace`, `debug`, `profiling`,
  `x86_64-suite`, and the compatibility alias `x86-suite`.
- There is no tracked root `rust-toolchain` file. CI uses stable Rust for the
  main crate and nightly only for sanitizer/build-std or bare-metal lanes.
- `.cargo/config.toml` selects `target-cpu=x86-64-v3` only on x86-64 hosts.
- The crate and Clippy lint tables allow warnings. A quiet build or green Clippy
  run is not proof that warning-prone code was reviewed.

Do not add a toolchain pin, alter the x86-64 baseline, change default features,
or update dependency/lock state incidentally.

### 4.1 Feature/host selection

| Validation intent | Feature selection |
|---|---|
| Portable interpreter core / cross-build | `--no-default-features` |
| Linux x86-64, Linux AArch64, or Apple-Silicon portable CI lane | `--no-default-features --features x86_64-suite,smir-jit` |
| Intel macOS portable CI lane | `--no-default-features --features x86_64-suite` |
| Linux x86-64 KVM backend | default features plus `--features x86_64-suite`, with usable `/dev/kvm` |
| macOS HVF backend | explicitly enable `hvf`; select a guest architecture supported by the host |
| C API JIT | package `rax-capi` feature `jit`, which forwards to engine `smir-jit` |

Use the exact current matrix in `.github/workflows/ci.yml` and
`.github/workflows/cross.yml` when host support is part of the claim. Feature
compilation does not prove that the corresponding runtime backend was exercised.

## 5. Architecture and ownership

The canonical source collaboration graph is:

```text
CLI/config -> VM runtime -> machine -> devices
                       -> backend -> per-ISA CPU
                                  -> SMIR lift/interpret/optimize/lower/runtime
static oracle -------------------> ISA decode + SMIR analysis
C API ---------------------------> public engine and oracle surfaces
```

This is an ownership guide, not a strict dependency DAG. Inspect actual imports
and callers before changing an interface.

| Path | Primary ownership |
|---|---|
| `src/cli/`, `src/config/` | CLI parsing, file/runtime configuration, validation |
| `src/vm/` | Architecture-neutral runtime, memory, snapshots, timing, vCPU contracts |
| `src/vm/vcpu/` | `VCpu`, exits, and multi-architecture exported CPU state |
| `src/backend/emulator/` | Software-backend adapters; several are intentionally thin |
| `src/backend/kvm/` | Linux x86-64 KVM backend |
| `src/backend/hvf/` | macOS Hypervisor.framework backends |
| `src/machine/` | Board selection, boot, address maps, and device wiring |
| `src/devices/` | Device models, buses, MMIO, PIO, DMA, and interrupt-facing state |
| `src/isa/x86_64/` | Direct x86-64 decode, execute, CPU, memory, architectural helpers |
| `src/isa/arm/` | AArch64, AArch32/Thumb, and Cortex-M decode/CPU semantics |
| `src/isa/riscv/` | RISC-V decode, CPU, memory, FP, compressed, crypto, CSR semantics |
| `src/isa/hexagon/` | Hexagon packet decode, CPU, generated opcodes, scalar/HVX semantics |
| `src/smir/ir/` | IR structure, operation taxonomy, types, flags, context, memory contracts |
| `src/smir/lift/` | Per-ISA machine-code-to-SMIR lifting |
| `src/smir/interpret/` | Canonical SMIR interpretation |
| `src/smir/optimize/` | Semantics-preserving SMIR transformations |
| `src/smir/lower/` | Host lowering, emitters, cross lowering, JIT gates, runtime/trampolines |
| `src/oracle/` | Stateless decode/lift/analysis output |
| `src/debug/` | GDB protocol and debugger behavior |
| `src/observability/` | Tracing and profiling |
| `capi/` | Stable C ABI, C++ wrapper, packaging, ABI consumers |
| `tests/support/` | Shared integration-test harnesses |
| `tests/suites/` | Handwritten integration and differential runners |
| `tests/generated/` | Checked-in include-only generated data; not Cargo targets |
| `tools/` | Generators and external-oracle tooling |
| `microkernel/` | Standalone multi-architecture bare-metal test payload |

`src/lib.rs` retains compatibility re-exports such as `rax::cpu`; new code
must use canonical ownership paths such as `rax::vm::vcpu`.

## 6. Change-surface map

Before implementation, mark each plane as affected, unaffected with reason, or
unknown:

| Plane | Questions |
|---|---|
| Direct decode | Does an ISA decoder recognize and validate every encoding form? |
| Direct execute | Does the software CPU implement the architectural effect? |
| CPU state | Are registers, flags, system state, exceptions, or serialization changed? |
| Memory/MMU | Are translation, permissions, alignment, ordering, atomics, or MMIO affected? |
| SMIR lift | Is the instruction represented exactly, including control flow and faults? |
| SMIR IR | Can existing operations express it, or is a new `OpKind` required? |
| SMIR interpreter | Is canonical IR behavior implemented for all widths/modes? |
| Optimizer | Can passes observe or transform the new operation safely? |
| Native lowering | Do x86-64/AArch64/cross lowerers support it, or reject it safely? |
| JIT runtime | Are gates, clobbers, helpers, exits, cache invalidation, or ABI affected? |
| Backend | Do emulator/KVM/HVF adapters expose equivalent state and exits? |
| Machine/device | Does board wiring or device-visible behavior change? |
| Oracle/analysis | Must decode JSON, effects, register access, or completeness change? |
| C ABI | Does public layout, enum numbering, ownership, or panic containment change? |
| Tests/docs | Which unit, integration, differential, generated, and reference artifacts change? |

An omission is acceptable only when the implementation genuinely does not use
that plane; state why. Do not add native admission merely because interpretation
works. Unsupported native regions must reject before execution and fall back at
the exact guest frontier.

## 7. Task routing

| Task | Start here | Usually inspect next |
|---|---|---|
| x86 direct opcode/semantic change | `src/isa/x86_64/decode/dispatch/`, `src/isa/x86_64/execute/` | `src/isa/x86_64/{cpu,memory,flags}.rs`, matching tests |
| x86 SMIR lift | `src/smir/lift/x86_64/{decode,dispatch,scalar,simd}/`, `src/smir/lift/x86_64/apx.rs` | IR ops, interpreter, lowerers, JIT gates |
| New SMIR operation | `src/smir/ir/ops.rs` | all `OpKind` matches, interpreter ops, optimizer, lowerers |
| x86-64 host lowering | `src/smir/lower/x86_64/`, `src/smir/lower/x86_64/ops/` | emitter, state, memory, JIT/runtime gate tests |
| AArch64 host lowering | `src/smir/lower/aarch64/` | `src/smir/lower/runtime/trampolines/`, host-specific tests |
| AArch64 guest semantics | `src/isa/arm/decoder/aarch64.rs`, `src/isa/arm/aarch64/cpu/` | `src/smir/lift/aarch64/`, ARM and differential tests |
| AArch32/Thumb semantics | `src/isa/arm/aarch32/`, `src/isa/arm/decoder/{aarch32,thumb}.rs` | `src/smir/lift/{aarch32,thumb}.rs`, ARM differential tests |
| RISC-V semantics | `src/isa/riscv/` | `src/smir/lift/riscv/`, lift/differential/JIT tests |
| Hexagon semantics | `src/isa/hexagon/` | `src/smir/lift/hexagon/`, packet/HVX differential tests |
| Backend contract | `src/backend/`, `src/vm/vcpu/` | state conversion, exits, snapshots, API consumers |
| VM or boot flow | `src/vm/runtime.rs`, `src/machine/` | devices, fixtures, machine tests, README examples |
| Device | `src/devices/` | machine maps/wiring, IRQ path, MMIO/PIO tests |
| Static analysis | `src/oracle/`, `src/bin/rax_isa_oracle.rs` | SMIR lifters, `tests/suites/api/isa_oracle.rs`, C API |
| C/C++ API | `capi/include/rax.h`, `capi/src/` | `capi/include/rax.hpp`, ABI test, examples, README, engine state |
| Integration-test binary | `Cargo.toml` `[[test]]` | runner file, support module, CI shard ownership |
| Generated corpus | `tests/generated/README.md`, `tests/generated/manifest.toml` | owning generator and differential runner |
| CI/tooling | matching workflow/script | `tests/suites/tooling/ci_actions_pinned.rs`, safety tests, workflow README |

## 8. Instruction and semantic implementation contracts

### 8.1 All ISAs

For an instruction or architectural behavior change:

1. Identify the normative ISA revision and exact encoding class.
2. Enumerate legal and reserved encodings before modifying dispatch.
3. Trace operand decode through architectural reads, writes, memory accesses,
   control flow, and exception paths.
4. Preserve precise instruction-boundary state, including fault PC and any
   architecturally defined partial completion.
5. Implement all relevant widths, modes, endian cases, and feature gates.
6. Distinguish defined, implementation-defined, constrained-unpredictable,
   unpredictable, and undefined outputs according to that ISA.
7. Add a direct semantic test and, where applicable, a differential test.
8. If the instruction reaches SMIR, establish direct-vs-SMIR equivalence.
9. If natively lowered, establish interpreter-vs-native equivalence on the
   applicable host.

Do not encode a test expectation from the implementation under test. Derive it
from the ISA specification or an independent oracle.

### 8.2 x86-64 direct path

The direct path is distributed:

- Prefix/ModR/M/SIB and map dispatch live under
  `src/isa/x86_64/decode/`.
- Category semantics live under `src/isa/x86_64/execute/`.
- CPU integration and large architectural state surfaces remain in
  `src/isa/x86_64/cpu.rs`, with memory and flag helpers in sibling files.

For legacy, REX, REX2, VEX, or EVEX work, test:

- mandatory prefix vs repeat-prefix meaning;
- operand and address size;
- REX/REX2 extension bits and legacy high-byte register exclusion;
- ModR/M register and memory forms, SIB, displacement, RIP-relative addressing,
  and segment bases;
- privilege and feature enablement;
- legal vs reserved `W`, `L'L`, `vvvv`, `aaa`, `z`, and `b` values;
- APX EGPR, NDD source preservation, NF flag suppression, and Map 4 selection;
- vector merge/zero masking, `k0` special behavior, inactive lanes, scalar
  upper elements, and VEX/EVEX upper-lane clearing;
- exact exception class and priority.

The current direct decoder exposes APX state through `is_apx`, `apx_ndd`,
`apx_nf`, and `apx_ndd_reg` in `src/isa/x86_64/cpu.rs`. Use these
central accessors rather than re-decoding EVEX fields inside individual
handlers.

Do not update only the direct decoder when the same instruction is accepted by
the SMIR lifter, or vice versa, without recording the intentional asymmetry.

### 8.3 SMIR operation additions

Before adding an `OpKind`, attempt to compose existing operations only if the
composition preserves faults, flags, ordering, and undefined behavior.

For a new operation:

1. Add its type and semantic contract in `src/smir/ir/ops.rs`.
2. Search every exhaustive `OpKind` match and metadata helper.
3. Define sources, destinations, widths, flag reads/writes, side effects, trap
   behavior, and whether it is safe for JIT admission.
4. Implement canonical interpretation in the matching
   `src/smir/interpret/ops/` category.
5. Update lifters.
6. Update optimizer handling conservatively.
7. Implement each applicable lowerer or return a deliberate unsupported result.
8. Update runtime/JIT gates only after complete lowering and state-marshalling
   support exists.
9. Test IR construction, interpretation, optimization parity, lowering bytes,
   native execution, and fallback as applicable.

Explicitly audit both `SmirOp::is_jit_safe` and `OpKind::is_jit_safe`, then
the target-specific runtime admission gates. A class-level whitelist is not
proof that a particular operand/width/state combination is natively valid.

Unknown operations, unsupported widths, helper failures, and unsafe frontiers
must not become `unreachable!()` merely to satisfy an exhaustive match.

### 8.4 Optimizer

An optimization must preserve:

- register and vector values, including partial-register semantics;
- lazy/materialized flag meaning and undefined-flag treatment;
- control-flow targets and interpreter frontiers;
- fault/trap possibility, type, priority, and faulting guest PC;
- memory access count, width, order, volatility, atomicity, and alias behavior;
- calls and observable runtime helpers;
- self-modifying-code and cache-invalidation contracts.

Test at O0 and every affected optimized level. Use adversarial CFGs: multiple
predecessors, loops, unreachable blocks, live values at exits/frontiers, aliasing
loads/stores, and trapping operations. A native equality test alone does not
isolate an optimizer defect; compare unoptimized and optimized interpretation.

### 8.5 Native lowering and JIT

Native code is an optional optimization, never the semantic fallback.

- The interpreter defines implemented SMIR behavior; the ISA manual remains the
  architectural authority.
- Admission gates must be fail-closed.
- A lowerer must account for host feature availability, physical-register
  clobbers, stack alignment, calling convention, guest-state marshalling,
  memory helpers, exits, flags, and instruction-cache synchronization.
- Do not emit a host instruction solely because it has a similar mnemonic.
- Test emitted bytes or words and execute them where the host supports the
  backend.
- Test rejection/fallback for unsupported operations and widths.
- Cross-ISA tests must distinguish guest ISA from host ISA explicitly.
- Run host-native JIT tests serially when the existing CI lane does so.
- Use `RAX_NO_JIT=1` to isolate interpreter behavior,
  `RAX_JIT_VERIFY=1` for x86-64 runtime differential verification, and
  `RAX_JIT_TRACE=1` for native-region crash attribution. These variables are
  presence switches; inspect source before assuming value parsing.

### 8.6 Floating point and vectors

Floating-point tests must cover, as applicable:

- positive and negative zero;
- normal boundaries and subnormals;
- quiet and signaling NaNs, payload/sign propagation, and default-NaN modes;
- positive and negative infinity;
- all architecturally selectable rounding modes;
- invalid, divide-by-zero, overflow, underflow, inexact, denormal/input-denormal,
  saturation, and sticky status flags;
- masked-off exceptional lanes and exception suppression;
- fused vs non-fused arithmetic;
- conversion boundaries immediately below, at, and above representable limits.

Compare raw bits and status registers. Use approximate equality only when the
ISA specifies an approximation, and encode its formal error bound.

Vector tests must vary element width, vector width, lane boundaries, mask
density, merge/zero mode, aliasing of operands, upper-lane behavior, and memory
crossing/fault boundaries.

### 8.7 Memory, atomics, and exceptions

Test:

- address wrap/truncation and canonicality;
- translation-disabled and translated modes;
- read/write/execute permissions and privilege;
- aligned and unaligned accesses;
- accesses crossing pages, mapped regions, MMIO boundaries, or vector lanes;
- endianness;
- precise exception priority and saved PC;
- atomic read-modify-write indivisibility and ordering;
- exclusive-monitor success and failure where applicable;
- partial-completion rules for repeated, gather/scatter, packet, or multi-access
  instructions.

Do not replace checked guest-memory access with host pointer access without a
documented and locally proven bounds, alignment, lifetime, aliasing, MMIO, and
concurrency argument.

### 8.8 ARM-family semantics

For AArch64:

- distinguish register 31 as SP or XZR/WZR according to the encoding;
- preserve W-register zero-extension into X registers;
- apply immediate field transforms, shifts, extends, and PC-relative scaling
  before host-width arithmetic can obscure architectural overflow;
- test NZCV and condition evaluation independently from the data result;
- test pre/post-index writeback, base/destination overlap rules, alignment,
  exclusive monitors, acquire/release ordering, and fault-time writeback;
- model FPCR/FPSR, NaN modes, rounding, saturation, and cumulative exception
  state explicitly;
- for NEON/SVE, test predicate granularity, inactive-lane policy, FFR,
  configured vector length, widening/narrowing lane mapping, and multi-register
  memory ordering;
- validate system-register privilege/feature checks and exception syndrome/state
  when the implementation exposes them.

For AArch32 and Thumb:

- distinguish ARM, Thumb-16, and Thumb-32 decode lengths and PC pipeline value;
- preserve CPSR condition execution, IT state, banked/SP/LR behavior, mode
  changes, and exception return semantics;
- test `cond=0b1111` encodings according to the exact instruction class rather
  than treating them uniformly;
- test writeback overlap, unaligned access policy, and little/big-endian modes;
- keep FPSCR/VFP/NEON state separate from integer flags.

For Cortex-M, include xPSR/IT state, MSP/PSP selection, exception stacking and
return, vector-table behavior, NVIC priority/masking, and
PRIMASK/BASEPRI/FAULTMASK interactions. Do not infer Cortex-M behavior from the
A-profile implementation merely because both execute Thumb encodings.

### 8.9 RISC-V semantics

- Make XLEN and enabled extensions explicit in decode and tests.
- Preserve x0 immutability and the specified sign-extension of W-form results.
- Distinguish 16-bit compressed and 32-bit instruction alignment/PC increments.
- Validate reserved encodings and extension collisions before dispatch.
- Test division/remainder zero and signed-overflow cases, shift-amount masking,
  branch/jump target alignment, and precise trap PC/cause/value.
- For FP, test NaN boxing, canonical NaNs, `frm`, accrued `fflags`, dynamic
  rounding mode, and illegal reserved rounding modes.
- For atomics, test LR/SC reservation invalidation, AMO width/sign extension,
  alignment, and `aq`/`rl` ordering.
- For RVV, include `vl`, `vtype`, SEW, LMUL, `vstart`, mask state,
  tail/mask agnostic vs undisturbed policy, overlap constraints, fractional
  groups, saturation, and fault-only-first behavior where implemented.
- CSR reads can have side effects and writes can be WARL/WLRL; do not model all
  CSRs as ordinary storage.

### 8.10 Hexagon semantics

- Decode and execute complete VLIW packets, not isolated words.
- Preserve parse bits, slot/resource constraints, packet PC, duplex forms,
  loop-end behavior, and packet commit timing.
- Model old vs `.new` register/predicate values explicitly; do not make source
  order accidentally define packet semantics.
- Test predicated-off instructions, multiple writes, compare-to-predicate
  forwarding, stores, branches, and exceptions within a packet.
- For HVX, cover vector and vector-predicate widths, pair alignment, lane
  signedness, saturation/rounding, permutations, carry chains, and memory
  alignment/fault behavior.
- Treat generated opcode recognition and handwritten semantics as separate
  change surfaces. A generated decode entry without semantic and differential
  coverage is incomplete.

### 8.11 Devices and VM runtime

For a device or machine change:

- Verify the address/port map does not overlap existing ranges.
- Define supported access widths, byte order, reset values, read side effects,
  write masks, reserved bits, and unmapped/open-bus behavior.
- Trace interrupt assertion, deassertion, routing, and acknowledgment.
- Avoid holding a device mutex across callbacks or code that can re-enter the
  device graph.
- Preserve deterministic snapshot/restore state or explicitly version the
  serialized representation.
- Test the device in isolation and through the owning machine/runtime path.
- Treat boot fixtures and guest binaries as inputs with provenance, not opaque
  blobs to replace incidentally.

### 8.12 Public Rust and C ABI

For public Rust changes, inspect compatibility re-exports in `src/lib.rs` and
downstream use in `capi`, examples, and tests.

For C ABI changes:

- `capi/include/rax.h` is the hand-authored source of truth.
- Do not renumber or reuse published enum/status/register identifiers.
- Preserve struct size/version negotiation, reserved-zero fields, ownership,
  nullability, buffer-length, threading, and callback re-entry contracts.
- Keep Rust panics contained; the release profile must retain unwind behavior.
- Update Rust implementation, C header, C++ wrapper when exposed, ABI consumer,
  examples, and `capi/README.md`.
- Run both `cargo test -p rax-capi` and `make -C capi test` when the public
  C/C++ surface changes.

## 9. Source organization and size discipline

### 9.1 Placement

- Add behavior to its semantic category, not the first convenient open file.
- Follow the surrounding import, visibility, error, and test idioms.
- A directory module keeps shared types and dispatch in `mod.rs`; semantic
  groups belong in siblings and are re-exported where the existing public path
  requires it.
- Use separate `impl Type` blocks across sibling files. Widen a helper only as
  far as necessary, usually to `pub(crate)`, when split modules share it.
- Keep canonical public paths stable unless API change is explicitly requested.

Representative current trees:

- `src/smir/lift/x86_64/scalar/`
- `src/smir/lift/x86_64/simd/{sse,evex,vector}/` plus
  `src/smir/lift/x86_64/simd/vex.rs`
- `src/smir/interpret/ops/`
- `src/smir/lower/x86_64/ops/`
- `src/smir/lower/aarch64/`
- `src/isa/arm/aarch64/cpu/{simd,sve,math}/`
- `src/isa/x86_64/execute/`

### 9.2 Size thresholds

For hand-maintained source:

- Approximately 1,500 lines is a soft ceiling.
- 2,000 lines or 150 kB is a hard split trigger.
- A new file must not cross the hard trigger.
- If a task adds to an already oversized legacy file, split the touched semantic
  group before or in the same change; do not use the task as authorization for
  an unrelated repository-wide split.
- Generated/include-only corpora are exempt from mechanical line thresholds but
  remain subject to generator ownership.

A mechanical split must preserve behavior and method coverage. Check for
`include!`, `include_str!`, path attributes, tests that scan source text,
module privacy, macro scope, and documentation links before moving code.
For example,
`tests/suites/isa/x86_64/simd/avx512/evex_rm_reg_ext.rs` reads the EVEX
dispatch source files with `include_str!`.

For a giant match, a thin dispatcher may delegate to semantic sub-dispatchers.
Preserve the original fallback contract: an unsupported/error case must remain
unsupported/error, and an invariant-only unreachable case may remain
unreachable only if the invariant is still proven. Local macros or closures
whose scope spans arms must be refactored deliberately before splitting.

After Rust restructuring, run formatting and build all targets. In a shared dirty
tree, first use `cargo fmt --all --check`; run mutating `cargo fmt --all` only
when its resulting diff is confined to owned files. Otherwise format exact owned
files with the repository edition and report unrelated formatting debt.

## 10. Generated, derived, reference, and binary material

Classify a file before editing it.

### 10.1 Generated implementation

`src/isa/hexagon/generated/opcodes.rs` is generated. Change its owning
generator/table under `tools/hexagon/`, regenerate, and review the semantic
diff. Do not hand-edit or split the generated file.

### 10.2 Generated test data

`tests/generated/` contains checked-in include-only data, not standalone test
binaries. Read:

- `tests/generated/README.md`
- `tests/generated/manifest.toml`
- the consuming `include!` or `include_str!` site

Several manifest fields explicitly say `unknown`; the repository cannot
currently reproduce every corpus exactly. Do not invent a regeneration command
or provenance. If a reproducible generator exists, update generator inputs,
output, manifest provenance/hash, and consuming tests together. If it does not,
state the limitation.

### 10.3 Integration-test registration

Because `autotests = false`:

- Read `tests/README.md` for the current target registry and reachability
  rules.
- Adding a file under `tests/suites/` does not make it run.
- A new test binary needs a `Cargo.toml` `[[test]]` entry.
- A case inside the aggregated x86 suite needs a `#[path = ...]` module entry
  in `tests/suites/isa/x86_64/main.rs`.
- ARM generated modules are included through
  `tests/suites/isa/arm/main.rs` and `tests/generated/arm/mod.rs`; verify
  reachability rather than assuming directory presence means execution.
- Add the target to the appropriate CI shard if existing broad Cargo selection
  will not execute it.

### 10.4 Reference and historical material

- Treat large vendor specifications, research reports, and imported hardware
  sources as reference inputs unless the task explicitly targets them.
- Put every external document used to design, implement, debug, or validate a
  change under `docs/`. Use the most semantically relevant existing subpath (for
  example, `docs/specifications/<isa>/`, `docs/architecture/<isa>/`,
  `docs/hardware/<platform>/`, or `docs/development/<topic>/`), and create that
  subpath when none exists. A source may also exist elsewhere, but the `docs/`
  copy is required; do not newly place implementation reference documents at
  the repository root or in an ad hoc scratch directory.
- Preserve enough provenance alongside each external document to identify its
  canonical title, author or issuing organization, revision or date, source URL,
  and retrieval date. Retain applicable license or redistribution notices and
  record a checksum when useful.
- Do not reformat or mass-edit primary-source text/PDF/XML material.
- Dated reports can contain obsolete paths or status. Revalidate every claim
  against current source.
- Do not add large binaries, kernels, dumps, or generated corpora without
  explicit scope, provenance, and size justification.

### 10.5 Dependency and workflow pins

- `Cargo.lock` is committed.
- `Cargo.toml` exact-pins `vm-memory` and applies a commit-pinned
  `linux-loader` patch. The adjacent manifest comments describe a
  platform/version-resolution constraint; read and revalidate it before any
  related dependency edit.
- Do not run broad `cargo update` as part of an unrelated task. For an
  authorized dependency change, inspect the resolved graph, feature unification,
  duplicate versions, target-specific dependencies, and cross-build effect.
- External GitHub Actions must remain pinned to full commit SHAs. Run the
  `ci_actions_pinned` test after workflow/action edits.
- Use `--locked` in reproducibility and cross-build evidence. If a lockfile
  change is intended, review every changed package rather than treating the
  generated diff as opaque.

## 11. Test design requirements

### 11.1 Mandatory evidence

- Every bug fix requires a regression test that fails under pre-fix behavior and
  passes after the fix.
- Every new instruction, opcode form, SMIR operation, lowering, optimization,
  device behavior, or public API behavior requires tests in the same change.
- A refactor requires behavior-preservation tests or existing coverage shown to
  exercise every moved dispatch group.
- Documentation-only changes require path/link/command validation appropriate to
  the text; they do not require an unrelated 124k-test run.

Establish the pre-fix failure by a captured baseline, a temporary local reversal,
an isolated parent revision, or a minimal reproducer. Do not claim red-green
coverage without observing both states.

Test-name filters are iteration tools. Before completion of a behavioral change,
run the complete affected Cargo test binary without the filter, plus every other
affected plane identified in the change-surface map.

### 11.2 Strategic case selection

Use boundary partitions, not one happy path:

- minimum, maximum, zero, all-ones, alternating-bit, and one-hot operands;
- every operand width and encoding family;
- source/destination aliasing and distinct registers;
- register and memory forms;
- first and last lane, empty/full/sparse masks;
- immediates at field boundaries and values requiring architectural masking;
- successful and faulting memory paths;
- legal, reserved, unsupported, and feature-disabled encodings;
- state immediately before and after overflow, saturation, rounding, page, and
  canonical-address boundaries.

For randomized/differential testing, record the seed, generated bytes, initial
state, oracle identity/version, comparison mask, and minimized reproducer on
failure. Never compare architecturally undefined bits as if they were defined.

### 11.3 Differential oracle hierarchy

Use the strongest independent oracle available:

- x86-64 architectural execution: KVM/real hardware where host support exists.
- x86 encoding without silicon support, such as APX forms: current LLVM
  assembler bytes plus the published ISA semantics.
- AArch64/AArch32: native EL0 where supported, otherwise QEMU user-mode and
  architecture specification.
- RISC-V and Hexagon: QEMU/toolchain oracle plus the relevant ISA manual.
- Direct-vs-SMIR and interpreter-vs-JIT comparisons are essential parity tests,
  but they are not independent architectural oracles.

Oracle harnesses often self-skip when a tool, feature, or device is missing.
For a claimed differential result, capture evidence that:

1. the intended test count was nonzero;
2. the oracle executable/device was found;
3. cases actually ran;
4. skip/unsupported counts are understood;
5. comparison did not mask the field being changed.

### 11.4 Test-target selection map

Target names below come from `Cargo.toml`; re-check the manifest when it
changes.

| Change surface | Required focused targets | Stronger evidence when applicable |
|---|---|---|
| x86 direct decode/execute | `x86_64`, relevant library tests | `asm_instructions`, `differential`, `diff_fuzz` |
| x86 AVX-512/AVX10/APX | `x86_64`, relevant SMIR tests | `x86_64_evex_qemu_diff`, `x86_64_apx_map4_qemu_diff`, `x86_64_avx512_kvm_diff` |
| SMIR IR/interpreter/optimizer | library tests, affected ISA target | affected lift/JIT/roundtrip target and differential oracle |
| x86-64 native JIT | `smir_jit_vcpu`, `smir_jit_evex_masking` | `differential`/verification mode on Linux x86-64 |
| AArch64 host lowering | `aarch64_smir_native` | `smir_jit_x86_aarch64`, `smir_jit_aarch32_aarch64`, or `smir_jit_thumb_aarch64` on an AArch64 host |
| AArch64/AArch32 semantics | `arm`, `arm_vfp_a32` as applicable | `arm_diff`, `arm_diff32` with native/QEMU oracle |
| RISC-V | `riscv_smir_lift`, affected library tests | `riscv_diff`, `riscv_vector`, `riscv_smir_x86_jit`, `riscv_smir_aarch64_jit`, `riscv_boot` |
| Hexagon | `hexagon_smir_lift`, affected library tests | `hexagon_diff`, `hexagon_cf_diff`, `hexagon_float_diff`, `hexagon_mem_diff`, `hexagon_hvx_diff`, `hexagon_hvx_mem_diff` |
| KVM backend | `kvm_minimal` | `differential`, `diff_fuzz`, release build on Linux x86-64 with `/dev/kvm` |
| PC/machine boot | `realmode_boot` or owning machine target | `microkernel_multiarch`, relevant boot fixture |
| Stateless oracle | `isa_oracle` | C API analysis tests and ISA differential target |
| CI/tooling | `ci_actions_pinned`, matching tooling target | run/parse the edited workflow or script |
| C/C++ API | `cargo test -p rax-capi` | `make -C capi test` |

When a row names multiple alternatives, select those intersecting the actual
change-surface map and document omissions. A target that is `cfg`-empty on the
current host provides compilation evidence only.

## 12. Validation ladder

Select commands from the owning change surface. Use `+stable` for CI parity
when the local default toolchain is not stable. Add `--locked` when validating
that dependency state must remain unchanged.

### 12.1 Cheap checks

```bash
git diff --check
cargo +stable fmt --all --check
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --lib
```

The Intel macOS portable CI lane currently omits `smir-jit`; use its exact
feature selection for CI parity. The x86-64 trampoline has Mach-O-specific
assembly support, so targeted macOS x86-64 JIT builds and execution are separate
validation paths, not coverage established by that CI lane. Execution through
Rosetta exercises emitted x86-64 code but is not a physical-x86 architectural
oracle.

### 12.2 Targeted integration tests

```bash
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --test x86_64 test_name_substring
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --test arm test_name_substring
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --test isa_oracle
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --test smir_jit_vcpu -- --test-threads=1
```

Replace `test_name_substring` with the intended Rust test-name filter. Do not
copy a test filename into `--test`; use the target name declared in
`Cargo.toml`.

### 12.3 Primary CI gates

```bash
cargo +stable fmt --all --check
cargo +stable clippy --all-targets --features x86_64-suite
cargo +stable build --all-targets --no-default-features --features x86_64-suite,smir-jit
cargo +stable test --doc --no-default-features --features x86_64-suite,smir-jit
```

Default-feature Linux x86-64 validation additionally covers KVM compilation:

```bash
cargo +stable build --all-targets --features x86_64-suite
```

### 12.4 Broad self-contained suite

`make test` runs release-profile tests with `x86_64-suite` and
`--include-ignored`. It is expensive and may include diagnostic/backlog tests.
The scheduled self-contained CI shards are defined in
`.github/workflows/full-suite.yml`; use their exact target sets when a more
controlled broad run is needed.

Broad SMIR or cross-cutting CPU changes should cover:

- library unit tests;
- the affected direct ISA suite;
- lift/interpreter tests;
- affected optimizer/lowerer/JIT targets;
- the relevant differential suite;
- doctests and all-target build.

### 12.5 External-oracle and host-gated suites

Use the exact setup and skip policy in:

- `.github/workflows/differential.yml`
- `.github/workflows/kvm.yml`
- `.github/workflows/sanitizers.yml`

Representative commands:

```bash
cargo test --features x86_64-suite --test differential -- --include-ignored --nocapture
cargo test --features x86_64-suite --test x86_64_avx512_kvm_diff -- --nocapture
cargo test --no-default-features --features x86_64-suite,smir-jit --test arm_diff -- --include-ignored --nocapture
cargo test --no-default-features --features x86_64-suite,smir-jit --test riscv_diff -- --include-ignored --nocapture
```

These commands can succeed without useful oracle coverage on the wrong host or
without tools. Report actual execution, not only exit status.

### 12.6 Other packages and products

C API:

```bash
cargo +stable test -p rax-capi
make -C capi test
```

Microkernel:

```bash
./microkernel/build.sh all
MICROKERNEL_REQUIRE=1 cargo test --no-default-features --test microkernel_multiarch -- --nocapture
```

ASL parser:

```bash
cargo test --manifest-path tools/asl-parser/asl-parser-rs/Cargo.toml
```

Root `cargo test` does not substitute for these.

### 12.7 Performance work

Establish correctness before measuring throughput. Use release builds and record
host CPU, OS, Rust/LLVM version, feature set, `RUSTFLAGS`, JIT switches, guest
workload, warm-up, repetitions, and statistic. Compare identical binaries and
inputs; report dispersion, not only the best run.

```bash
make bench
RAX_NO_JIT=1 RUSTFLAGS="-C target-cpu=native" cargo run --release --example bench_loop
```

Use `make pgo` only for an explicit PGO task; it intentionally trains and
rebuilds host-specific release artifacts. When changing the PGO script, run
`cargo test --test pgo_build_script --test pgo_script_safe`. A faster result
with altered guest state, instruction count, exception behavior, or fallback
rate is not a valid performance improvement.

## 13. Platform and false-green hazards

- KVM targets may compile to no tests outside Linux x86-64.
- JIT targets may return early or be `cfg`-empty on an unsupported host.
- Differential tests may print a skip and return success when QEMU, LLVM,
  cross-compilers, `/dev/kvm`, or CPU features are absent.
- `#[ignore]` may mean expensive oracle coverage, known backlog, or developer
  inventory. Inspect the test before using `--include-ignored`.
- Generated data being present does not prove its runner is registered or
  reachable.
- A filtered Cargo invocation can run zero tests and return success. Read
  `running N tests`.
- The release profile disables overflow checks and debug assertions; CI also
  configures dev/test to approximate release run semantics. Run debug-checked
  tests when arithmetic changes, then test the CI/release semantics.
- Host-native floating-point and SIMD behavior may depend on host features or
  control state. Reset and compare that state explicitly.
- The root x86-64-v3 rustflag changes the host baseline on x86-64. Do not mistake
  a host illegal-instruction failure for guest semantic failure.
- Warnings are allowed globally. Search for exhaustive call sites and semantic
  omissions even when the compiler is silent.

## 14. Unsafe code, concurrency, and serialization

Any new or changed `unsafe` block requires a local `SAFETY:` argument proving:

- pointer provenance and lifetime;
- bounds and alignment;
- initialized representation;
- aliasing and mutability;
- thread synchronization;
- platform/ABI assumptions;
- unwind behavior across FFI or JIT boundaries.

Prefer existing guest-memory and runtime helpers to raw pointers. Test boundary,
misalignment, fault, and concurrent/re-entrant cases proportional to the risk.

For shared state:

- document lock ordering;
- do not hold locks across guest callbacks, hooks, blocking I/O, or re-entrant
  APIs unless the contract proves it safe;
- use deterministic state transitions in device and snapshot code;
- treat serialized `CpuState` and emulator state as compatibility surfaces;
- distinguish architectural state from implementation-private counters/caches
  when using `set_state`, `update_state`, reset, and snapshot restore.

## 15. Provenance and documentation

For architectural claims, cite the exact local primary source and section/table
when available. Primary repository references include:

- Intel SDM:
  `docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`
- Intel AVX10 specifications:
  `docs/specifications/x86_64/355989-intel-avx10*.pdf`
- ARM ASL sources:
  `docs/architecture/arm/asl/`
- RISC-V specifications:
  `docs/specifications/riscv/`
- Hexagon manuals:
  `docs/architecture/hexagon/`
- SMIR implementation contract:
  current `src/smir/`, with derived documentation under
  `docs/specifications/smir/`

Do not cite a document merely because its filename looks relevant. Verify the
claim in the document. Do not fabricate a section number, DOI, revision, command,
or generator lineage.

Update documentation when changing:

- public behavior or CLI examples;
- module ownership/path;
- feature/platform support;
- C ABI;
- generated-corpus provenance;
- deliberate deviations from an ISA;
- test or CI commands.

Use current `path:line` citations in the final handoff for code evidence, but
do not bake volatile line numbers into durable architecture prose unless needed.

## 16. Debugging and reproducibility

- Minimize failing instruction streams and initial state before editing broad
  semantics.
- Capture exact guest bytes, PC, register/system/vector state, relevant memory,
  feature configuration, host triple, toolchain, oracle version, and environment
  switches.
- Use `RUST_LOG=debug` or narrower tracing only after locating the responsible
  subsystem; avoid logs too large to inspect.
- For JIT discrepancies, compare: direct interpreter, SMIR O0 interpreter,
  optimized SMIR interpreter, lowered bytes, and native result.
- For decoder discrepancies, compare direct decode, SMIR lift decode, and oracle
  output from identical bytes/address/mode.
- For intermittent failures, establish whether nondeterminism comes from guest
  state, host scheduling, shared global state, randomized input, or an external
  oracle before increasing retries.
- A retry can characterize flakiness; it cannot convert a failure into evidence
  of correctness.

## 17. Final self-red-team and delivery

Before declaring completion, inspect the final current state rather than relying
on intent or earlier output.

### 17.1 Required self-red-team questions

- Which valid encoding, width, mode, lane, mask, privilege, or feature case was
  not tested?
- Could the new dispatch arm shadow an existing arm?
- Could an unsupported case now panic or execute partially?
- Are flags or status bits over-specified where the ISA leaves them undefined?
- Can a fault occur after an unintended state update?
- Can optimization remove/reorder an observable effect?
- Can native lowering clobber live guest/host state?
- Can the test pass by filtering, skipping, fallback, or comparing the
  implementation with itself?
- Did formatting/generation touch user-owned files?
- Does another execution plane still implement the old behavior?
- Did documentation or an inventory become stale?

### 17.2 Quality Gates

All must pass:

- **QG1 — Assumptions:** the Assumption Register is complete, stress-tested, and
  reconciled.
- **QG2 — Requirement coverage:** every explicit and derived acceptance
  criterion maps to implementation and direct evidence.
- **QG3 — Reproducibility:** units, calculations, encodings, commands, seeds,
  versions, and error bounds are consistent and reproducible where applicable.
- **QG4 — Contradictions/edges:** no unresolved contradiction or relevant edge
  case remains hidden.
- **QG5 — Provenance:** architectural and tooling claims have verified primary
  provenance; unknowns are labeled.
- **QG6 — Bounded expansion:** adjacent opportunities/risks are impact-labeled
  and kept out of scope unless blocking.
- **QG7 — Worktree integrity:** only authorized files changed; concurrent and
  untracked content is preserved.
- **QG8 — Behavioral evidence:** regression/new behavior is tested across every
  affected plane; false-green skip/filter/fallback paths were excluded.
- **QG9 — Repository consistency:** paths, test registration, features,
  generated provenance, public API, and documentation agree with current state.

### 17.3 Final report

Lead with the outcome. Include:

1. changed behavior and owned files;
2. tests/checks run, with pass/fail/skip counts or exact limitations;
3. Assumption Register status;
4. unrun gates and the concrete reason;
5. high/medium/low bounded-scope findings;
6. pre-existing or concurrent worktree changes left untouched.

Do not claim `all tests pass` unless all tests actually ran and passed. Do not
describe an unverified implementation as complete.
