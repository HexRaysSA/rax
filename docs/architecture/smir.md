[← Documentation home](../../README.md)

# SMIR and native execution

SMIR—Sigma Machine IR—is the shared intermediate representation between guest instruction semantics and several execution/analysis paths. It is not a replacement for the architecture-specific interpreter. It is an additional representation that can be interpreted, optimized, compared, and lowered to native host code where the admission rules allow it.

```text
x86-64 ─┐
AArch64 ├──► architecture lifter ─► SMIR module/block/op
Hexagon ┤                              │
RISC-V ─┘                              ├──► SMIR interpreter
                                       ├──► optimizer
                                       └──► native lowering
                                              ├── x86-64 host
                                              └── AArch64 host
```

The detailed language specification lives under `docs/specifications/smir/`. Source is authoritative when the specification lags an implementation change.

## Representation

The implementation organizes IR into functions, blocks, typed operations, values, control-flow frontiers, architectural state accesses, memory operations, helper calls, and explicit exits. The exact types and opcodes are defined by the source and specification; documentation should not invent a stable external ABI for internal IR structures unless the project commits to one.

Important semantic obligations include:

- preserving guest-width integer wrapping and extension behavior;
- representing flags or deferred flag calculations precisely enough for all exits;
- carrying floating-point environment and rounding requirements;
- preserving vector lane widths, mask behavior, and inactive-lane semantics;
- distinguishing guest memory from host memory;
- representing faults and replay-sensitive helper calls;
- making control-flow and state-commit boundaries explicit;
- not committing architectural state past a faulting instruction.

## Lifters

Each architecture-specific lifter translates a decoded guest instruction or region into SMIR. Coverage is architecture-dependent:

- x86-64 supplies the production hot-region path and newer vector/APX-specific lifting work;
- AArch64 supplies scalar, control-flow, floating-point, and expanding NEON lifting, with selected native AArch64 validation;
- Hexagon has broad scalar/HVX lift coverage tested against its interpreter;
- RISC-V has broad scalar, FP, vector, CSR, bit-manipulation, and crypto lift coverage tested against its interpreter.

“Lift complete” is only defensible when an executable source/manifest inventory defines the finite instruction set and the lift target rejects no reachable implemented instruction in that set.

## SMIR interpreter

The IR interpreter provides a second execution of lifted semantics. It is useful for:

- validating lifters independently of native machine code;
- comparing optimized and unoptimized modules;
- isolating lowerer bugs;
- running operations that have no admitted native form;
- testing architectural state adapters.

Agreement between the architecture interpreter and SMIR interpreter is evidence for the lifter/SMIR semantics. Shared helper code can create correlated failures, so external differential testing remains useful.

The x86 direct engine and SMIR explicitly share x87 data semantics in
`src/smir/interpret/x87/data.rs`, operating on raw 80-bit register values.
The direct wrapper supplies its own fault delivery and state-image accesses.
Their agreement tests check integration and lifting, while hardware/QEMU
comparisons are needed to test the shared implementation independently.

## Optimizer

The documented optimizer includes O0/O1/O2-style levels and transformations such as:

- liveness and frontier-aware state analysis;
- dead-code elimination;
- dead-flag elimination;
- copy propagation;
- constant folding;
- branch folding;
- simplification constrained by exits and observable state.

An optimizer may remove an operation only when no architectural exit, exception, callback, memory effect, or helper can observe it. Lazy flags require special care: an apparently dead flag calculation can become live at a later condition, push-flags, exception, or region exit.

## Native lowerers

The source contains native host lowering for x86-64 and AArch64, plus host/guest-specific adapters. Lowering includes instruction selection, register allocation, runtime helpers, executable-memory management, entry/exit trampolines, and state synchronization.

Executable memory follows a W^X discipline in the documented runtime: code is emitted into writable storage and transitioned to executable use without maintaining a permanently writable-and-executable mapping.

A lowerer supporting an operation does not automatically make that operation eligible in a production vCPU region. Admission also depends on:

- guest/host pair;
- runtime feature detection;
- representable flags and vector state;
- memory helper availability;
- fault/replay semantics;
- region frontiers;
- register-pressure and temporary requirements;
- machine integration;
- test coverage and explicit whitelist policy.

## Hot-region promotion

The integrated vCPU path counts back edges or region heads and promotes a region after it becomes hot. The process is:

```text
interpreter observes hot region
    → construct candidate region
    → lift to SMIR
    → optimize
    → apply guest/host admission gate
    → lower and allocate executable code
    → cache by code/state identity
    → execute native block
    → synchronize state or exit/fallback
```

A failed candidate must fall back to the interpreter without speculative guest-state corruption. Persistently ineligible region heads can be memoized to avoid repeated compilation attempts.

## x86 guest on x86-64 host

The documented production gate admits a broad scalar integer/control-flow core, eligible memory operations, and a whitelist of vector/crypto operations. Host ISA features are checked before emitting native instructions that require them. Guest MXCSR and floating-point behavior must be honored for admitted FP/SIMD operations.

FS/GS-relative memory and other complex accesses can use MMU/runtime helpers. A helper must return a clean fault or exit rather than allowing native execution to run past an architecturally faulting access.

A guest call can be represented as an interpreter call-out followed by native-region resumption. `RAX_JIT_NO_CALL=1` restores the conservative behavior in which a call terminates the region. `RAX_JIT_NO_MEM=1` disables memory admission; using both returns the path toward a register-only tier.

## x86 guest on AArch64 host

The integrated cross-host path is intentionally narrower. It maps the ordinary x86 GPRs onto AArch64 registers and bridges condition flags through PSTATE/NZCV plus explicit preservation of the remaining RFLAGS state.

Current documented rejection conditions include:

- memory operations;
- FP/SIMD;
- APX extended registers;
- unrepresentable flag contracts;
- virtual temporary requirements beyond the path’s mapping;
- operations without a safe state/exit model.

This is a selective native tier, not full x86 dynamic translation on Arm.

## AArch64 guest execution

AArch64 guest instructions can be lifted and lowered to AArch64 native code for the integrated/tested surface. Dedicated tests exercise scalar integer, scalar floating-point, NEON, and memory cases. An AArch64-to-x86 lowerer may be present as an emit-and-test foundation without being connected to an automatic live run loop; the two claims must remain separate.

## RISC-V state-backed regions

RISC-V uses cache-keyed straight-line regions over the architectural state object. Region boundaries avoid operations that cannot be replayed or committed safely. Native support includes selected scalar, memory, atomic, crypto, FP, and memory-free RVV operations on x86-64 and AArch64 hosts, while unsupported boundaries return to the interpreter.

## Hexagon lifting

Hexagon scalar/HVX instructions are lifted and interpreted through SMIR in the dedicated lift suite. Packet semantics impose an additional obligation: the lifted representation must preserve packet-old reads, forwarding, and packet-end commit rather than treating the packet as an ordinary sequential list.

## Self-modifying code and cache identity

Process address spaces (`user::mm`) also invalidate decoded instructions and
native regions when executable pages are written, unmapped, replaced, or lose
execute permission. CPU adapters apply the invalidation log before resuming.
A guest process fork discards inherited compiled regions and recompiles them
when hot; i386 compatibility code stays interpreted. These process contracts
are covered by `user::` library tests and `user_linux` and are separate from
whole-machine invalidation tests.

Native code must be invalidated when guest code changes. The x86 software MMU records writes to executable pages and evicts affected compiled blocks. Cache keys for region-based paths include the instruction bytes/encodings used to build the region. SMC-heavy workloads can mark a region ineligible to avoid compile/evict thrashing.

A frontier-less spin loop or region with no safe exit can be refused so native execution cannot indefinitely bypass VM polling and interruption.

## Runtime controls

| Variable | Effect |
|---|---|
| `RAX_NO_JIT=1` | Disable hot-region native promotion at runtime |
| `RAX_JIT_VERIFY=1` | On the supported x86-64 host path, re-execute/audit compiled-region results against the interpreter |
| `RAX_JIT_NO_CALL=1` | Make guest calls terminate candidate regions rather than using the call-out/resume path |
| `RAX_JIT_NO_MEM=1` | Exclude memory operations from native admission |

These are diagnostic controls, not stable API guarantees unless the project explicitly freezes them.

## Verification layers

The relevant test families include:

- architecture interpreter versus external oracle;
- architecture interpreter versus SMIR interpretation;
- optimized versus unoptimized SMIR behavior;
- architecture interpreter versus native lowerer result;
- vCPU hot promotion, cache, exit, and fallback behavior;
- cross-host x86-on-AArch64 state equality;
- RISC-V state-backed x86-64/AArch64 JIT equality;
- AVX10 round-trip and EVEX masking cases;
- runtime live verification on the supported x86-64 host path.

No single layer proves the whole pipeline. The strongest bug report names the guest bytes, initial state, host, feature set, selected path, native/fallback counters, and the first state component that diverges.

## Known limitations

- Native coverage is partial and guest/host-specific.
- Locked/RMW and double-width divide remain constrained where the IR/lowerer cannot model the exact contract.
- x86-on-AArch64 is currently register-only scalar.
- AArch64 live verification is not the same mechanism as `RAX_JIT_VERIFY` on x86-64 hosts.
- Native block-to-block chaining and broader cross-ISA live integration remain incomplete.
- A successful JIT test is evidence for its cases, not formal equivalence over all states.
