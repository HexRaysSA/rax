# SMIR Specification

Version: **2.0-source-synchronised**  
Source baseline: `HexRaysSA/rax` `master` commit `7ff6953e9919916632e4c321a64a14fb1fac1f73`  
Generated: `2026-06-14`

This folder replaces the older SMIR v0.1 specification. The prior specification described a planned three-tier execution stack and marked JIT tiers as future. The current implementation has moved materially beyond that: `smir-jit` is a default feature, native lowering infrastructure exists, x86-64 and AArch64 runtime trampolines exist in `lower/runtime.rs`, the opcode set has expanded substantially, RISC-V and Hexagon lifters include architecture-specific exact semantic escape operations, and the optimizer contains frontier-aware region liveness.

## Normative source order

1. Rust source under `src/smir/` at the baseline commit is authoritative.
2. The root `README.md` is authoritative for high-level project intent and integration claims, unless a source file is more precise or newer.
3. This specification is a derived document. Where this text and source disagree, the source wins.
4. Old files in `docs/specifications/smir/` are historical context only.

## Document map

| File | Contents |
|---|---|
| `00-status-and-scope.md` | Current implementation status, compatibility with the old spec, assumptions, and non-goals. |
| `01-architecture.md` | End-to-end architecture: lifters, IR, interpreter, optimizer, lowerers, runtime, and JIT integration. |
| `02-types-and-state.md` | Source architectures, IDs, registers, widths, addressing, operands, conditions, and execution context. |
| `03-ir-structure.md` | `SmirModule`, `SmirFunction`, `SmirBlock`, `SmirOp`, `Terminator`, calls, traps, phis, and well-formedness. |
| `04-opcodes.md` | Implemented `OpKind` taxonomy, semantic contracts, and operation-index groups. |
| `05-flags.md` | Lazy flags, materialization, RFLAGS/NZCV mapping, condition evaluation, and flag optimization constraints. |
| `06-memory.md` | Memory traits, access widths, address forms, atomics, exclusive monitors, fences, MMU helper lowering, and SMC. |
| `07-lifting.md` | Lifter trait, `LiftContext`, per-architecture lifting rules, and control-flow discovery. |
| `08-interpretation.md` | Interpreter cache, execution loop, operation execution, exceptions, and architecture-specific state access. |
| `09-optimization.md` | Optimization levels, frontier-aware liveness, dead flags, constants, DCE, branch folding, and invariants. |
| `10-lowering-and-codegen.md` | Lowerer trait, `CodeBuffer`, relocations, register allocation, x86-64, AArch64, AVX10, and state-backed lowering. |
| `11-runtime-and-jit.md` | `GuestRegs`, `Aarch64GuestRegs`, trampolines, W^X executable memory, native exits, helpers, and hot-block policy. |
| `12-cross-target-lowering.md` | How SMIR lowers one guest ISA to a different host ISA. |
| `13-safety-and-verification.md` | JIT whitelist, clobber gates, interpreter fallback, differential verification, and conformance obligations. |
| `14-implementation-layout.md` | Current source tree layout and ownership boundaries. |
| `15-change-log-from-v0.1.md` | Material deltas from the original v0.1 spec. |
| [16-aarch64-pointer-authentication.md](16-aarch64-pointer-authentication.md) | Keyed PAuth execution, feature gates, mixed-width exception return, persistence, native frontiers and validation; declares its own newer source baseline. |
| `PROVENANCE.md` | Source files, blob SHAs, assumptions, falsification probes, and quality-gate notes. |

## Terminology

The terms **MUST**, **MUST NOT**, **SHOULD**, **MAY**, and **DEFINED BY SOURCE** are used in the RFC 2119 sense, except that this folder is a repository-internal engineering specification rather than an internet standard.

## One-page architecture

```text
      source bytes / decoded instructions
        x86-64 · AArch64 · Hexagon · RISC-V · AVX10-visible forms
                         │
                         ▼
                per-architecture lifters
                         │
                         ▼
                    SMIR structural IR
          SmirModule → SmirFunction → SmirBlock → SmirOp
                         │
          ┌──────────────┼────────────────┐
          ▼              ▼                ▼
    interpreter     optimizer       target lowerers
   SmirContext     O0/O1/O2       x86-64 · AArch64 · state-backed A64→x86
          │                              │
          └──────────────┬───────────────┘
                         ▼
              runtime helpers / W^X executable memory
                         │
                         ▼
              interpreter fallback at region frontiers
```
