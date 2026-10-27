# Standalone AArch32 backend context

`Aarch32Vcpu::save_context` captures the standalone software backend at an
instruction boundary. `restore_context` decodes and admits a context before
publishing any changes. The target must have the same vCPU ID and matching
guest memory. Public `VCpu::get_state` remains the existing register projection;
it does not contain all banked or private state.

The context stores the actual `Armv7Cpu` structure, including every represented
bank, CPSR/SPSR, CP15 register, FP data/control/identification register, security
state, halt/branch state, and instruction width. It also stores the exclusive
reservation and retired instruction counter. Serialization is derived on the
owning state types, so adding a modeled field cannot silently omit that field
through a hand-maintained export list. A change to that serialized structure
requires a new format revision before published contexts can use it.

| Format field | Representation |
| --- | --- |
| Format/revision tag | Eight ASCII bytes `RAXA3201` |
| vCPU identity | Fixed little-endian u32 |
| CPU state | Declared Serde field order of `Armv7Cpu` and its state types |
| Exclusive address | Legacy-encoded `Option<u32>` |
| Exclusive access width | u8, in bytes |
| Retired instruction count | Fixed little-endian u64 |

The body uses the canonical legacy codec and is limited to 65,536 bytes. Unknown
feature bits, invalid current modes, oversized status fields, invalid instruction
or active reservation widths, trailing data, and mismatched identities are
rejected before mutation. Saved SPSRs may contain an uninitialized mode: merely
capturing them must not execute an exception return or normalize their bits.
An enclosing AArch64 PE's projected FP-access context is rejected by this
standalone API; that PE requires capture of its actual owning state.

The decoder's ARM/Thumb mode and the bridge's MMU configuration are derived from
restored CPSR/CP15 before subsequent instruction execution. A stale bridge fault
is cleared. The decoder has no separately configurable per-instance feature
profile in this adapter. Time and space are O(B) for B encoded bytes, bounded
by the body limit; no guest RAM is copied by these methods.

## Assumption register

| ID | Assumption | Basis and dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | Capture runs at an instruction boundary | Safe Rust cannot execute the same adapter through `&mut self` while `save_context` borrows it; this permits coherent local state capture | Capture after a guest control write, LDREX, WFI, and IT; compare resumed execution | 20 native adapter tests passed; prior Rosetta suite passed 19, with latest cross-target validation pending |
| A2 | Cached bridge/decoder state is derived | `step_one` refreshes MMU state before fetch and decoder state before decode | Restore a different Thumb state and continue its IT block; add translated-memory coverage before VMM integration | MMU and Thumb/IT continuation passed before generic bundle wiring |
| A3 | Guest memory belongs to the context owner | The adapter receives an externally owned `Arc<GuestMemoryMmap>` | Compare identical-memory uninterrupted/restored continuations; external writes invalidate that premise | Explicit caller precondition |
| A4 | The standalone backend has no enclosing-PE FP view | Its constructor leaves `fp_access_context` absent; the AArch64 projection owns that derived view | Reject a projected context before mutation | Enforced; adversarial rejection passed before generic bundle wiring |

## Evidence and boundaries

The two retained predecessor failures under
`rax-audit-work/four-findings-a32-private-state-negative` use guest writes to
CPACR and FPEXC. Public register restoration loses the denied access and permits
the following VADD. The new tests use those same guest words and require the
full context path to retain the fault, unchanged destination, and retirement
count. Additional tests cover all represented CP15 fields, banked-mode changes,
LDREX/STREX continuation, halt/wake, Thumb IT state, every truncated prefix, and
malformed-input nonmutation. LLVM's independent exclusive-instruction encodings
and the exact command are retained beside this document.

| Impact | Remaining boundary |
| --- | --- |
| High | Generic context transport is validated for the C API and actual S3C64xx VMM adapters; full writer coordination remains required |
| High | Other software/native backends and platform/interrupt/in-flight state still require complete capture and restoration |
| High | Shared-memory exclusive monitor coherence between CPUs is separate from preserving this adapter's existing local reservation |
| Medium | External guest-memory writers must participate in checkpoint quiescence |

This component does not close C-STATE or establish full machine restoration.
