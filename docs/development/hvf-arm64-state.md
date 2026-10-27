# Native ARM64 HVF current stack-pointer transfer

The ARM64 HVF adapter previously restored `regs.sp` to SP_EL0, then overwrote it
with `sregs.sp_el0`. Its getter always returned SP_EL0 as the current SP, including
EL1h. An actual native RAX predecessor probe reproduced the lost requested value
for EL0t, EL1t and EL1h through backend/GIC/vCPU creation and public state transfer.

The native getter now selects the exposed current SP from PSTATE. Restoration
prepares both banked values first, overlays the selected bank with the canonical
`regs.sp`, and preserves the inactive bank. EL0t and EL1t select SP_EL0; EL1h
selects SP_EL1. This adapter represents native AArch64 EL0/EL1 state; other modes
are rejected before its first native register write. The SDK accepted the initial
invalid-mode probe, so mode admission is performed by RAX rather than delegated
to a presumed SDK rejection. The original failed rejection assumption and corrected
observations remain in the audit evidence.

Native state-transfer methods now live in `arm64_state.rs`; the portable bank
policy is isolated in `arm64_stack.rs`. Public CPU structures and checkpoint field
layouts are unchanged. Other register transfers and unbounded execution remain
unchanged outside the explicit SP/mode changes.

Arm's archived AArch64 exception-model guide 102412, section 5.1.4, specifies
PSTATE-based stack selection. A separate SDK-native program executes
`ADD X0,SP,#0` followed by BRK and independently observes the selected bank for
all three supported mode encodings. No RAX stack helper participates in that
architectural control. The native SDK/host and raw observations are retained.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| S1 | Current SP is selected by the represented PSTATE mode. | Arm 102412 section 5.1.4 and actual native ADD-SP observations for mode encodings 0/4/5. Any different effective-SP value falsifies selection. |
| S2 | `regs.sp` is the canonical current-SP projection. | Existing software CPU state-transfer contract; deliberately disagreeing input projection and bank fields expose overwrite order. Native old/current library probes verify the resulting physical register values. |
| S3 | The inactive bank survives restoration. | Pure prepared pair replaces exactly one selected element. Full-width cases and native comparisons verify the other bank without alignment or truncation. |
| S4 | Unsupported modes are rejected before any native write. | The complete prepared pair is computed before the GPR loop. All 32 mode encodings and actual invalid-mode before/after public-state observations can falsify nonmutating rejection. |
| S5 | Native proof stays on the creating thread and within represented state. | SDK ownership requirement; each probe creates, operates and destroys its own VM/vCPU on one thread. The evidence does not establish worker migration, full private-state capture or rollback after unrelated SDK errors. |

Eight portable regressions cover mode selection, rejection, projection authority,
inactive banks, full-width values, unrelated PSTATE bits and seeded round trips.
The independent integer model checks 10,000 complete policy observations spanning
all 32 mode encodings, 640,000 bytes and 128 single-field corruptions. Separate
native predecessor/current probes exercise 12 SP cases and invalid-mode admission
per library, including exact complete public-state text comparison on rejection.

Selection and pair preparation use O(1) time and space. Native transfer retains
its existing register API call costs; the early mode check adds no native calls.

High impact: complete native private/system-register state, thread ownership,
IRQ/device checkpoint coordination and rollback after unrelated SDK setter failures
remain open. Medium impact: mode validation is deliberately limited to the
represented mode field; other hardware register constraints remain SDK-dependent.
Low impact: public state layouts and existing software-backend semantics remain
unchanged. This group does not implement native retirement budgets.
