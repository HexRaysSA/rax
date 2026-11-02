# AArch64 timer output publication across reset

A CPU reset that retains its GIC now retains the last successfully published timer output levels until the next timer poll reconciles them with the reset timer registers. A successful reset of an owned GIC clears the cached levels together with the controller. If that controller reset cannot acquire its poisoned lock, the output cache remains available for retry; the next system entry reports the publication error before retiring an instruction.

Previously, reset cleared the cache even when it retained the controller. With both timer controls disabled by reset, subsequent polls saw no change and could leave the old PPI asserted indefinitely. A separate defect wrote both timer inputs whenever either changed; this could clear a software-pending bit on the unchanged timer PPI. Publication now writes only the individually changed lines.

The baseline executed three regressions: zero passed, three failed. They observed both stale timer PPIs after reset, loss of the other PPI's pending bit, and instruction entry despite a retained poisoned timer output. The final tests cover bound VM-clock and unbound instruction-counter CPUs, owned/shared/absent controllers, poison/repair, target and peer IRQ mirrors, and a serialized private-core round trip.

## Publication frontier

```
Timer registers       Last published cache       Shared GIC
---------------       --------------------       ----------
armed, pending        asserted                    asserted
CPU reset disables    still asserted              still asserted
checkpoint saves      pending deassertion          old controller state
next poll             deasserted                  deasserted
next instruction      coherent input              coherent input
```

The cache records the external publication frontier. Resetting the architectural timer registers does not publish a controller update. A deferred synchronous native fault still takes precedence over a VM-clock timer poll. No new wire field, tag or file version is required: the existing private cache and GIC state already represent both sides of this transition. Old buggy captures that already discarded the cache cannot reconstruct the lost history unambiguously.

The software VMM polls online bound CPUs before selecting another instruction. Unbound/legacy cores drain the retained transition in their existing system-step timer update. No extra instruction retires and no new idle-clock advancement is introduced. Publication uses one existing controller lock and at most two PPI updates; only changed outputs are written. No lock is held across guest callbacks by the new code. The controller's existing per-update scan remains: one publication costs O(P * (32 + S)) time for P configured CPU interfaces and S configured SPIs, with O(1) added space. An unchanged coordinator refresh costs O(P); K changed lines add O(K * P * (32 + S)), where K <= 2P. No throughput claim is made.

## Owning machine evidence

The machine tests configure timer controls and the GIC through guest instructions and MMIO, then read GICR pending bits through a self-contained guest program. They save real 1/2/4-CPU files immediately after a full public CPU reset and before the owed output is published. Fresh file construction runs with the original kernel file absent. Source and restored execution must agree on complete target CPU state, coordinator and selected clock, while peer retirement counts stay unchanged. Virtual-only, physical-only and both-timer cases include software pending on the unchanged timer PPI.

A separate 2/4-CPU test executes guest HVC CPU_OFF, saves the off-CPU frontier, restores source-free, then executes guest HVC64 CPU_ON and reads the restarted PE's timer PPIs. A truncated final CPU record must leave live CPU state, clock and shared graph unchanged, and the original owed deassertion must still complete afterward.

## Qualification boundary

This repairs reset/publication and the unchanged-sibling input transition. It does not introduce a new representation for overlapping hardware and software sources on the same INTID, change GIC active/EOI policy, or qualify complete interrupt-source conservation. Full A32-FP, C-STATE, C-SMP and C-HVF scope remains open, including broader native/private/IRQ/replay profiles and physical Intel execution.

The public void reset API is unchanged. The poisoned owned-controller test qualifies retained timer publication and the next-entry error, not a new atomic whole-reset failure contract. Generic Timer102379_0100_02, GIC IHI0069H4.1 and PSCI DEN0022D primary copies are retained under docs/specifications/arm; exact paths, checksums, test commands and source/executable hashes are indexed in qualification.json.

## Final local validation

| Gate | Outcome |
| --- | --- |
| doctests-workspace-v2 | 0 passed / 0 failed / 5 ignored; 0 passed / 0 failed / 0 ignored |
| focused-timer-outputs-v2 | 7 passed / 0 failed / 0 ignored |
| owning-root-library-v2 | 11969 passed / 0 failed / 35 ignored |
| owning-arm-v2 | 46850 passed / 0 failed / 0 ignored |
| owning-arm_vfp_a32-v2 | 521 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_programs-v2 | 75 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_native-v2 | 0 passed / 0 failed / 0 ignored |
| owning-smir_jit_aarch32_aarch64-v2 | 26 passed / 0 failed / 0 ignored |
| owning-smir_jit_thumb_aarch64-v2 | 25 passed / 0 failed / 0 ignored |
| owning-checkpoint_cpus-v2 | 12 passed / 0 failed / 0 ignored |
| owning-checkpoint_resume-v2 | 10 passed / 0 failed / 0 ignored |
| owning-checkpoint_config-v2 | 1 passed / 0 failed / 0 ignored |
| owning-retired_clock-v2 | 13 passed / 0 failed / 0 ignored |
| owning-checkpoint_clock-v2 | 16 passed / 0 failed / 0 ignored |
| owning-retirement_clock-v2 | 10 passed / 0 failed / 0 ignored |
| owning-counter_ticks-v2 | 12 passed / 0 failed / 0 ignored |
| owning-retirement_budget-v2 | 14 passed / 0 failed / 2 ignored |
| owning-user_linux-v2 | 43 passed / 0 failed / 1 ignored |
| owning-capi-library-v2 | 241 passed / 0 failed / 0 ignored |

Formatting,all-target build/check/Clippy and without-debug/without-JIT compilation passed. Exact receipts and source/executable hashes are in qualification.json.
