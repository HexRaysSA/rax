# AArch64 instruction stepping across JIT promotion

The AArch64 adapter's `step_insn` previously entered the system JIT lookup and
back-edge promotion paths. A compiled region can execute many instructions in
one call. The legacy region counter does not report every dynamically executed
instruction, so a later budget-delta check could accept an overexecuted step.

An actual predecessor probe repeatedly requested one unit from a four-instruction
loop with a finite exit. On call 256, JIT promotion changed X0 and X1 from 64 to
4,095 and advanced to the loop exit while reporting one retirement. The raw trace,
exact source, matching libraries and `compiled` promotion receipt are retained.
An initial loop without an exit was ineligible for compilation; its source and
negative control output are also retained.

The adapter now requests an interpreted system attempt for `step_insn`, including
the diagnostic micro-engine path. The same system routine handles timers, IRQs,
wait states, exceptions and faults; the bounded entry bypasses region lookup and
promotion. An attempt may still return a zero-retirement state transition. User
mode retains its existing single-instruction path, including framed one-instruction
PAuth regions. Unbounded `run` retains its existing JIT policy. No persistent JIT
flag is toggled and no cache is discarded for this boundary.

The adapter's diagnostic stepping and exit translation live in `aarch64_step.rs`.
Eight public regressions cover diagnostic/full-machine modes, crossing the hot
threshold, direct stepping, 1,000-unit budgets, heterogeneous budgets, already
warmed execution and diagnostic faults. A library regression installs a runnable
compiled region, verifies one interpreted instruction while preserving cache
identity and the JIT setting, then executes that same region through normal system
execution. Its native-cache portion runs on AArch64 hosts with `smir-jit`; the
common interpreted portion also runs on other hosts.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| A1 | A multi-instruction region cannot implement one instruction. | Actual predecessor promotion trace overexecutes on call 256. Full PC, X0, X1 and retirement observations expose the difference even when a delta check does not. |
| A2 | The interpreted entry preserves system semantics. | Both policies share one system routine; only lookup and promotion are conditional. Existing IRQ, timer, fault, wait and PAuth suites remain required. |
| A3 | Bounded execution also bypasses a pre-existing cache entry. | The library regression installs and retains the same Arc-backed region, executes one interpreted attempt, then proves normal execution can still use it. Cache loss or native overexecution falsifies this result. |
| A4 | Both adapter modes retain exact observable boundaries. | Separate diagnostic/full-machine objects each execute 1,000 one-unit calls and the full 0/1/2/999/1000/1001 budget sequence. Any PC, register or count mismatch fails the independent integer model. |
| A5 | Existing unbounded and user execution policies are preserved. | Unbounded runs retain the old system entry, diagnostic fault translation is moved intact, and the user path is unchanged. Source comparisons and existing suites can falsify compatibility. |

The independent model checks 2,012 observation rows, 112,672 exact bytes and 8,006
retired units. One-bit mutations cover every field at both sides of the promotion
boundary, both adapter modes and final budget rows. These are selected execution
observations, not a complete private-state or SMP proof.

The interpreted boundary adds O(1) policy selection. A budget B retains O(B + 1)
step calls and O(1) scheduler scratch space. Disabling region entry for this API
changes its performance characteristics; no throughput bound is claimed.

High impact: deterministic default coordination, exact native-hypervisor budgets,
unbounded-region retirement accounting and complete platform/checkpoint/replay
state remain open. Medium impact: bounded calls execute interpretation even when
a compiled region is available. Low impact: the diagnostic helper split isolates
fault translation and stepping from adapter construction and state transfer.
