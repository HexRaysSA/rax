# Retirement clock publication at bounded execution boundaries

`VCpu::run_retirement_budget` publishes each validated successful retirement to
an explicitly bound `ClockMode::Retired` context before starting the next step
or returning its exit. The next instruction therefore observes all preceding
retirement units within the same scheduling quantum. This publication is
separate from the existing diagnostic tick and charged eBPF/SBPF meters.

The clock advances by one third of a nanosecond per instruction or Hexagon
packet at 3,000,000,000 units/s. Integer nanoseconds, retirement units and the
retained remainder use the existing full-u64 clock arithmetic. A retiring I/O
or halt exit advances once. Zero budget, unsupported stepping, failed attempts,
zero-retirement state transitions, invalid multi-retirement deltas and halted
reentry do not publish an additional unit. Previously committed units remain.

Wall-bound and unbound execution retain their time sources. Direct `step_insn`
and unbounded `run` calls retain caller ownership of clock advancement. Existing
VMM constructors still select wall time. Guest architecture-specific counter
routing and a deterministic VMM coordinator are separate work.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| T1 | Successful backend deltas represent retirement. | Existing budget checks admit only wrapping deltas zero or one; all twelve emulated profiles and malformed deltas are tested. A failed attempt or delta above one advancing time falsifies the result. |
| T2 | Publication precedes the next instruction. | A clock-reading backend records all 1,000 values inside one call. Any gap, duplicate or final-only advancement fails exact equality with 0..999. |
| T3 | Existing clock arithmetic preserves fractional phase and wraps. | The same clock advancement operation serves explicit and budget-driven calls. Restored phase two at u64 maxima must wrap to zero after one successful step. |
| T4 | Context selection is explicit and thread-local. | Nested retired/wall contexts must update only the selected retired clock; direct steps remain caller-owned. Any neighboring-context change falsifies routing. |
| T5 | Fault charge is distinct from retirement. | Actual eBPF and SBPF V0-V4 meters charge the fourth failing attempt while the clock records exactly three retired units. |

Ten owning regressions cover the contracts above. The standalone producer emits
72 observations over twelve backend profiles and 1,000 clock reads inside one
budget. An independent Python integer model checks 12,032 exact bytes and rejects
520 one-bit mutations. Old/current libraries execute the same consumer; the
predecessor's clock remains zero rather than tracking retirement.

For budget B, the loop retains O(B + 1) step calls and O(1) scheduler scratch
space. Each retiring step adds one thread-local lookup and one clock mutex
acquisition; no measured native throughput bound is claimed. The observation
fixture stores O(B) words because it records the within-call trace.

High impact: deterministic default policy, all-vCPU coordination, architecture
counter/timer routing, thread-safe interrupt delivery and native exact budgets
remain open. Medium impact: advancing an explicitly shared context serializes
its clock updates but does not establish deterministic worker ordering. Low
impact: direct backend users must choose the bounded API or own clock updates.
