# VM-owned timing context

Each VMM now owns a `TimingContext`. Construction, execution, public CPU-state
capture, base/bundle capture and base/bundle restore enter that context. Existing
timing-helper calls inside those boundaries resolve the owning VM's wall clock,
diagnostic tick counter and coalesced timer-pending flag. A successful restore
re-anchors only that VM's clock to the recorded nanosecond base, including a
repeated restore in the same process.

Standalone callers without a bound context retain the previous process fallback,
including its existing function signatures and conversion formulas. This change
does not replace wall time with retirement time. The diagnostic `timing::tick`
counter is also distinct from backend retirement counters and the separate x86
published instruction count.

`Vmm::timing_context` supplies an Arc for explicitly managed workers. Enter the
context on each worker; thread creation does not inherit a binding. Contexts are
Send + Sync, while a scope guard is bound to its thread. The current thread uses
the latest surviving binding. Dropping guards out of order removes only the
matching binding; unwinding restores the remaining context. TLS borrows end
before clock operations, allowing nested calls. Clock anchors use a mutex;
diagnostic ticks and pending notification use atomic operations. A pending flag
coalesces notifications, preserving its previous Boolean contract.

The same existing-API consumer is compiled against the actual predecessor and
current libraries. It constructs two VMs and restores a synthetic
1,000,000,000,000,000 ns = 1,000,000 s offset into one. The predecessor also moves
the unrelated VM by that offset. The corrected implementation keeps the unrelated
VM on its own clock and gives the offset only to the restored VM. Recorded wall
timestamps are observations; their exact values are not predicted.

The independent model checks 96 exact counter/notification bytes and 32 observed
wall-timestamp bytes using isolation/monotonicity bounds. It rejects mutations
in all twelve modeled counter/flag words and four violated wall-time predicates.
The 12 owning regressions additionally cover actual VMs, explicit shared workers,
independent workers, nested/out-of-order scopes, unwinding, reset, repeated base
replacement and failed restore.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| T1 | VMM timing-helper consumers run within the owning context. | Six runtime methods and construction are bound; actual two-VM restore comparison and caller-scope sentinel expose an omitted boundary. |
| T2 | Workers bind explicitly. | Thread-local stack and cloned Arc; eight workers share 8,000 ticks, separate workers retain separate counters and notifications. |
| T3 | Guards cannot leak or replace another active binding. | Unique Rc token per entry; nested, out-of-order drop and unwind tests. A guard is not Send. |
| T4 | Existing unbound behavior remains available. | The original fallback bodies/statics and public signatures remain after the routing additions are removed. Source-normalized comparison and inherited full suites are required. |
| T5 | Clock observations stay within the test's isolation domain. | A synthetic 1,000,000 s offset separates fresh local clocks from the restored one; producer execution is bounded to 60 s. Exact wall-time values remain unknown before observation. |
| T6 | Restore admission precedes anchor replacement. | Existing invalid-version admission plus caller-scope and target-anchor sentinels; a rejected restore must not install its proposed offset. |
| T7 | This context covers the existing timing helpers, not every time source. | Direct device/backend Instant sources, backend counters, native timers and standalone engine integration require separate inventory and changes. |

Clock reads, ticks and flag operations are O(1), excluding mutex contention.
Entering a scope is amortized O(1). Dropping a guard searches/removes one entry
from D nested scopes in O(D), using O(D) thread-local storage. The context uses
fixed-size anchor/counter/flag state. Wall nanoseconds retain the previous u64
wrapping representation. No latency bound is inferred from the short fixtures.

High impact: deterministic retirement time at the planned frequency, complete
per-VM timer/counter state, scheduler workers, native boundaries, standalone
engine context ownership and checkpoint/replay closure remain open. Medium
impact: future workers must carry the explicit context; direct time sources must
be audited before claiming complete clock isolation. Low impact: the mutex clock
read can be optimized only with equivalent anchor/scope behavior established.
