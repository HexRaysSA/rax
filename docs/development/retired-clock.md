# Exact retirement clock and phase state

`TimingContext::with_mode(ClockMode::Retired)` selects an explicitly advanced
clock. The existing default constructor and VMM construction still select wall
time. `advance_retired(u)` advances by retired instructions or Hexagon packets;
it neither sleeps nor reads wall time. Its frequency is exactly
3,000,000,000 units/s. Advancing a wall clock is rejected before mutation.

For elapsed nanoseconds t, phase r in {0,1,2} retirement units and an unsigned
64-bit delta u, advancement is:

    q = u128(u) + r                 [retirement units]
    t' = (t + floor(q / 3)) mod 2^64 [ns]
    r' = q mod 3                   [retirement units]
    U' = (U + u) mod 2^64           [retirement units]

One SI second contains 1,000,000,000 ns. The selected rate therefore gives exactly
three retirement units per nanosecond. The u128 intermediate is at most
2^64 + 1, so every u64 delta is admitted without overflow or narrowing the input
domain. Integer elapsed time alone has a remainder r/3 ns, less than 1 ns; the
stored phase makes composition exact. Three advances of 1,000 units produce
(333 ns,1), (666 ns,2), (1,000 ns,0). Counters and nanoseconds retain explicit
u64 wrapping semantics; the independent phase survives either wrap.

`ClockState` records mode, integer nanoseconds, retired total, phase, diagnostic
ticks and pending notification. Import checks phase and source/target mode before
changing any field. Capturing/importing the compound state requires caller
quiescence of independent tick/notification writers. Advancement itself is
serialized by the context mutex, including concurrent worker advancement.

Integer `set_resume_base` deliberately clears the retirement phase and preserves
the retired total. Complete state import preserves the phase instead. Legacy
`reset` clears only diagnostic ticks and pending notification, leaving the
selected clock state intact. These are separate operations.

In a bound retired context, `timing::tsc()` exposes the exact wrapping unit
counter, including the sub-nanosecond units. Wall/unbound contexts retain their
legacy diagnostic conversion. This does not yet reroute every guest/backend
counter instruction or select a deterministic VMM execution policy.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| V1 | The configured model rate is exactly 3e9 retirement units/s. | Accepted execution plan and explicit constant; one-second and 1,000-unit composition cases plus an independent literal-rate model. |
| V2 | Phase survives arithmetic and integer-counter wraps. | u128 intermediate and explicit modulo arithmetic; MAX delta, nanos/unit wrap, all phases and seeded mixed deltas. |
| V3 | Full import preserves future clock behavior. | 104 resumed instances continue the 10,000-event trace; compare every subsequent result with an independent bigint total. |
| V4 | Admission precedes mutation. | Invalid phase values 3/4/255, mismatched modes and hidden wall phase/units must leave a retired target unchanged. |
| V5 | Independent tick/notification writers are quiescent for capture/import. | Explicit API contract; notification/tick preservation cases and completed worker joins. Full coordinator quiescence remains open. |
| V6 | Concurrent advancement commits the whole clock state. | Eight workers advance 8,000,000 units; exact final nanos, unit total and remainder are checked after joining. |
| V7 | This component does not select the VMM execution policy. | Existing constructors remain wall mode; scheduler, native counters and file/replay integration require separate changes. |

The independent Python model uses arbitrary-precision totals and checks all
320,000 bytes of a 10,000-event trace, including u64::MAX deltas and continuation
through 104 restored instances. It rejects 128 single-bit corruptions spanning
all four fields at 32 selected trace rows. This is a seeded campaign with boundary
cases, not an exhaustive enumeration of 2^64 inputs. The arithmetic bound above
covers the full delta representation.

Advancement, sampling and import are O(1) time and O(1) storage, excluding mutex
contention. The oracle is O(E) time/storage for E trace events. No instruction
latency or host/native performance bound follows from the modeled rate.

High impact: deterministic default selection, per-vCPU retirement accounting,
complete guest timer/counter routing, scheduler/worker/IRQ coordination, required
file timing sections, replay and native boundaries remain open. Medium impact:
integer rebasing loses phase by definition; exact continuation must use full state
import. Low impact: future clock rates require explicit arithmetic/format identity
and equivalent phase evidence.
