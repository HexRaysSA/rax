# Exact counter conversion at a platform frequency

`TimingContext::counter_ticks(frequency_hz)` converts the context's sampled time
to a wrapping 64-bit counter at the caller's frequency in Hz. It samples integer
nanoseconds and the retained third-nanosecond phase under the same clock lock.
The read changes neither time nor saved state. Zero Hz returns zero.

For n nanoseconds, phase p in {0,1,2}, and frequency f Hz, the result is
`floor((3*n+p)*f/3,000,000,000) mod 2^64`. The conversion uses elapsed time and
phase, independently of the separately wrapping retirement-unit and diagnostic
counters. Integer rebase and checkpoint import therefore retain their existing
contracts.

The direct numerator can require 130 bits for full-u64 n and f. The implementation
uses `a=n*f`, `q=a/1,000,000,000`, `r=a%1,000,000,000`, then
`q + (3*r+p*f)/3,000,000,000`, finally reducing to u64. The first product is below
2^128; the second numerator is below 2^66. All intermediates fit u128. Before the
explicit counter wrap, flooring introduces less than one counter tick of error,
or less than 1/f seconds for f>0. Conversion uses O(1) time and space.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| F1 | Internal phase is zero, one or two. | Existing validated clock state and advancement invariant. All phases and restored boundaries are exercised; admitting a larger phase falsifies the invariant. |
| F2 | Full-u64 time/frequency products remain exact. | Proven u128 decomposition above; 10,000 cases use an independent Python bigint numerator. Any output mismatch or arithmetic panic falsifies exactness. |
| F3 | Time and phase are sampled together. | One existing clock mutex; concurrent advancement and reads must retain exact final counter values and valid bounds. |
| F4 | Reading a frequency does not reconfigure the clock. | No stores in the conversion path; compare complete saved states across frequency changes, diagnostics/reset and zero-Hz reads. |
| F5 | Platform counter frequency is caller-supplied policy. | This primitive does not route guest registers or select a platform model. A writable architectural frequency-advertisement register is not assumed to control the physical counter. |

Twelve public regressions cover 3 GHz phase visibility, 62.5 MHz and 10 MHz tick
boundaries, full-width constants, wraps, independent counters, rebase, checkpoint
continuity, diagnostics, wall-time bracketing and concurrent sampling. The
standalone producer emits 320,000 bytes over 10,000 complete cases; the independent
model rejects 64 one-bit field mutations. Predecessor controls establish that the
new conversion API was absent, with an existing-clock positive control.

High impact: platform-frequency identity, architectural counter/timer wiring,
deterministic coordination and native exact-budget proofs remain open. Medium
impact: frequency changes between reads change conversion results but do not
simulate a frequency transition history. Low impact: generic counter conversion
and the x86 exact retirement-unit TSC remain distinct explicit clock views.
