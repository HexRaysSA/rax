# LAPIC selected VM clock

A LAPIC constructed inside a retired `TimingContext` retains that VM's clock.
Host delay and unrelated thread-local clock scopes do not advance its timer.
Wall-mode controllers retain the existing explicit `Instant` behavior.

The modeled source is 1 GHz. For relative age `A` ns and DCR divisor `D`,
elapsed ticks are `floor(A / D)`. A periodic interval of `I` ticks has duration
`I * D` ns. Consuming expired periods retains `A mod (I * D)` ns and rebases
against the same sampled timestamp. This is O(1) arithmetic and storage per
controller, excluding mutex contention. The selected clock retains exact thirds
of a nanosecond; LAPIC observations use its integer-nanosecond source edges.

Complete controller images carry relative timer age and retain no live source
clock. Both legacy and complete VMM device capture also detach the binding; an
additional owning regression exercises those two actual capture paths with an
independently selected device clock.
Preparation anchors that age to the incoming clock epoch before publication;
controller replacement keeps the target VM's clock identity. Clock state then
commits its nanoseconds and fractional phase. Wrapping subtraction assumes less
than `2^64` ns between relevant logical observations. Whole-cycle gaps remain
ambiguous in the underlying clock representation.

The pre-change public-MMIO reproducer failed both selected-clock cases. The
unchanged reproducer passes against the freshly compiled RAX library and in
the standalone source-module harness. Eleven
owning regression cases cover frozen time, expiry, all eight divisors,
reprogramming under another ambient scope, source/target epoch separation,
clock wrap, fractional phase, wall behavior and legacy image binding. The exact
181-byte pre-change producer fixture decodes and re-encodes byte-identically.

Validation: the complete root library passed 11566 tests with
35 ignored; C API passed 225. Workspace formatting, check, build and
Clippy passed. Fresh C/C++ validation executed 19 programs and compiled seven ABI
objects against an identified engine with no optional features. One additional
physical Apple-Silicon native file test continued one, two and four CPUs through
the changed restore caller. Counts overlap across layers.

The complete ignored native CPU-profile module was not rerun for this device
change. Its independently reproduced streaming-FPSR failure remains open.
Physical Intel execution was unavailable. These results do not qualify a
retired-clock VMM: constructors still select wall mode and reject retired-mode
files. Deterministic default scheduling, native retirement accounting, RTC,
external-event replay and the remaining audit findings remain incomplete.

The [qualification record](qualification.json) contains assumptions,
falsification probes, exact source/executable provenance and remaining limits.
