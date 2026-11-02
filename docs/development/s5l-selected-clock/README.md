# S5L selected elapsed clock and checkpoint epochs

S5L boot and diagnostic heartbeat elapsed clocks now retain the VM clock selected
at construction. With explicit `ClockMode::Retired`, host delay and another VM's
ambient timing scope cannot advance or replace them. Wall mode retains its host
elapsed behavior. Heartbeat reset retains its existing clock owner.

`det_timer != 0` still uses the existing instruction-attempt/modeled-idle profile.
For `det_timer == 0`, the guest counter reads elapsed microseconds from the
selected clock and applies its existing speedup and multiplier modulo `2^64`.
This group changes the elapsed source, without changing those profiles or the
model's nondecreasing timer update and 256-instruction refresh rules.

Checkpoint capture uses one selected epoch for all scoped CPU clocks. A prepared
replacement rebinds suspended clocks to the destination owner's clock, even if
preparation occurs under a foreign ambient timing scope. A foreign publication
scope rejects before shared state changes. Existing elapsed image fields remain
`seconds: u64, nanos: u32`; no source pointer, host instant or clock identity is
serialized. Malformed fractional nanoseconds still reject.

```text
capture one source epoch -> serialize elapsed durations
admit incoming clock -> prepare destination-owned suspended clocks
                    -> publish RAM/UART + common incoming epoch
                    -> commit incoming clock -> resume guest
```

CPU publication precedes clock commit. Retired activation therefore uses the
incoming saved nanosecond value prepared before publication, rather than the
destination's old clock. Wall activation samples the first publication boundary.
All CPU clocks share that activation point; checkpointing before first entry
preserves elapsed durations without counting preparation or downtime.

For the existing model rate, three retired units add one nanosecond, retaining
fractional phase. Elapsed subtraction is unsigned modulo `2^64` nanoseconds;
observation gaps must be less than one complete counter cycle. Duration addition
saturates at Rust `Duration::MAX`. Each elapsed read/reset/bind costs O(1) time
and O(1) additional storage. Existing CPU/media/RAM capture costs are unchanged.
Clock writers must remain quiescent through stopped-VM publication. This group
does not introduce synchronization for independently mutating external clocks.

The actual parent engine failed two behavior regressions under host delay.
Repaired tests cover retained owner identity, foreign scopes, wrap, malformed
images, existing wall behavior, shared publication, and distinct old/incoming
clock epochs. A fresh-process test saves actual 1/2/4 prepared S5L CPU files,
removes source kernel/NAND directories, restores under conflicting family/timer
settings and executes guest loads from TIMER1 offsets `0x80` (high) and `0x84`
(low). The fixture seeds 3,000,001 retired units as prior state and measures
subsequent actual guest retirement separately. It checks a pre-entry recheckpoint
and in-place restoration from a different old epoch. Synthetic fixtures do not
establish physical ARM1176 timing or proprietary firmware conformance.

Exact commands, executable/source hashes, pass/fail/ignored counts, reconciled
assumptions and limits are in [qualification.json](qualification.json). Focused
tests overlap the unfiltered root library. Compiler fixture errors are excluded
from behavioral regression evidence. No ignored hardware tests are counted as
executed.

All four original findings remain partially validated. Default/idle clock policy,
Other board clocks, entropy, architectural secondary startup, native
retirement/full replay and physical Intel validation remain open. The unchanged
serialized elapsed fields retain the existing S5L image format.

[Selected RTC calendars](../rtc-selected-clock/README.md) now binds PMU calendar
reads as well; Wall host input and full replay remain separate requirements.
