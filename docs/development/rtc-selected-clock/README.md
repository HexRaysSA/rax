# Selected PC and S5L RTC calendars

Both modeled guest RTCs now retain the VM clock selected before construction.
With `ClockMode::Retired`, CMOS time/date and UIP, CMOS alarm comparisons and
S5L PMU calendar reads use `2000-01-01T00:00:00Z` plus the owning VM's elapsed
nanoseconds. Host delay, host timezone and another VM's timing scope cannot
change that calendar. CMOS Wall mode retains host UTC; PMU Wall mode retains
its existing host local-time behavior and non-Unix/error fallback.

The origin is an explicit POSIX-style model policy with86400 seconds per day;
leap-second inputs are not modeled. It is not a physical battery-clock value.
There is no initial sample of host time in the retired calendar. One validated
retired instruction or Hexagon packet adds one third of a nanosecond under the
existing VM clock contract. Calendar reads do not add retired units or logical
time. The third-nanosecond phase remains in the saved VM clock. The shared civil
conversion is moved from the existing CMOS implementation with its function
body unchanged; an independent Python UTC datetime vector set checks Gregorian
boundaries, including years2000,2100 and2400 and the full modeled time range.

```text
retired calendar timestamp = 946684800 seconds + VM.elapsed_nanos
VM.elapsed_nanos          = wrapping u64 nanosecond counter
CMOS UIP                  = subsecond_nanos >= 999756000, unless SET is set
```

The u64 nanosecond counter has its existing modulo behavior: the selected date
returns to the origin on counter wrap. Before wrap, this origin spans years2000
through2584. Existing PMU year formatting clamps to00..99; its weekday remains
an existing zero-valued stub. Existing CMOS BCD/binary and12/24-hour formatting,
SET/UIP policy, mutable CMOS/I2C data and polling-based interrupt policy remain.
This change does not implement guest-programmable RTC offsets, precise periodic
IRQ frequency/idle advancement, PMU alarms or a physical chip calendar model.

Runtime clock references never enter private payloads. CMOS prepared restore
updates its existing owner; detached PMU restore explicitly rebinds to the
matching destination clock and retains the saved I2C command/data progress.
The complete VM clock commits before restored guest entry. An old destination
epoch is therefore discarded without adding it to a saved calendar. The stopped
VM contract still requires independent writers to remain quiescent.

| Private tags | Calendar restore admission |
| --- | --- |
| `RAXPCD02`, `RAXSLI02` | Bundle-selected Wall or Retired calendar. |
| `RAXPCD01`, `RAXSLI01` | Existing Wall behavior only; Retired restoration rejects before publication. |

The payload field layouts remain unchanged. New tags distinguish this calendar
contract from older host-backed images. Decoding and re-encoding a legacy image
preserves its old tag. Legacy Wall imports remain supported. Existing retired
PC/S5L files with old calendar tags are not silently upgraded or treated as
complete selected-calendar files. No source checkpoint is rewritten.

Two actual parent-engine guest-register regressions returned host dates under
selected retired mode. Repaired tests cover owned identity, fractional phase,
wrap, UIP, formatting, alarms and legacy admission. Actual CMOS IN/OUT guests
and PMU LDR/STR guests use1/2/4 prepared CPU contexts and complete saved files.
CMOS restores after source removal, observes a different old destination epoch
and checks legacy denial. PMU restores in a fresh process with source kernel/NAND
removed and destination timezone/family settings changed; it saves and restores
again after consuming part of the PMU response. Manually seeded prior clock
units are explicitly distinguished from subsequently executed instructions.
Prepared online contexts do not establish architectural secondary startup.

[qualification.json](qualification.json) records exact commands, test counts,
source/executable hashes, assumptions and bounds. Focused tests overlap the
unfiltered root library. No ignored hardware test is counted as executed.
Implementation-validation fixture corrections are excluded from parent-engine
behavioral regression evidence.

Default clock selection, deterministic idle/periodic-IRQ policy, external input
and entropy replay, complete backend/private/native state and physical Intel
qualification remain open. All four original audit findings remain partial.

A post-validation constructor-documentation correction preserves every
non-comment source line exactly. Its separate formatting/doctest build checks
and before/after fingerprints are recorded in the qualification.
