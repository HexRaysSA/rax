# Intel native host scheduling

The VMM selects an optional finite host-slice contract for native CPUs that
implement it. A host yield returns `None`; a real guest exit returns `Some`.
The coordinator advances its CPU cursor without inventing HLT, guest instruction
retirement or debugger completion. Backends without this optional contract retain
their existing dispatch; this component does not make their entry bounded.

Intel entry remains on its permanent SDK owner and holds admitted RAM backing
through the synchronous entry operation. The default coordinator interval is
10 ms. One deadline spans all internal CPUID/MSR/control exits in that turn.
Prepared I/O and debugger completions take priority over another entry attempt.
An actual returned I/O, debug or failed-entry reason is dispatched before a
later deadline check.

The SDK expects absolute mach ticks. With `numer/denom` nanoseconds per tick:

```
ticks = ceil(interval_ns * denom / numer)
end   = now_ticks + ticks
```

The u128 intermediate covers the multiplication and addition. The result must
fit u64 and must differ from the SDK FOREVER sentinel, u64::MAX. Conversion
rounding excess is nonnegative and less than one mach tick; this bound excludes
SDK/hardware timer granularity and host scheduling overhead. For the retained
Apple Silicon timebase 125/3, 10,000,000 ns converts to 240,000 ticks exactly.
Zero/oversized intervals and invalid timebases reject before native entry.
Hardware without the SDK preemption timer returns an error and fences later
entry; the coordinator never substitutes an unbounded run in that case.
This is an SDK-entry deadline, not a hard real-time completion guarantee.

The preemption timer belongs to the SDK. Pin-control bit6 is normalized only in
copied checkpoint/control-readback values; other client control differences still
reject. Both visible and hidden SDK timer models are covered. Each SDK entry
supplies either the finite deadline or the documented FOREVER value, preventing
an earlier finite deadline from becoming a later standalone run's policy. No
host deadline enters the guest record, and no serialized layout changes. Restore
validates the fixed pin policy without writing that field, so it does not rely on
the SDK silently masking a client write of its timer bit.

The final check that can skip entry runs under admitted memory before clock and
priority preparation. Once preparation begins, the same deadline is submitted to
the SDK even if preparation exhausts the interval. A skipped host turn therefore
does not consume a restored CPU's pending clock rebase.

Interrupted delivery with valid IDT-vectoring information currently requires an
unimplemented general reinjection contract. Entry fails closed and fences later
entry in that case. Failed-entry reasons retain priority over undefined/stale
vectoring data. Additional reason flags are not silently collapsed into a timer
yield. This does not implement general exception or event reinjection.

## Qualification boundary

The coordinator baseline observed two unbounded-entry failures. The corrected
coordinator cases passed 4/4. Complete affected backend binaries passed 202
tests; complete SDK-model targets passed 45 with debug and 43 without debug.
The full root library passed 11541 with 5 ignored, and the C API
library passed 225; 19 C/C++ consumers ran successfully. Workspace
format/check/build/clippy passed. Doctest commands executed no examples and
ignored five; exact counts appear in qualification.json. Counts overlap helpers.
The production ABI tool checks the actual Mach layout, field offsets and both
signatures against x86/Arm SDK compilers; swapped Rust fields fail both.
The retained SDK-model file tests cover 1/2/4 native CPU records and rollback.
Coordinator scheduling and SDK file/entry tests qualify separate edges; they
do not establish physical Intel SMP or a native guest file continuation.

Physical Intel execution is unavailable on the current Apple Silicon host.
Already-expired SDK return freshness, hardware timer visibility and full native
interrupt/reinjection behavior remain unverified. The original A32-FP, C-STATE,
C-SMP and C-HVF findings remain incomplete. Native Apple SME/FPSR restoration,
other backend scheduling/startup/clocks and deterministic replay retain their
previous open status.

## Sources

The retained [Apple hv.h](../../specifications/apple/hypervisor-sdk-27.2/hv.h)
defines `hv_vcpu_run_until`, Mach absolute deadlines, FOREVER and unsupported
timers. The retained [Mach header](../../specifications/apple/hypervisor-sdk-27.2/mach_time.h)
defines the timebase layout and calls. The retained
[Intel SDM](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
Vol. 3C Section 26.6.1/Table 26-5, Section 27.5.1 and Appendix C define
pin-control bit 6, timer operation and exit reason 52.

Component evidence and explicit assumptions are recorded in [qualification.json](qualification.json).
