# Native entry and the retained device clock

This internal composition extends the [first-entry gate](first-entry.md).
`Image::stage_resume_clock_with_timing` admits a VM wall clock and its saved
`ClockState` while the managed backend boundary excludes entry. It publishes
the software clock in a stopped runtime state and retains its owner beside
the canonical native clock image. The public native checkpoint producer
remains inactive.

The clock wire is unchanged. Stopped state belongs to the destination's
publication protocol, rather than to the source clock's selectable mode.
Captured elapsed nanoseconds, diagnostic ticks and pending notification remain
exact while publication is stopped. Integer rebasing and diagnostic reset do
not independently resume a stopped clock.

Retained `ClockEpoch` samples and software LAPIC timers now bind to the VM's
selected wall or retirement clock. A foreign ambient context cannot replace
their owner. Standalone models without a context preserve explicit host
`Instant` behavior. Complete restoration prepares device epochs against the
incoming clock base before publishing it. Legacy wall bundles supply their
historical nanosecond base for that preparation; their existing diagnostic
counter and notification behavior is preserved. Publication without a clock
import samples the live retained domain at publication.

At actual managed entry, the private worker validates that the retained
software clock is still stopped at its admitted phase. It applies the common
native TSC offsets and KVM clock, then resumes the device clock from the host
`Instant` sampled adjacent to that native rebase anchor. Setter work counts as
runtime. These host clocks are sampled independently; the native controls
bound the observation interval instead of claiming an atomic sample.

Readiness probes, owned I/O returns, deferred exits, powered-off calls and
userspace HLT polling leave both clocks staged. The retained software owner
cannot be detached or replaced by another clock while pending. A changed
software phase, lost CPU owner, incomplete setter sequence or failed worker
cleanup fences the managed VM before another CPU can enter.

## Validation and scope

The pre-change production-module harness ran eight controls: six passed, two
failed. Separate VM wall clocks incorrectly shared a domain, and a future host
sample incorrectly advanced a bound wall timer. After the change, all fifteen
module controls passed, including stopped import, repeated capture, delayed
activation, wrapping nanoseconds, retirement phase and standalone host samples.
Those direct module controls are iteration evidence; the complete affected
library binary and workspace gates remain required before publication.

The added physical-KVM controls exercise source-free JSON and binary native
images with 1, 2 and 4 CPUs, first entry on different CPUs, a prepared software
LAPIC timer, delayed publication, repeated stopped capture, HLT polling,
independent RDTSC observations, foreign-owner rejection, phase-change fencing
and retention after outer handles are dropped. Their execution status must be
reported from the qualification receipts, not inferred from test registration.

High-impact work remains: the public producer, native controller/PIT phase,
in-flight terminal state, and rollback of the original destination clock must
be composed before this constitutes complete VM checkpoint restoration. This
change establishes no Intel Hypervisor.framework execution evidence.
