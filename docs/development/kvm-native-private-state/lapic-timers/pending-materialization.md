# Exposing a queued LAPIC timer before capture

An independent native KVM control can move an expired one-shot interrupt into
the exported IRR without advancing the original guest. This is a candidate
capture prerequisite, not a timer-restoration fix or an enabled RAX producer.
The existing [settled-phase counterexample](README.md) remains unresolved.

```text
save MP state -> temporarily set HALTED -> queue entry-only signal
             -> KVM_RUN returns EINTR -> restore original MP state
             -> GET_LAPIC exposes the expired timer in IRR
```

The test process blocks the private signal in userspace. Its KVM entry mask
unblocks only that signal; it is already pending before entry. Cleanup removes
the KVM mask, consumes the notification and restores the caller's mask.
`immediate_exit` is zero. No guest trampoline or guest-memory patch is used.
The diagnostic owns its process signal dispositions; it does not establish the
production entry worker's cleanup contract.

| Control | Retained observations | Interpretation |
| --- | --- | --- |
| Signal alone, original MP state | IRR remains absent in 6/10 runs; GPRs and RAM remain unchanged | Signal alone is insufficient |
| Temporary HALTED, guest IF=0 | 10/10 complete; 5 move absent IRR to present | Candidate exposes previously hidden work |
| Temporary HALTED, guest IF=1 | 10/10 complete; 5 move absent IRR to present | Enabling guest interrupts does not advance this fixture |

The successful control compares all general and special registers, the restored
MP state and all 2,097,152 bytes of guest RAM. Each run has IRR bit 1 set in the
vector-`0x41` bank after normalization. Samples with IRR already present are
retained and counted separately. Subsequent source execution reaches the timer
handler. The independently created target also reaches its handler, using raw
LAPIC restoration; that is not a completed-EOI or full-state migration check.

The fixture uses one native CPU, an enabled unmasked one-shot, initial count
1,000,000 and a 100 ms expiry wait. Each observer entry has a 200 ms alarm; the
wrapper bounds each whole child process to 5 s. No timer-frequency conversion
or measured failure probability is inferred.

## Reproduce

On Linux x86-64 with GCC and usable `/dev/kvm`:

```sh
python3 docs/development/kvm-native-private-state/lapic-timers/materialize.py
```

The wrapper compiles the exact retained sources with warnings as errors, runs
the signal-only diagnostic ten times and the halted diagnostic ten times for
each IF value, checks the positive invariants and requires at least one actual
absent-to-present transition per IF value. Missing transitions fail coverage.
Negative-control observations are reported without requiring a stochastic
failure on every new host. Temporary executables are removed on every exit.

## Provenance and assumptions

[Linux v6.8 x86 KVM source](../references/linux-x86-v6.8.c) contains
`kvm_arch_vcpu_ioctl_run`, `vcpu_run`, `vcpu_block` and the LAPIC getter.
`immediate_exit` returns before `vcpu_run`; the loop processes pending timers
after a positive return from entry/block and before its signal-work check.
[LAPIC source](../references/linux-lapic-v6.8.c) defines
`apic_has_pending_timer` and `kvm_inject_apic_timer_irqs`. These sources explain
the candidate ordering; native results apply to the recorded Ubuntu kernel.
The exact cause of every signal-only result is not established here.

The [qualification record](materialization-qualification.json) lists assumptions,
falsification probes, bounded findings and original observations. The replay
record identifies the current source hashes and its independent rerun. Original
`.original.c` files match the initial raw records; active `.c` files expand error
branches for readability and are rebuilt by the replay.

High-impact remaining work is restoration that retains the original initial-count
register without introducing another interrupt, plus masked/periodic/deadline
timers, PIT phase, pending INIT/SIPI, nested state, coordinated peer preflight,
rollback and the actual first-entry gate. Physical Intel macOS remains untested.
None of the four original audit findings is closed by this control.
