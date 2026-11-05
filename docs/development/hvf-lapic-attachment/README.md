# Intel LAPIC attachment lock order

The movable Intel vCPU facade previously acquired native execution exclusion
and then asked its permanent SDK owner to lock the software LAPIC. A checkpoint
can hold that controller mutex before requesting native write exclusion. Those
opposite orders allow attachment and checkpoint capture to wait on each other.

Attachment now resolves the existing shared TPR handle on the calling thread,
releases the controller mutex, and then asks the SDK owner to bind the handle:

```text
attachment: LAPIC mutex -> clone TPR handle -> unlock -> native reader -> owner
checkpoint: controller mutexes -> native writer -> capture/publication
```

The owner receives no controller mutex to acquire. The existing handle retains
the canonical TPR identity when the controller register image is replaced.
Controller poisoning still fences execution with the same retained priority
failure. SDK work remains on the permanent owner. Handle extraction and rebinding
take constant time and auxiliary storage; lock/channel scheduling wait is not
bounded by an architectural latency guarantee.

The regression holds the controller mutex while attachment starts, then checks
that a separate checkpoint boundary can still be acquired. It releases the
mutex and joins both workers before asserting even under pre-fix behavior, so
a failing test does not leave the threads deadlocked. The pre-fix executable
failed this check: zero passed, one failed, 58 filtered, exit 101. The 50 ms
scheduling grace and 1 s observation timeout are harness parameters, not product
latency guarantees. The corrected complete owner target passed all 59 tests with zero failures,
ignored tests, or filtering. Formatting and Intel-target Clippy checks passed.
[Qualification](qualification.json) identifies the frozen executable and combined
source. Those tests ran before concurrent remote Windows changes were
integrated; all attachment-owned source/test files match the qualified bytes.
They do not establish isolated validation of the other pending backend changes.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: cloning the canonical handle preserves attachment semantics | TPR/CR8 coherence after binding and restore | Existing complete native-context owner tests exercise attached TPR and raw-record restoration | Confirmed by the complete 59-test target |
| A2: attachment cannot retain native exclusion while waiting for the controller | Absence of this checkpoint lock cycle | The blocked-controller regression must acquire a checkpoint boundary before controller release | Baseline failed; corrected focused and complete targets passed |

High-impact boundary: these tests use the SDK model and do not establish native
Intel guest execution or close the broader IRQ, private-state, SMP, or MMIO
findings. The independently dispatched native Intel candidate predates this
attachment change. Its result must retain that separate source attribution.
