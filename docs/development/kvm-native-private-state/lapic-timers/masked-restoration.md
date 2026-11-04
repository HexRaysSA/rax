# Masked expired-timer restoration counterexample

Temporarily masking the restored timer LVT does not generally prevent a
completed one-shot timer from firing again. A freshly created native target
can conceal this failure. The initialized, relocated control reproduces the
duplicate despite equality of all 1,024 exported LAPIC bytes.

The [native replay](masked-restore.py) uses the existing retained C control,
whose SHA-256 is checked before generating either variant. It links no RAX
implementation. The [qualification record](masked-restore-qualification.json)
contains 24 observations from the physical Intel Linux host in
[host.json](host.json), running Linux `6.8.0-138-generic`.

| Target preparation | Source phase | Raw restore: deliveries | Masked restore: deliveries | Repetitions per method |
|---|---|---:|---:|---:|
| Fresh, default APIC base | Completed through EOI and IRET | 1 | 0 | 3 |
| Fresh, default APIC base | Expired and materialized in IRR | 1 | 1 | 3 |
| Initialized, relocated APIC base | Completed through EOI and IRET | 1 | 1 | 3 |
| Initialized, relocated APIC base | Expired and materialized in IRR | 1 | 1 | 3 |

The source continuation requires zero deliveries for the completed phase and
one for the pending phase. It produces no subsequent delivery in the bounded
observation. Each source CPU, VM and RAM mapping is destroyed before its
destination is constructed. The destination receives copied RAM and native
records. These controls do not exercise RAX checkpoint files.

## Sequence and initialization boundary

The masked sequence installs the saved LAPIC record with timer-LVT bit 16 set,
temporarily sets MP state to HALTED, and runs with the already-pending private
entry-only signal used by the earlier [materialization control](pending-materialization.md).
It restores the source events, writes the original LVT through x2APIC MSR
`0x832`, and restores the source MP state. It preserves timer mode, vector and
initial-count register. The inherited output field `fake_nmi_pending` remains
zero: this variant does not select NMI delivery.

The initialized variant sets APIC base to `0xfee01000` on both source and
destination. Each new graph executes an owned initialization `OUT` to port
`0xe8` and completes that native output before any timer image is installed.
It then restores the initial GPRs and guest code. Destination initialization
precedes publication of the captured source RAM and registers; it does not
execute the captured guest continuation.

This real entry matters. Exploratory controls that only relocated the base,
or followed relocation with a HALTED signal entry, still concealed the
duplicate. The final replay retains the actual native-initialization case.

The retained [Linux v6.8 LAPIC source](../references/linux-lapic-v6.8.c)
sets `APICV_INHIBIT_REASON_APIC_BASE_MODIFIED` for a nondefault enabled base.
Its `apic_timer_expired` has an APICv-specific direct-injection path;
`apic_has_pending_timer` excludes masked LVTs. The retained
[x86 source](../references/linux-x86-v6.8.c) processes `KVM_REQ_APICV_UPDATE`
in `vcpu_enter_guest`. These definitions explain why initialization and
masking require separate controls. The APICv explanation is a source-based
inference; the probe does not directly read the kernel's private APICv flag,
and the Ubuntu kernel's complete patched source has not been matched here.

All 12 masked restores retain exact GPRs, SREGS, exported events, MP state,
LAPIC bytes and 2 MiB of RAM before continuation. Initial count remains
1,000,000 counts and current count remains zero. No timer frequency is inferred.
The initialized completed cases nevertheless introduce one delivery. Exported
register equality therefore does not establish timer-phase equivalence.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| M1 | Masking and draining the target removes the duplicate for all tested initialization states | Apparent success on fresh default graphs | Candidate restoration sequence | Initialized relocated source and destination | A completed source yields a destination interrupt after unmasking | Falsified in all three initialized completed cases |
| M2 | The initialized path exposes a different timer-injection path | Linux APIC-base inhibition and deferred APICv-update source | Interpretation of the initialization effect | Compare fresh and initialized controls | Direct kernel tracing contradicts the proposed path | Retained as an inference; private APICv state is not measured |
| M3 | Duplicate delivery is independent of replaying uncompleted source output | Explicit native output completion, EOI, IRET and source continuation | Timer-phase counterexample | Source-free reconstruction and second-delivery observation | Source itself repeats the handler or records differ before continuation | Confirmed within the recorded observations |
| M4 | The replay builds the exact observed sources | Parent-source guard, generated-source hashes and replay-script hash | Reproducibility | Generate and compile both variants with strict warnings | A source hash differs or a build fails | Confirmed for the retained replay |

## Replay and bounds

On Linux x86-64 with GCC, pthreads and usable `/dev/kvm`:

```sh
python3 docs/development/kvm-native-private-state/lapic-timers/masked-restore.py > masked-replay.json
```

The default is three repetitions of eight cells. The wrapper verifies the
counterexample, including the duplicate; successful replay is not a passing
production restoration test. Each guest delivery observation is bounded by
200 ms and each process by 5 s. Temporary generated C sources and executables
are removed. For R repetitions and B copied RAM bytes, work is O(R * B) and
working storage is O(B), excluding the retained O(R) observation records.

High impact: the masked sequence is unsuitable as a general production fix.
An owned timer-phase representation, a common stopped capture boundary and
coordinated first entry remain required. This result does not activate the
private producer or resolve periodic/deadline timers, PIT state, rollback,
other profiles or physical Intel macOS validation. All four original audit
findings remain open.
