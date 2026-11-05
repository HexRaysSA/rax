# Intel HVF guest stepping at scalar MMIO boundaries

The scalar MMIO planner formerly rejected guest `RFLAGS.TF`. The common
retirement boundary already generated pending `BS` after successful intercepted
instructions, but IRQ/NMI injection could discard that pending guest trap.
Intel SDM revision 086, Volume 3C section 28.7.3 requires the previous-instruction
trap to precede either asynchronous event. Its injection rules explicitly clear
pending debug exceptions when the injected event is an IRQ or NMI.

Represented scalar MMIO plans now retain guest TF. Reads, arithmetic reads and
RMW replies reach the common retirement boundary after register/flag publication;
writes reach it after device acknowledgment. Incomplete and failed transfers do
not publish a host step completion. Successful completion clears RF, generates
BS when TF is set and BTF is clear, retains existing pending causes, and expires
STI/MOV-SS blocking. Host MTF remains independent of guest TF.

Both injection eligibility and actual injection now inspect pending guest debug
exceptions. An unblocked BS or enabled-breakpoint cause defers IRQ/NMI injection
without consuming the caller's event. Disabled B0-B3 status alone does not block
injection. Occupied event slots and existing interruptibility checks retain
priority. An SDK read failure propagates without writing the entry slot.

The change adds no serialized field, native-state format, register identifier or
C ABI layout. Pending inputs and outputs use their existing checkpoint records.
The SDK-owner controls destroy the source CPU and VM before decoding and restoring
the pending record into a fresh owner. Guest debug causes and the current host
step request remain independent throughout completion.

```text
device request -> saved pending transaction -> reply / acknowledgment
                                              |
                                              v
                                      publish registers/flags
                                              |
                                              v
                                      retire and retain #DB
                                              |
                              host step stop, if requested
                                              |
                                              v
                                  guest #DB before IRQ / NMI
```

| Plane | Coverage |
|---|---|
| Scalar MMIO planner | TF admission; existing instruction/effect/EPT validation |
| Native completion | Shared TF/RF/BTF, pending debug and host MTF boundary |
| Interrupt injection | Defer IRQ and NMI while a higher-priority debug trap is pending |
| Checkpoint | Existing input/output/debug records restored into a fresh owner |
| Instruction semantics, SMIR and JIT | Unchanged; existing arithmetic reference corpora replayed |
| Public ABI | No layout or identifier change |

The pre-fix complete MMIO target has 61 passes and two failures in the new TF
controls. The independent event target has 13 passes and one failure: accepting
an IRQ with a pending debug trap. Current qualification and actual gate counts
are recorded in [qualification.json](qualification.json).
The final targets additionally contain the width/mode and output-failure
controls, and the exhaustive debug/event arbitration matrix added after those
baselines; their final counts are 65 MMIO and 15 event tests.

The no-debug owner gate also exposed an older test-harness defect. Its direct
VMCS-map lookup panicked for an untouched exception bitmap, although the fixture's
read API returns zero. The same test assumed DebugState ended the entire record;
`RAXHVI03` appends a 44-byte deadline image after the inner context. The repaired
test uses the fixture read default and edits the inner debug field before the
versioned trailer. The qualification records the original 71-pass/1-failure run,
isolated corrected control, and complete corrected no-debug run separately.

The native consumer retains its previous 206 cases and adds 84 actual guest
controls: seven scalar actions, host stepping disabled/enabled, no restore or a
fresh owner restored before/after completion, and deferred IRQ/NMI requests.
Each case requires a real guest #DB handler to observe the exact post-MMIO RIP,
saved TF/IF with RF clear, DR6.BS, and an unexecuted subsequent marker. The same
caller-owned asynchronous event is delivered after the debug handler. A build,
SDK fixture or source inspection does not qualify these native guest claims.
Native execution status is explicit in the qualification.

## Native execution qualification

[Run 42106758650](https://github.com/HexRaysSA/rax/actions/runs/42106758650)
executed all 290 cases successfully at source
`f1cc2e5a3ce8cda2d3ee3df1d60906c171fdfdcc`. The
[native receipt](native-pass-42106758650.json) verifies all 4,493 engine inputs
against Git blobs and the current engine tree, all three consumer sources,
driver/support identities, artifact ZIP hashes and the signed executable hash.
The [unmodified execution report](native-execution-42106758650.json),
[ordered observations](native-observations-42106758650.jsonl),
[guest stdout](native-guest-42106758650.stdout),
[build report](native-build-42106758650.json),
[prepared identity](native-prepared-42106758650.json), and
[availability record](native-availability-42106758650.json) retain the evidence.

| Native partition | Cases | Result |
|---|---|---|
| Previous RAM, scalar MMIO, PAT, MSR, timer, double-shift and VMM controls | 206 | Passed |
| Seven 64-bit scalar actions x host step off/on x three restoration phases x IRQ/NMI | 84 | Passed |
| Complete ordered Boolean profile | 290 | Zero failed or missing cases |

All 84 new observations contain one guest debug-handler invocation, the exact
post-MMIO RIP, saved TF/IF with RF clear, DR6.BS, and an unexecuted later marker.
The guest then continues and receives the caller-retained asynchronous event.
The restored-owner cases destroy the original CPU/VM and transfer the private
CPU record to a new owner while retaining the test's guest RAM backing.
The previous profile also reruns the twelve 1/2/4-CPU startup/IPI, file
continuation, CPUID-topology and firmware-discovery controls.

The host is untranslated Intel i7-8700B on macOS 15.7.9, SDK 15.5, with
`hypervisor_guest=1`. This is nested Intel execution evidence, not a bare-host
qualification. The new guest cases use BTF clear. Independent
[SDK DEBUGCTL observations](../hvf-debugctl-sdk/README.md) do not establish
functional native BTF, even when field/MSR reads return 2. No full BTF, data/I/O
breakpoint, or unrepresented MMIO profile is inferred from this pass.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| D1 | Represented scalar operations neither branch nor explicitly modify TF/RF | Common completion boundary | Opcode/effect validation, all scalar widths and code modes; incomplete/failing transfers never retire | Locally confirmed |
| D2 | An unblocked pending #DB trap precedes IRQ/NMI and injection would discard it | Event deferral | BS/enabled-breakpoint/status/interruptibility/event-slot matrix; SDK failures; real guest saved RIP/DR6 and later IRQ/NMI | Primary and recorded nested TF profile confirmed |
| D3 | Restoring existing private records preserves the transaction and debug boundary without the source owner | Source-free continuation | Destroy source CPU/VM, decode private record, re-emit and complete once; native before/after-completion cases | Confirmed for the recorded CPU-owner/RAM-retention profile |

Each production decision uses O(1) time and auxiliary space. The test matrices
and retained records use O(N) time and space for N cases.

High-impact remaining requirements include data/I/O breakpoint synthesis,
unrepresented atomic/string/vector/segment/APX MMIO and PIO profiles, remaining
interrupt/controller coherence, and the complete original state/SMP/FP findings.
This component does not close any of the four original findings.
