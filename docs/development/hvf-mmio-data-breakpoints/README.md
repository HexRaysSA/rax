# Guest data breakpoints for scalar HVF MMIO

The Intel HVF path completed emulated scalar memory accesses without synthesizing
their guest data-breakpoint causes. A watched MMIO load could therefore return
its value and advance RIP without the required post-access #DB when TF was clear.
The previous guest-TF qualification does not establish data-breakpoint behavior.
SDM section 29.3.4 clears the pending-debug field on ordinary EPT exits; its
specified exceptions include MOV-SS blocking and certain asynchronous exits.
Preserving the old field alone does not synthesize the emulated access's trap.

The planner now retains the validated linear address separately from the device's
physical address. A four-slot DR0-DR3/DR7 matcher applies local/global enable bits,
read/write conditions and the 1/2/4/8-byte LEN encodings to the actual byte range.
Read-only accesses do not match write-only conditions. Stores and modifying
accesses do; the independent zero-count shift controls also establish write
matches when the stored value is unchanged. Instruction and port-I/O breakpoint
conditions do not become data-memory matches. RF does not suppress data traps;
guest TF and host MTF retain their independent completion paths.

Only relevant, enabled address registers are read. SDK read failures propagate;
staging failures, including a write that fails after mutation, prohibit further
execution. No device request is exported after such a failure. NMI/IRQ injection
remains blocked, following the existing Boolean API contract.

## Completion and checkpoint timing

After successful planning, the CPU creates its existing pending transaction and
retains the matched B0-B3 plus enabled-breakpoint bit 12 in the existing serialized
VMCS pending-debug field. Pending I/O excludes native entry, architectural state
overlays and asynchronous injection. The field acts as private deferred storage
under that exclusion: the guest cannot receive the trap before a successful
device reply or output acknowledgment and architectural retirement. DR6 remains
unchanged until actual #DB delivery.

```text
validated linear access + guest DR bank
                  |
                  v
pending device transaction + deferred data causes
                  |
         device reply / acknowledgment
                  |
                  v
publish result, flags and RIP; complete host step
                  |
                  v
guest #DB delivery before deferred IRQ / NMI
```

Private CPU records already include the pending-debug field, input/output
continuations, guest debug registers and failure latches. This change adds no
wire field, version tag, public register identifier or C ABI layout. The new
`Plan.linear` is a transient decoder result. The SDK-owner tests transfer both
pending and retired records after destroying the source CPU, VM and test RAM.
The restored destination uses its separately initialized RAM and retains its
current host-step configuration.
The separate native consumer replaces CPU/VM owners while retaining its guest
RAM backing; it does not establish a complete machine/RAM checkpoint by itself.

Stopped capture may retain a readable terminal record after an execution failure.
The SDK-owner controls distinguish read failures that prevent capture from
readable write-failure records: restoring those records must retain the execution
fence. An acknowledged device effect must never be redispatched.

## Evidence boundaries

The [independent KVM records](kvm-reference-v2.stdout) contain 336 actual Linux
x86-64 guest observations. [Provenance](kvm-provenance.json) retains host, source
and executable identities and resource cleanup. Widths 1/2/4 use scalar accesses;
width 8 uses SSE MOVQ accesses in a protected-mode guest. The production matcher
replays enabled DR6 causes from every record. Disabled B0-B3 status is excluded
from comparison as permitted by SDM section 19.2.3.

The owner regression uses the actual RAX API and substituted SDK storage; it
executes no native guest. A retained one-call reversal establishes the exact
missing-cause failure: 0 instead of 0x1001. The first full pre-fix owner run has
75 passes and one missing-field failure; its test read was corrected to honor the
SDK model's zero default. Intermediate test failures remain separate evidence.
The [local qualification](qualification.json) records 79 complete SDK-owner tests
with debug, 76 without debug, 142 tests across seven portable backend targets,
48 Python tooling tests and 16 CI policy tests. Build, Clippy and formatting pass;
Clippy emits zero warning lines. The doctest command passes with all five examples
ignored, so it establishes no executed examples.

The native consumer retains its previous 290 cases and adds 192 data-debug
cases: eight represented 64-bit actions x TF off/on x host step off/on x three
owner-restoration phases x IRQ/NMI. They require actual handler entry, exact
post-access RIP, combined data/BS causes in DR6, an unexecuted later marker and
subsequent delivery of the caller-retained event. Compilation alone qualifies
none of those new native claims.

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| B1 | The decoded scalar access has one validated byte range | Match original linear addresses before register publication | Physical aliases, bit-string address adjustment, every width/LEN/slot and boundary overlap | Portable and SDK-owner evidence; see qualification |
| B2 | Existing pending-I/O exclusion prevents entry or state overlays before completion | Reuse the serialized pending-debug field | Re-emit without entry; source-owner destruction; pre/post-completion restore; partial SDK failures and terminal records | SDK-owner controls; native status must remain explicit |
| B3 | VMX delivers enabled data causes at the post-access frontier and updates DR6 | Actual guest-visible trap and IRQ priority | Native consumer's exact saved RIP/DR6 and subsequent IRQ/NMI delivery | Primary contract confirmed; native execution is a separate gate |

Matching uses four watches and at most eight bytes: O(1) time and auxiliary
space. Aligned watch ranges carry architectural guarantees. Unaligned debug
addresses use LEN masking without claiming defined architectural results.

High-impact remaining scope includes port-I/O breakpoints, unrepresented
atomic/string/vector/segment/APX MMIO profiles, the independently unresolved
DEBUGCTL/BTF execution boundary, and complete backend/private/platform state,
startup, interrupt, clock and replay requirements. All four full findings remain
partial.

Architectural primary source: retained Intel SDM086 (December 2024), SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`,
Vol.3B 19.2.1, 19.2.3-19.2.6 and 19.3.1.2; Vol.3C 26.4.2, 28.7.3 and 29.3.4.
