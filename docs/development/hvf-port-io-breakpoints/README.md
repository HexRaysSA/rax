# Scalar Intel HVF I/O breakpoints

Scalar IN/OUT completion omitted guest I/O breakpoint causes. The complete
SDK-owner baseline has 79 passes and two failures: successful input and output
both retain zero instead of pending B0 plus enabled-breakpoint bit12 (0x1001).
The source and test inputs were frozen through that command. This is a
substituted SDK control, with no native guest execution.

The backend now reads relevant DR0-DR3/DR7 conditions and guest CR4.DE before
exporting an I/O request. It matches the zero-extended port's byte range with
DR7 R/W=10, local/global enables and LEN masking. Memory and instruction
conditions are excluded. DE-clear R/W=10 is architecturally undefined; this
backend selects no I/O match for that input. RF does not suppress the trap;
guest TF independently adds BS during retirement.

The matched causes use the existing VMCS pending-debug field under pending-I/O
exclusion. Input replies and output acknowledgments retire the instruction
before native reentry. DR6 is updated by actual guest #DB delivery. Existing
private records retain the deferred causes, transaction, raw debug bank and
failure latches; there is no new wire field, version or public ABI layout.

Pre-fix producers omitted the cause even while the scalar request remained
pending. Incoming admitted records reconstruct it from the saved port, width,
CR4 and DR0-DR3/DR7, preserving independent pending debug bits. Failure records
that remain terminal after publication and live-target rollback
retain their exact images. VM restore decides from the current debugger session
that it publishes, rather than a replaced captured debugger failure. The
regression first reproduced both lost causes with zero native guest entries. The SDK-owner
controls exercise both directions, all three widths, immediate/DX forms and
independent BS/TF across source-owner destruction. Additional regressions check
exact rollback and source/current failed/healthy debugger combinations. These are simulated old
records, not records emitted by a historical executable.

```text
validated I/O exit + matching guest DR bank
                  |
                  v
pending device request + deferred debug causes
                  |
       full input reply / output acknowledgment
                  |
                  v
result and RIP retirement; host-step completion
                  |
                  v
guest #DB before caller-retained IRQ / NMI
```

The portable controls cover 49,152 slot/enable/condition/LEN/width/DE/boundary
partitions. They also replay [972 Bochs model records](bochs-records.jsonl).
The [reference wrapper](bochs-wrapper.cpp) extracts unmodified function bodies
from the retained, pinned [Bochs source](references/bochs-crregs.cc); its register
shim executes no guest instructions. Disabled B0-B3 status is excluded from
comparison as permitted by SDM19.2.3. The source/license provenance is retained
beside the reference files. Production matching uses byte membership, rather
than copying the reference's interval implementation.

The separate [Linux KVM records](kvm-reference.stdout) contain 960 actual guest
observations. They report zero I/O causes, including 148 matches expected by
the software reference, while all 408 TF cases report BS. Therefore these
records do not establish I/O-match conformance. Upstream Linux v6.8's scalar
PIO handlers finish through instruction skipping with TF synthesis; this is
consistent with the observation, but is not proof of the exact Ubuntu kernel's
source lineage. The [published collector](../../../tools/hvf/intel_port_breakpoint_kvm.c)
returns success when collection completes; that status is not an architectural
conformance pass. Its original working basename was port-reference.c; its
source byte hash is retained in the observations. All owned remote build files
were removed after collection.

The SDK-owner matrix covers both directions, 1/2/4-byte transfers, immediate
and DX forms, guest TF, host step and fresh/pending/retired owner phases.
Source CPU, VM and RAM are destroyed before replacement. Additional controls
cover SDK reads/writes failing before/after mutation and all short input reply
lengths, including a later full reply after restoring the retained failure.

The native consumer preserves its previous 482 cases and adds 446 cases:
384 watched-port combinations, 48 inactive-condition controls and 14 rejected
short replies with source-owner replacement. Of the 384 positive cases, 96
clear only the saved pending-debug field before restoring the pending access,
simulating an old producer. The consumer requires a unique exact serialized
VMCS field and preserves the public projection. Actual guest #DB handlers record
RIP, flags, DR6 and guest-visible CR4. IRQ/NMI delivery follows the recorded
frontier. The native consumer retains its RAM backing across owner replacement;
it is not a complete machine/RAM-file continuation by itself.
CR4 is sampled only by the #DB handler. Inactive rows retain zero in that
observation slot; that value does not assert that guest CR4.DE was clear.

The 928-case extension is compiled/signed locally but has not yet executed on
native Intel. The historical 482-case run does not qualify the extension.
Complete local command results and the eventual exact-source native receipt
remain separate evidence. The [local qualification](qualification.json) records
89 debugger-enabled owner passes,85 without debugger support,146 portable passes,
48 Python tooling passes and the exact command/skip/warning results.

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| P1 | Qualified scalar exits identify one successful port byte range (SDM19.2.4-19.2.6) | DR7 condition/enable/LEN matching | All fields, immediate versus distinct DX, upper address bits and boundary ranges | Portable and independent software-model controls passed; native extension pending |
| P2 | Pending-I/O and retained errors exclude native entry before successful completion | Existing deferred-field/checkpoint carrier | Re-emission, source CPU/VM/RAM destruction, partial SDK failure, short/late replies | Focused SDK-owner controls passed; 89 debug and85 no-debug complete owner tests passed |
| P3 | VMX delivers pending enabled causes at the post-access frontier and publishes DR6 (SDM28.7.3) | Native guest trap and interrupt order | Actual handler RIP/DR6/CR4, independent TF/host step, restored owners and later IRQ/NMI | Primary contract established; 928-case native gate pending |
| P4 | Independent software matching is distinct from hardware execution | Bochs reference classification | Exact source/body hashes and retained raw KVM counterexample | Confirmed; no KVM I/O-conformance claim |
| P5 | Forward publication reconstructs pending causes using the effective debugger session, while rollback preserves its exact image | Older pending records and current debugger ownership | Missing cause plus independent BS; source/current failed/healthy debugger combinations and host step | Intermediate counterexamples reproduced; complete final targets and10-case subgroup passed |

Matching uses four watches and at most four accessed bytes: O(1) time and
auxiliary space. Aligned debug ranges have architectural guarantees; unaligned
inputs retain LEN masking without a defined-hardware-result claim. Comparisons
whose byte extent exceeds 0xffff are computational boundary controls, rather
than a peripheral-bus hardware qualification.

High-impact remaining scope includes string/REP I/O, further MMIO/control/
exception/reinjection profiles, unresolved DEBUGCTL/BTF, native ARM streaming
FPSR, complete backend/private/platform/writer coordination, startup, clocks
and replay. All four original findings remain partial. Medium-impact reference
limit: intercepted KVM I/O cannot serve as the matching oracle on the observed
host. No additional low-impact change is required for this group.

Architectural primary: retained Intel SDM086, December2024, SHA-256
6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73;
Vol.3B19.2.3-19.2.6/19.3.1.2 and Vol.3C26.4.2/28.7.3/29.3.4.
