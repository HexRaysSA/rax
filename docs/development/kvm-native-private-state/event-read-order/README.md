# Pending-exception read-order control

The installed Linux `6.8.0-138-generic` kernel does not reproduce a candidate
capture-order defect suggested by the retained upstream v6.8 source. In four
native setter/getter controls, CR2 and DR6 already have their expected values
when first read, before `KVM_GET_VCPU_EVENTS`. Production code is unchanged.

The [retained harness](run.py) compiles [probe.c](probe.c) with warnings as
errors, runs it against `/dev/kvm`, checks every observation, and removes its
temporary executable. [native.json](native.json) identifies the exact sources,
executable, compiler and kernel. Each cell uses a fresh VM and CPU. It enables
exception-payload support to queue a pending #PF or #DB, then selects the
capability state before sampling MP state, special registers, debug registers,
events, and the registers again. These are setter/getter controls; no guest
instruction, exception handler or RAX checkpoint is executed.

| Payload capability at observation | First CR2/DR6 read | Later CR2/DR6 read | Pending | Injected | Payload retained |
|---|---|---|---:|---:|---:|
| Disabled | Corresponding payload already materialized | Same value | 1 | 1 | 0 |
| Enabled | Original register values | Same values | 1 | 0 | 1 |

Both #PF and #DB exercise each row. The #PF payload changes CR2; the #DB
payload changes DR6. The unrelated register stays unchanged. All four cells
match; the receipt records actual duration in seconds. These finite controls
do not establish behavior on other kernel builds or every native exit path.

```sh
python3 docs/development/kvm-native-private-state/event-read-order/run.py
```

The harness requires Linux x86-64, GCC, Linux KVM headers and usable `/dev/kvm`.
Missing prerequisites fail the command. Compilation is bounded by 30 s and the
native child by 15 s. Four fixed cells use constant working storage, excluding
the compiler and captured output.

The existing [upstream v6.8 source](../references/linux-x86-v6.8.c) delivers
pending exception payloads from `kvm_vcpu_ioctl_x86_get_vcpu_events` when the
payload capability is disabled. The later
[documentation proposal](getset-ordering-2026-09.html) describes getter-order
constraints and changes to newer kernels. Its merge status is unknown.
[references.json](references.json) records source URLs, issuing authors,
retrieval time and hashes, including the separate upstream TSC-deadline getter
ordering fix. Neither source identifies the complete Ubuntu patch set used by
this control. The exact mechanism responsible for its observations is unknown.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| E1 | Only the events getter materializes a queued payload on the installed kernel | A current-host stale CR2/DR6 counterexample | Read both registers before and after events for #PF/#DB with capability disabled | Falsified in these controls |
| E2 | Enabled and legacy payload profiles expose distinct event representations | Future complete native producer must preserve its selected event contract | Repeat both exception classes with capability enabled; check pending/injected/payload fields | Confirmed within the four cells |
| E3 | Retained upstream v6.8 source identifies every behavior of the installed Ubuntu kernel | Exact source attribution | Match the full distro source and patch set | Unknown; no such equivalence is claimed |

High impact: complete private/shared/in-flight capture, timer phase,
coordinated restoration and the public KVM producer remain required. This
control neither repairs nor activates that producer. No audit finding is closed.
