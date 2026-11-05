# Common native clock activation at first entry

The [retained device-clock extension](device-clock.md) couples a stopped
software wall clock to this native entry gate.

The managed owner can now retain a restored unscaled TSC/VM-clock image until
an authorized native entry. `Image::stage_resume_clock` validates the stopped
target and stores its canonical phase without applying native clock setters.
The enclosing checkpoint producer must retain its writer boundary through RAM
and device publication. A second stopped bank capture preserves the queued
clock image rather than sampling elapsed destination publication time.

Managed host-slice entry checks the queued epoch under the normal reader
lease. A CPU that will actually enter releases its CPU/read guards, acquires
writer intent and VM write exclusion, then checks again. The writer lease
continues through the first private entry worker. That worker sets up its
entry signal mask and deadline before rebasing the complete managed CPU set,
immediately before its native attempt. Other managed entries remain excluded.
Later CPUs use the same installed epoch and do not rebase it again.

For each CPU, the retained clock helper applies:

```text
new_offset[i] = saved_offset[i] + saved_anchor - resume_anchor  (mod 2^64)
```

The common delta preserves exact inter-CPU phases. The helper also restores
the VM clock with its measured publication interval. Activation takes O(n)
work and temporary references for n configured CPUs, bounded by 255. Ordinary
entry adds one constant-time pending-clock check.

Register observations, invalid host durations, power-off returns, owned exit
returns and parked userspace HLT polls do not consume the epoch. A halted CPU's
immediate-exit interrupt-readiness sample also leaves it queued. Legacy public
CPU checkpoint hooks reject a queued native epoch because their register
projection cannot represent it. Public register overlays remain possible.

The worker upgrades every managed CPU owner and checks rates and in-flight
ownership before setters. Losing a CPU or introducing unmanaged descriptors
invalidates activation. Any activation error fences the whole native owner;
native setters can have modified a prefix. Worker panic or deadline cleanup
failure during activation also disables further managed entry.

The first writer already excludes every other managed CPU/SDK guard. The
worker may therefore retain the selected CPU's guard before locking the other
cores without a competing lock-order cycle. It never invokes a device callback.
The selected CPU guard is released before the enclosing writer lease; that
lease is released before reader admission reopens.

## Qualification and assumption register

The complete selected owner namespace passes all 21 cases, including the four
new first-entry controls, with zero failures or ignored tests. Other library
namespaces are filtered in that focused invocation; the full-library gate
remains required. The same candidate also passes the complete 15-case host-slice
and 31-case SMP targets with zero ignored or filtered tests. Selected access,
state, completion, CPUID and APIC namespaces pass 8, 16, 7, 4 and 4 cases,
respectively. Minimal VM, workspace and full-library qualification remain
pending. The preceding halt/CR8 candidate completed its native integration,
owner/state/completion, workspace Clippy/build, no-JIT and doctest gates. Its
queued unfiltered library run was superseded while idle; those completed
results remain separate from this changed candidate's required full gate.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| FG1 | Clock activation excludes stopped publication time | Retained clock helper and new managed entry gate | Source-free resumed time | JSON/binary decoding after destroying source owners, 150 ms publication delay, 1/2/4 CPUs | Guest RDTSC includes the delay or installed offset implies a resume anchor outside the first-entry call | Native control passes in the 21-case namespace |
| FG2 | Observation and parked calls do not authorize guest execution | Entry predicate and separate immediate-exit readiness path | Pending phase remains canonical | Invalid durations, IF overlay/readiness sampling, repeated HLT and power-off | Canonical image changes before wake/entry or public checkpoint silently omits it | Native controls pass |
| FG3 | One writer can activate every CPU before another enters | Writer-intent/exclusion order and retained worker scope | Shared CPU phases | First CPU 0 or the final CPU, then run every peer | Different offset deltas or a second rebase | Source-free native control passes |
| FG4 | A staged image must retain its managed owners | Weak registry plus wrapper-owned core/VM/RAM references | Entry after outer handles are dropped | Drop VM/RAM wrappers; separately destroy a required CPU | Freed backing/FD use, or guest execution after membership failure | Both native lifetime/failure controls pass |
| FG5 | Partial native publication must never allow entry | Clock setters can fail after a prefix; owner poison path | Failure containment | Lost-peer control and review of setter/error/panic cleanup | Guest can run after activation failure | Pre-activation failure control passes; post-setter failure injection is unrun |

The time assertion uses actual guest RDTSC and an independently sampled host
entry window. A second check infers the native resume anchor from installed
offsets, so a stale activation cannot pass merely because a host scheduler
delays the observation. These tests do not compare only an internal pending flag.

## Remaining full producer work

This is an internal composition facility. The complete public KVM private/shared
producer is still inactive. Kernel PIT/LAPIC phase ownership, terminal/deferred
state, complete rollback including the original destination epoch, all admitted
profile integration and actual complete VM-file continuation remain required.
The enclosing producer must also bind the software device clock and timer
activation to this same native epoch; the internal native gate does not install
that cross-domain binding by itself.
Physical Intel macOS HVF qualification is also outstanding. The gate does not
make raw LAPIC register images complete timer checkpoints.

Primary behavior and measured clock bounds are documented in the retained
[clock component evidence](../kvm-native-private-state/clock-rebase/README.md)
and the [native owner contract](../kvm-native-owner.md). The retained Linux
[x86 implementation](../kvm-native-private-state/references/linux-x86-v6.8.c)
and [KVM API](../kvm-public-state/references/kvm-api-v6.8.rst) define the native
interfaces. The existing source tags and immutable input maps identify each
qualification candidate separately.
