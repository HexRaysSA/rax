# KVM native entry and ownership

This change implements a finite KVM entry interval using a private worker and a
thread-directed CLOCK_MONOTONIC timer. The worker blocks signals in userspace;
KVM_SET_SIGNAL_MASK temporarily unmasks the selected timer signal only during
KVM_RUN. An expiration yields without fabricating a guest exit or retirement
count. Actual exits retain their native data and pending input buffer.

The production KVM backend now uses this entry policy and the retained native
handle wrapper. The complete four-case native target passes on abyss with
DEBUG/JIT enabled. Workspace, alternate-feature and API documentation gates
remain in progress. Two published public-state CI runs had 2 passes and 12
failures with the common XSAVE image-size/MXCSR-mask admission error. The
corresponding suite passes 14 cases on abyss. Diagnostics in `fb6eb3f06`
identified AMD-defined MXCSR.MM bit 17; the shared validator correction in
`4ddd5ef91` passes all 15 portable XSAVE module tests. Native GitHub confirmation
and final combined-source validation remain pending. This prerequisite does not
establish complete C-SMP or C-STATE behavior.

```text
caller -> worker blocks signals -> arm timer -> KVM_RUN
                                                |
                                    real exit / EINTR
                                                |
                              delete timer + reset mask
                                     |              |
                                   success       cleanup error
                                     |              |
                                worker exits    poison CPU
                                     |              |
                                     +----> caller <-+
```

The worker never restores an unblocked userspace mask. timer_delete does not
promise to remove an already pending signal; keeping it blocked until the
private thread exits prevents delivery through a process-global handler. The
backend does not install or replace such a handler. The native entry mask is
backend-owned; concurrent raw-FD mutation is outside the managed CPU's exclusive
borrow contract.

Intervals and absolute deadlines must fit Linux's signed 64-bit nanosecond
ktime_t domain. Conversion uses exact integer nanoseconds. CLOCK_MONOTONIC is
sampled in the worker; TIMER_ABSTIME prevents a relative addition from silently
saturating inside the kernel. Linux also saturates at the final whole-second quotient of KTIME_MAX; that
boundary rejects explicitly. Zero/oversized intervals reject before entry.
Pending uncompleted input also rejects before changing its buffer. Preparation
errors release any installed timer/mask. Cleanup failure or a worker panic
latches a failure that prohibits further managed entry.

Each call uses one joined worker and at most one timer: O(1) work and storage
outside native execution. Host scheduling can delay the observed return beyond
the requested interval. These deadlines do not define deterministic guest time.
Host worker IDs, signal masks and timer handles are not guest checkpoint state.

## Evidence and validation scope

The dedicated `kvm_host_slices` target is registered under
`tests/suites/backend/kvm/host_slices.rs`. Its four tests use isolated child
processes for signal-disposition checks and explicitly require native KVM.
They cover an infinite guest loop, zero/overflow preflight, PIO and MMIO input
completion across worker returns, output and HLT. The three host-entry tests failed against the baseline complete RAX library,
which did not implement the host-slice contract. The original three-test binary
passed through the exact module/factory type seam recorded in
`deadline-owning-seam-saturation-v6.json`. Production wiring now passes all four
cases, including raw-handle ownership. The initial MMIO fixture retained the
reset 64 KiB data-segment limit and faulted before its intended MMIO. A full
32-bit cached DS limit corrects that fixture while retaining its expected
address and input/output bytes.

`deadline-exact-module-absolute-v3.json` records the exact module SHA and actual
RAX KVM entry through a test type seam: 40 requested 2000000 ns turns, observed
2650595--15070196 ns, PIO continuation, retained caller mask/foreign handler, and
real cleanup-ioctl EBADF plus worker-panic injection. Both failures disable
subsequent entry and retain the original timer-object count. The surrounding
type seam is not the production KvmVcpu Cargo integration.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| D1 | KVM temporarily applies its own signal mask and returns EINTR before userspace delivery when the original mask blocks the signal | Handler-free interruption | Native default-disposition and existing-handler infinite guest turns; caller survives and handler remains operative | Confirmed on abyss; retained KVM API4.21 contract |
| D2 | The managed CPU borrow excludes foreign raw-FD entry/mask mutation | Timer/mask ownership | Concurrent supported entry through a shared FD would falsify the boundary | Retained managed API requirement |
| D3 | A private worker can return the actual input buffer while the owning CPU/FD stays live | Caller input completion | IN/OUT/HLT and MMIO sequences completed across workers; unchanged mapped ownership | Confirmed by the production native PIO/MMIO target |
| D4 | Worker cleanup errors must not permit another managed entry | Native lifecycle coherence | Real EBADF on an owned duplicate FD and injected worker panic, followed by reentry attempts | Exact-module failure-injection proof passed; normal production target passed |
| D5 | The native deadline must avoid signed nanosecond overflow and the kernel whole-second saturation boundary | Exact finite scheduling request | Zero, oversized interval, absolute-addition overflow and native saturation-horizon requests preserve PC and timer-object count | Exact-module full-target seam passed; primary Linux v6.8 headers retained |
| D6 | A native vCPU requires registered backing until its native FD and run mapping are destroyed | Retained raw-handle ownership | Drop public VM/RAM/backend handles; require the backing weak reference to stay live before entry, read the original byte, then require release after vCPU drop | Production native test passed |
| D7 | Excluding mutable dereference prevents safe replacement of the retained inner native FD | Ownership boundary | Attempt `&mut **cpu`; compare all mutable native methods with the pinned dependency; run the API compile-fail doctest | Historical compile rejection, ten-method inventory and final two compile-fail Cargo doctests confirmed |

## Primary sources

The retained Linux v6.8 KVM API in
`../kvm-public-state/references/kvm-api-v6.8.rst`, section4.21, specifies the
entry-only signal mask, EINTR and original-mask delivery behavior. Its
KVM_RUN/section5 documentation defines pending input/output completion.

The verbatim installed Linux man-pages6.7-2 sources are under `references/`:
`timer_create.2` defines CLOCK_MONOTONIC and Linux SIGEV_THREAD_ID;
`timer_settime.2` defines TIMER_ABSTIME; `timer_delete.2` explicitly leaves
pending-signal treatment unspecified; `pthread_sigmask.3` and `signal.7`
define per-thread masks and process dispositions. Linux v6.8 `kernel-types-v6.8.h`, `kernel-time64-v6.8.h` and
`kernel-ktime-v6.8.h` retain the signed nanosecond type, exact limits and
saturation rule. Copyright/license notices,
installed source paths, retrieval date and SHA-256 are retained in
`references/provenance.json`.

The independent [native I/O completion probes](native-completion/README.md)
retain scalar, MMIO RMW and six REP width/direction outcomes. They establish
required follow-on native completion behavior for the remaining producer; they
do not qualify complete RAX checkpoint restoration.

## Required remaining work

| Impact | Requirement | Blocks full goal |
|---|---|---|
| High | Actual VMM INIT/SIPI startup, APIC IDs/topology and scheduler/kernel MP-state coherence for1/2/4 native CPUs | Yes |
| High | Complete native CPU/shared/in-flight producer, coordinated rollback, RAM/controller/clock association and source-free continuation | Yes |
| High | Remaining A32/HVF profiles and physical Intel macOS execution | Yes |
| Medium | Per-call thread/timer overhead has not been benchmarked as a performance claim | No correctness claim depends on throughput |

## Native handle ownership

`KvmVm::create_vcpu_fd` now returns
`OwnedVcpuFd`. It retains the VM/RAM owner until the native FD and run mapping
have been destroyed. Immutable ioctls remain available through `Deref`; the
ten mutable native operations are forwarded explicitly. The wrapper omits
`DerefMut`, which would allow `mem::replace` to detach an unowned FD.

The low-level `KvmVm::vm_fd` escape becomes explicitly unsafe: native objects
derived from that borrowed FD must not outlive the VM/backing owners, and the
caller must exclude entry during native state/map mutation. The VMM's ordinary
registration path uses `register_memory`, which retains backing before the
first native slot operation. These Rust API changes are implemented; no C ABI or
checkpoint wire layout changes are introduced by this ownership wrapper.
Callers that explicitly require a bare mutable `VcpuFd` must migrate to the
forwarded methods or take responsibility through the documented unsafe escape.

`raw-owner-parent-red-v1.json` observes the complete current RAX implementation
release registered RAM after dropping its public VM handles while a raw vCPU
still exists. The regression fails at the ownership assertion before guest
entry. `raw-owner-exact-module-green-final-v2.json` runs the identical test through
the exact new wrapper and a VM-owner type seam: backing remains live, the native
guest reads0x5a and halts, then backing is released after CPU destruction.
`raw-owner-mutable-escape-negative-v1.json` records rustc E0596 for the attempted
mutable dereference. The complete production four-case Cargo target now passes, with the original
seam receipts retained as historical evidence. Complete broader qualification
and the host-specific whole-library failures are recorded below.

## Final native qualification status

The refreshed production export passes formatting, workspace all-target build
and Clippy, the alternate no-JIT/no-debug workspace check, both API compile-fail
doctests, all four native entry/ownership cases, all fourteen public-state cases,
all fifteen shared XSAVE cases, twelve workflow-owner cases and both minimal
KVM cases. The two doctests pass; five pre-existing doc examples remain ignored.
The corrected AMD-profile GitHub run41630404578 also passed its fifteen XSAVE,
fourteen public-state and two minimal cases plus the release build.

The complete unfiltered owning library suite finished with13132 passed,4 failed,
20 ignored and0 filtered in6020.27 seconds. Source and immutable executable hashes
were unchanged. Every failure matches the independently reproduced native host
baseline: two32MiB socket-buffer assumptions and two Linux6.19 netlink expectations
on the Linux6.8 host. This is not an all-green library result. The first
final focused-test driver passed a workspace-only feature to a root-only test;
that invocation failed before testing. The corrected root-only invocation passed
without restarting completed build/lint checks or the full library suite.
These results qualify the finite-entry/ownership component only. The original
four findings and full native checkpoint/startup requirements remain open.
