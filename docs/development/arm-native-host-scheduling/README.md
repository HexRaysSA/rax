# ARM64 native host scheduling

Apple Hypervisor.framework cancellation is host control, while guest WFI/WFE
continues to produce the existing guest Hlt exit. The native backend now opts
into the coordinator host-slice contract. It uses one checked Mach absolute
deadline across internal exits; expiration returns None without inventing a
guest halt, retirement, interrupt or debugger completion. A cancellation latched
while a CPU was idle is consumed inside that same deadline so successive turns
can actually enter the guest. Real pending input/output and shutdown exits keep
their existing priority. The legacy run method requests successive finite turns
until a guest exit, releasing request quiescence between turns.

The existing cancellation worker has a nominal period of 5 ms. Intervals below
5 ms, intervals outside the u64 nanosecond range, and clock conversion overflow
reject before entry. This is not a hard wall-time guarantee: host scheduling,
SDK and kernel latency are outside that period. An already blocked SDK call
cannot be guaranteed to return if cancellation itself fails. The first nonzero
SDK cancellation result is retained atomically and prohibits subsequent entry
and capture; success never clears the error. Healthy host control is not
serialized as guest state. No checkpoint version or public C layout changes.

Work per internal exit is O(1), storage and host stack are O(1); n internal exits
cost O(n). The existing worker retains one thread per native CPU.

## Evidence and limits

A signed Apple M4 Hypervisor executable reproduced the former false Hlt on a
guest that stores a marker and then only branches to itself. A candidate that
yielded immediately on cancellation subsequently failed the two/four-CPU marker
check; the correction consumes idle cancellation under the original deadline.
The complete 16-case physical test binary passed after that correction. Final
owning gates passed: 16 state cases with debug, 16 without debug, 7 ARM MMIO,
10 owner-policy and 14 run-loop cases, with no ignored or filtered cases.
Workspace format/check/build/clippy passed. Exact source identities appear in
[qualification.json](qualification.json).

Physical cases cover manual two/four-CPU turns, invalid intervals, pending MMIO
input delivery and genuine PSCI shutdown after idle cancellation. They do not
qualify end-to-end VMM AP startup, guest interrupt routing, deterministic clock
replay or complete native checkpoints. A separate physical MMIO observation
shows PC advancing before a read reply; that defect remains open in this group.
Physical Intel SDK/VMX and Linux KVM execution remain unqualified here.

The primary cancellation contract is the retained Apple SDK 27.2
[hv_vcpu.h](../../specifications/apple/hypervisor-sdk-27.2/hv_vcpu.h), the
hv_vcpu_run and hv_vcpus_exit declarations and discussion. A cancellation
requested while stopped makes the next run return without guest entry.

Subsequent native read-frontier, legacy-record and finite test-consumer
qualification is in [Native ARM64 MMIO load retirement](../arm-native-mmio-frontier/README.md).
