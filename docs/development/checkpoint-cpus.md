# Ordered represented CPU checkpoint contexts

Default bundle capture records every configured vCPU in stable ID order.
Each entry contains the backend's existing public `CpuState` and represented
`EmulatorState`. Restore validates every entry against its target backend before
assigning the first CPU or changing RAM/devices. A multi-vCPU bundle without this
required component is rejected by typed configuration and runtime restore. The
older base `Snapshot` API retains its CPU-0 projection contract for wall contexts.
Explicit retired VMMs require complete clock/coordinator/CPU/private bundle records.

Required tagged-v8 section 11/schema 1 starts with `RAXCPU01` and a little-endian
u32 count. A complete table of u64 public/private record lengths precedes all
payload pairs. Payloads use the existing fixed-integer bincode representation.
Count must equal the already decoded configuration and occupy the full supported
configuration domain, 1 through 255. Each nonempty record is at most 16 MiB; the
whole section is at most 1 GiB. Exact aggregate/table/file bounds are admitted
before payload allocation. Duplicate sections, optional aliases, wrong schemas,
late placement, trailing bytes, mixed architectures and conflicts with the base
CPU-0 public/private payload are rejected. Base-only readers reject the section
at its header, before reading payload bytes. Required extraction is explicit.

For C contexts and P serialized CPU bytes, capture/codec work is O(C + P), with
O(C + P) resident encoding/decoded state. C <= 255 and P is bounded by the section
budget. Backend validation and assignment costs depend on each backend's
represented register/vector state. Existing physical/media processing retains
its independent bounds. These are algorithmic bounds, not measured latencies.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| U1 | Ordered entries correspond to stable constructed vCPU IDs. | Runtime iterates its existing vector; distinct 1/2/4-context markers and the exact 255-count codec boundary expose omission/order errors. |
| U2 | Payloads mean exactly the existing backend representation. | Public x86 APX, XMM/YMM/ZMM, opmask/MMX/system and represented x87/lazy/private fields are compared bytewise; actual x86/AArch64/RISC-V context getters are also compared. Missing backend-private fields remain outside this contract. |
| U3 | Admission precedes mutation for represented emulator errors. | An invalid final x86 MXCSR and reserved final RISC-V privilege must preserve every earlier CPU and RAM. The RISC-V pure validator also probes the tohost lock before assignment. |
| U4 | Required state cannot disappear during parsing/extraction. | Malformed count/table/schema/order/alias/duplicate/truncation cases, CPU-0 conflict and base-only header rejection; independent literal packing checks every modeled payload byte. |
| U5 | Independent writers remain quiescent. | Explicit capture/restore caller contract; captures occur before guest execution in fixtures. Concurrent scheduling/DMA coordination remains open. |
| U6 | Native host setters can fail after admission. | Native rollback is unknown; emulator and codec evidence cannot establish KVM/HVF transactions. |

The same private-context observation algorithm is retained for actual predecessor
and current implementations. It uses existing runtime methods and test-only
access to actual constructed vCPUs. It records every target RAX after a bundle
roundtrip; it does not infer preservation from the source file alone.
Independent Python fixed-width packing covers all bytes of seven x86 contexts
across 1/2/4-context files and compares live restored register markers. A separate
file-resume oracle retains full physical/projection byte comparison and actual
missing-kernel RISC-V UART/shutdown execution, with the added CPU section checked.

High impact: full backend-private/platform/interrupt-controller/scheduler state,
per-VM timing, quiescence, native failure transactions, replay and actual SMP
execution remain open. The original CPU-table component did not implement
scheduling. The current [execution coordinator](execution-coordinator.md) selects online software CPUs;
creating/restoring several contexts alone does not establish SMP execution.
Medium impact: legacy multi-vCPU files cannot reconstruct omitted contexts and are rejected by
the expanded workflow. Low impact: future required components must extend typed
admission and explicit handling. Source receipts and validation counts live in
the audit ledger; no broader completion claim follows from this component.

The [S5L private producer](s5l-checkpoints/README.md) adds required versioned
backend records and resource-closed NAND, detached CPU preparation, shared UART
and physical RAM publication, and common elapsed-clock rebasing. Its 1/2/4
prepared-context continuation tests preserve the cold CPU0-only startup policy;
architectural S5L secondary startup and deterministic PMU RTC replay remain open.


[Explicit VMM clock construction](vmm-selected-clock/README.md) selects the saved
clock before constructing devices/CPUs and restores complete software retired
files with exact fractional phase. It rejects mismatched/incomplete timelines
before publication. The intended deterministic default, independent board clocks,
idle advancement, native accounting and full replay remain open.
