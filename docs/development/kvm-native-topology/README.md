# Native CPU topology and KVM clock discovery

Native VMM construction now establishes one immutable CPU profile before CPU
creation. Each CPU receives the configured geometry and its own APIC identity;
MP firmware uses the same projected signature/features. Previously only the
identity fields were projected: package/cache fields retained host geometry,
and the native topology leaf reported zero logical processors on the qualified
host.

The kernel also supplied the KVM signature and feature leaves while CPUID.1's
hypervisor-present bit remained clear. Linux therefore selected bare-metal
clock discovery and failed TSC/LAPIC calibration. The profile now enables KVM
detection when the supplied signature identifies KVM, including the documented
legacy signature maximum of zero. It preserves the kernel's complete feature
mask and its existing frequency interfaces. No synthetic crystal ratio is added.

| Interface | Projected geometry |
| --- | --- |
| CPUID.1 | Initial APIC ID, package capacity, HTT topology flag |
| CPUID.4 | Cores per package; private L1/L2 and package-shared higher caches |
| CPUID.B; supported CPUID.1F | One thread per core, package shift/capacity, terminator and current ID |
| AMD/Hygon 80000008 | Package capacity and APIC ID width |
| Advertised AMD/Hygon 8000001D/1E/26 | Cache sharing, core/node identity and matching extended domains |
| KVM signature/features | Detection enabled; supplied feature records retained |

For configured count `N`, let `C = min(N, 64)` and `S = ceil(log2(C))`.
CPU `id` has package ID `id >> S` and core ID `id & (2^S - 1)`.
The six-bit legacy cache field remains representable above 64 CPUs by using
additional packages; the final package may be partly populated. Firmware lists
only configured CPUs, without filling reserved ID holes. Construction and
projection use O(E) time/storage for E native CPUID records. The complete count
range 1..255 is component coverage; actual native VMM execution covers 1/2/4.

Unconfigured SDK calls retain their existing native geometry and CPU-ID API.
Callers selecting a virtual count use `Vm::configure_cpu_topology` before native
CPU creation. Invalid pure profiles/IDs reject before native allocation; after
allocation the configuration stays closed even if later setup fails. Stateful
CPUID records, unrelated ISA features and unavailable optional leaves are retained.

## Checkpoint identity for an invalid topology level

The Linux KVM checkpoint witness at `190b4929b` rejected a restore when the
source and destination exposed different host x2APIC IDs in a CPUID leaf
`0x1f`, subleaf 0 record. Both records had a zero logical-processor count and
an invalid domain. Only EDX differed, from `0` to `2`. The configured RAX
profile now writes the virtual CPU's ID to EDX even when that level is
invalid. Its validity fields and the maximum CPUID leaf are preserved.
[Native failure](https://github.com/HexRaysSA/rax/actions/runs/44669442871/job/136066614970)
[Intel SDM, Volume 2A, CPUID leaf 1FH](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf)

Existing version-4 records can restore when the saved configured and
observed profiles agree on that exact invalid subleaf. Restore projects
their EDX to the destination vCPU ID before the existing profile checks.
The wire format and the runtime checks for other CPUID fields are preserved.
The legacy projection takes O(E) time and O(1) additional space for E entries.

The Linux x64 KVM job at `4e3cc795f` passed the full 15-case `kvm_minimal`
suite. The source-free PC test completed the restore, RAM verification, and
guest continuation loop for 1, 2, and 4 vCPUs. The 15-case native entry and
I/O suite and the 32-case native SMP suite also passed. The job ran through
the release build. Qualification applies to the recorded Linux KVM host.
[Native success](https://github.com/HexRaysSA/rax/actions/runs/44670444437/job/136069846160)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| A zero-domain subleaf carries x2APIC identity without advertising a valid topology level. | High | Project the two observed host IDs at each vCPU in 1-, 2-, and 4-vCPU configurations. Require equal profiles, unchanged validity, and EDX equal to the vCPU ID. |
| The legacy producer retained the same invalid subleaf in both saved banks. | High | Vary EDX between the banks and vary domain validity. Require strict comparison in both cases. |

## Guest discovery and startup evidence

The final guest records 38 CPUID queries per CPU, starts every configured CPU,
performs two fixed-IPI/EOI/halt-wake rounds, and enables an independent native KVM
clock page for each CPU. It checks complete versioned publication and derives
TSC frequency from the kernel's multiplier/shift, comparing it with the native
SDK frequency to within 1 kHz. That tolerance covers the integer-kHz observations;
it does not establish hard real-time latency or checkpoint clock continuity.

The unchanged complete PIT library passes ten existing owning cases and fails
all six geometry/clock regressions. The first profile implementation passes
those 16 cases but fails a separate existing SDK-usage control. The final
SDK-compatible complete library passes all 17 owning cases, all ten native I/O
cases, ten profile unit/lifecycle cases and sixteen public-state cases. Root
unit selections are filtered; these results are not an unfiltered library run.

The historical final-CLI Linux run activated exactly 1/2/4 CPUs, detected
KVM clock MSRs and a 3491.912 MHz TSC, and reported a periodic LAPIC
verification failure. All eighteen canonical workspace commands passed.
Receipts and assumptions are in `qualification.json`. Native
private/shared/in-flight checkpoint production, coordinated restore, full
clocks/replay, remaining A32/HVF profiles and physical Intel HVF execution
remain separate full requirements. AMD/Hygon
field matrices are synthetic; no physical AMD/Hygon runtime result is claimed.

The current-source probe at `4b2bff02` used the same Linux
`6.8.0-138-generic` guest image and a fresh CLI build. Linux reported
TSC-deadline availability and brought up all configured CPUs in both the
one- and four-vCPU cases. The harness exited after the SMP bring-up
marker. Linux skips legacy LAPIC calibration when it enables
TSC-deadline. With `clearcpuid=152` masking that feature, the one-vCPU
control stopped emitting serial output after disabling its early
console. It reached neither legacy calibration nor SMP bring-up within
325 s. The startup evidence covers a single Linux guest and Intel KVM host.
[Linux LAPIC calibration](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kernel/apic/apic.c)
[Linux CPU feature indices](https://github.com/torvalds/linux/blob/v6.8/arch/x86/include/asm/cpufeatures.h)
[Native boot observations](linux-startup-native.json)

## Short native entries during legacy timer setup

Three live checkpoints found the stalled vCPU at the same instruction,
`pit_set_periodic+0x36`, just after writing the PIT divisor. RFLAGS.IF was
clear. During 106.185045493 s of VM wall time the modeled PIT advanced by
106,201 ticks, or 1,000.150 ticks/s, consistent with the programmed divider.
These samples establish PIT progress and the CPU's repeated stop location.

The host repeatedly changed the worker TID associated with the vCPU. A
sampled worker was blocked in `synchronize_rcu` inside `kvm_vcpu_ioctl`.
Linux 6.8 waits for that grace period on a KVM_RUN thread change before
processing the architecture-specific request. The RAX timer could expire
during that wait even when the guest had a runnable instruction.

| Requested timer | Guest I/O exits with timer already armed | Guest I/O exits with worker bound first |
| ---: | ---: | ---: |
| 100 us | 1/128 | 128/128 |
| 1 ms | 1/128 | 128/128 |

The table comes from an independent KVM UAPI guest that repeatedly writes
port `0x80`. Both conditions created a fresh worker before each timed run.
Only the worker association order changed. A separate RAX experiment with
the Linux guest reproduced the 325 s stall after increasing the slice floor
to 1 ms. Disabling Linux's I/O delay also reproduced the stall. Binding the
worker first reached bring-up of one CPU, and Linux accepted a measured
100-jiffy periodic APIC verification interval.

With `KVM_CAP_IMMEDIATE_EXIT`, ordinary managed slices now associate the
worker with the vCPU using a stopped KVM_RUN before arming the timer. The
ordinary I/O adapter owns any preceding I/O completion or reported exit.
The worker continues to own its timer and signal mask until it exits. The
association adds O(1) operations and requires O(1) additional storage. It
does not bound kernel scheduling or grace-period latency.
[Linux 6.8 KVM_RUN dispatch](https://github.com/torvalds/linux/blob/v6.8/virt/kvm/kvm_main.c#L4144-L4169)
[Linux KVM UAPI immediate-exit and I/O completion semantics](https://github.com/torvalds/linux/blob/v6.8/Documentation/virt/kvm/api.rst#L5984-L5995)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Short entries can make progress once worker association precedes the timer. | High | Retain a previous KVM_RUN worker, then require eight ordered guest port markers across 100 us entries. The parent stopped before the first short-entry marker. |
| An immediate-exit association can complete owned I/O without executing another instruction. | High | Require exact port and MMIO completion, then observe the next guest event and its operand once. |
| A checkpoint still commits an in-flight operation at its stopped boundary. | High | Save and restore the physical file on fresh 1-, 2-, and 4-vCPU owners. Require exact RAM and UART continuation. |
| The kernel timer retains its previous signal ownership. | Medium | Repeat timed slices while a foreign caller handler is installed. Check the caller mask, disposition, and timer inventory. |

An exact production-overlay build on native Intel KVM also reached the
single-vCPU Linux bring-up marker. Linux verified the periodic APIC timer
with a delta of 100 jiffies. The harness stopped on the SMP marker.
The complete native `kvm_host_slices`, `kvm_minimal`, and `kvm_smp`
targets passed 16, 15, and 32 tests respectively. The runs enabled the
KVM-gated cases and reported zero failures, ignored cases, or filters.

`native-profile.S`, `encoding.json`, and `queries.json` retain the guest witness.
The adjacent primary Linux references preserve their original notices. Intel
SDM and AMD APM section/page provenance is in `references/provenance.json`.
