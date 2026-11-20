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

## Unfiltered hosted KVM validation

Dispatch the KVM workflow with `owning_library=true` to run the complete
`kvm_minimal`, `kvm_host_slices`, `kvm_smp`, `checkpoint_cpus`, `realmode_boot`
and library test binaries with KVM and debugger support enabled. This mode uses a
commit-specific concurrency group so later pushes to the same branch can
run the normal KVM checks without cancelling the unfiltered run.

The hosted Linux x86-64 `/dev/kvm` run at `bb5f7059b` completed every
owning binary without a failure. The integration invocation included ignored
tests. The library invocation left its 97 normally ignored tests disabled.
[Hosted KVM job](https://github.com/HexRaysSA/rax/actions/runs/44771673783/job/136410666709)

| Test binary | Passed | Ignored |
| --- | ---: | ---: |
| `checkpoint_cpus` | 12 | 0 |
| `kvm_host_slices` | 17 | 0 |
| `kvm_minimal` | 15 | 0 |
| `kvm_smp` | 32 | 0 |
| `realmode_boot` | 10 | 0 |
| Library | 14,209 | 97 |

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
[Linux 6.8 KVM_RUN dispatch](references/linux-kvm-main-v6.8.c#L4427-L4449)
[Linux KVM UAPI immediate-exit and I/O completion semantics](../kvm-public-state/references/kvm-api-v6.8.rst#L6495-L6505)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Short entries can make progress once worker association precedes the timer. | High | Retain a previous KVM_RUN worker, then require eight ordered guest port markers across 100 us entries. The parent stopped before the first short-entry marker. |
| An immediate-exit association can complete owned I/O without executing another instruction. | High | Require exact port and MMIO completion, then observe the next guest event and its operand once. |
| A checkpoint still commits an in-flight operation at its stopped boundary. | High | Save and restore the physical file on fresh 1-, 2-, and 4-vCPU owners. Require exact RAM and UART continuation. |
| The kernel timer retains its previous signal ownership. | Medium | Repeat timed slices while a foreign caller handler is installed. Check the caller mask, disposition, and timer inventory. |

A build with the committed worker change on native Intel KVM reached
the Linux CPU bring-up marker in each configuration. Linux verified the
periodic APIC timer with a delta of 100 jiffies in every run.

| Configured vCPUs | CPUs brought up | Verification interval (jiffies) | Time to marker (s) |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 100 | 189.223 |
| 2 | 2 | 100 | 210.009 |
| 4 | 4 | 100 | 257.147 |

The harness stopped on the SMP marker. The build used source revision
`3f560f6fd` with the worker source from `b7046c44b`. The
[native receipt](short-host-slices-native.json) records the source,
kernel and binary hashes, command line, and control observations.

The complete native `kvm_host_slices`, `kvm_minimal`, and `kvm_smp`
targets passed 16, 15, and 32 tests respectively. The runs enabled the
KVM-gated cases and reported zero failures, ignored cases, or filters.

## Linux progress after CPU bring-up

Revision `53dbf4fc7` brought up all four CPUs on the same physical Intel
KVM host. Linux again measured 100 jiffies in its forced legacy
APIC calibration, then stopped emitting console output after the pinctrl
initialization line. The 720.741 s run never reached the static `/init`
witness. The witness pins a child to each CPU and checks CPU identity
across a 20 ms absolute monotonic sleep. Build it with
`cc -static -std=c11 -Wall -Wextra -Werror -O2 -o init linux-pinned-timers.c`
and archive the executable at the root of an initramfs.

| Assumption or boundary | Impact | Falsification probe |
| --- | --- | --- |
| The early guest log timestamps alone do not measure clock continuity. | High | Boot the same kernel and init with QEMU/KVM. Check for the same early ordering and compare native pvclock stamps across the vCPUs. |
| CPU 0 repeatedly retries an inconsistent CMOS calendar read after SMP. | High | Capture worker-only KVM exit and port traces. Compare seconds returned at the beginning and end of each complete CMOS scan. |
| An active LAPIC countdown needs a separate expiry-state witness. | High | Request a coordinated checkpoint at this boundary. Require either a usable record or a precise capture error. |

QEMU 8.2.2 on the same host reached `/init` with the same kernel and
init executable. All four pinned children completed the requested sleeps
with observed elapsed times from 20,095,246 ns to 22,858,565 ns. Both
VMMs printed early AP timestamps earlier than the BSP bring-up timestamp.
A separate RAX trace of 23 native pvclock publications recorded matching
TSC epoch, time base, multiplier, shift, and stable flag for samples on
all four CPUs. The QEMU PC machine uses a different virtual chipset.
[Linux printk timestamp](references/linux-printk-v6.8.c#L2169-L2177)
[Linux KVM pvclock setup](references/linux-kvmclock-v6.8.c#L167-L195)

A 780.387 s follow-up stopped at the same boundary. Two scoped kernel
traces resolved CPU 0 exits to `rtc_cmos_read` and observed timer
interrupt handlers on each AP. The median interval between consecutive
CMOS byte responses was 124.951 ms across 77 intervals. All five complete
calendar scans crossed a one-second boundary and returned a different
seconds value on the final check. Linux retries those inconsistent
snapshots. Three quieter controls, including TSC-deadline and disabling
paravirtual spinlocks, also failed to reach `/init` within 180 s each.
[Linux CMOS PIO](references/linux-x86-rtc-v6.8.c#L80-L91)
[Linux CMOS consistency check](references/linux-rtc-mc146818-v6.8.c#L21-L86)

RAX rejected the stopped checkpoint request with a programmed LAPIC
countdown whose expiry state was unavailable. The follow-up produced
zero checkpoint files. The [native receipt](post-smp-native.json) records
the guest and binary hashes, scoped trace counts, clock evidence, and
individual CMOS observations. The kernel-owned countdown phase at that
boundary remains unavailable. The userspace LAPIC has a separately
qualified wake path below.

`native-profile.S`, `encoding.json`, and `queries.json` retain the guest witness.
The adjacent primary Linux references preserve their original notices. Intel
SDM and AMD APM section/page provenance is in `references/provenance.json`.

## Concurrent KVM worker rounds

For multiple x86 vCPUs with the KVM interrupt controller, the VMM posts a
bounded entry to every online CPU before collecting results. It collects
all posted entries before device dispatch and checkpoint capture, including
when a later post fails. The entry allowance is capped at 1 ms. An active
GDB session uses the serial coordinator to preserve debugger stop and step
semantics.

On a physical Intel Xeon E5-1650 v3 running Linux 6.8, the stock four-vCPU
Linux guest completed 128 pinned timer measurements in each of TSC-deadline
and legacy LAPIC modes. Each vCPU completed 32 waits of at least 20 ms.
Separate trace runs using the same artifacts recorded 1 and 152 pairs of
entry-to-exit intervals, respectively, that overlapped by at least 5 µs on
distinct physical cores. The intervals include host work inside KVM.

Replay both guest configurations and require all 128 unique CPU/sample
pairs to check the timer result. For the overlap result, match the
executable and guest digests, then reconstruct entry-to-exit intervals from
the host CPU topology and discard migrating or sibling-core pairs.
[Native qualification receipt](parallel-worker-timers.json)

The hosted Linux x86-64 KVM regression exercised two and four vCPUs. The
BSP started the APs with INIT/SIPI and the coordinator collected a pending
UART input from each CPU. After checkpointing and destroying the source VM,
the restored CPUs reported their distinct saved bytes. A final unread UART
byte proved that restore did not consume input twice.
[Hosted KVM run for `db443e45b`](https://github.com/HexRaysSA/rax/actions/runs/44750698131/job/136337513983)

## Halted checkpoints and PC interrupt delivery

Three native KVM regressions passed at `bb5f7059b` on the hosted Linux x86-64
runner. Each check required the named test to execute successfully.
[Hosted KVM run](https://github.com/HexRaysSA/rax/actions/runs/44771568304/job/136410468049)

| Profile | Guest and checkpoint witness |
| --- | --- |
| Userspace interrupt controller, one, two and four vCPUs | Real-mode code armed the software LAPIC count and halted the VM. A new VM restored the saved timer age. The first scheduled idle turn resumed the clock. The selected CPU took vector `0x41`, executed EOI and IRET, and reached the continuation once. Every peer remained halted at its saved PC. |
| Userspace interrupt controller, one vCPU | A stopped guest UART `OUT` enabled a pending receive interrupt. Settling the PIO completion presented vector `0x24` through the userspace PIC. |
| Kernel interrupt controller, one vCPU | Real-mode code routed IOAPIC pin 12 to vector `0x2c`, then generated an i8042 auxiliary byte through PIO. Capture settled the outstanding write, and a fresh VM ran the handler once. It reported `0x5a`, then returned to the interrupted code and reported `0xbe`. |

At `0f9a84f77`, hosted Linux KVM also passed detached restoration of a
pending UART receive interrupt routed through level-triggered IOAPIC pin 4.
The restored real-mode guest took vector `0x24`, read byte `0x5a` at COM1,
acknowledged the local APIC, returned with IRET and reached the `0xbe`
continuation without taking the handler again. Two software regressions
failed on the parent and passed with the fix. They require an IIR read to
release a level PIC input at the PIO boundary and detached restoration to
preserve an acknowledged edge while the UART line is still held. All 32
PC interrupt tests passed. [Hosted KVM run](https://github.com/HexRaysSA/rax/actions/runs/44779244703/job/136437434975)

The userspace LAPIC stores the countdown age. A separate kernel-owned LAPIC
probe observed identical 1,024-byte APIC images with current count zero
before an armed timer fired and after the interrupt was serviced. The
coordinated KVM capture path still rejects that ambiguous countdown state.
[Hosted KVM countdown probe](https://github.com/HexRaysSA/rax/actions/runs/44761608392)
