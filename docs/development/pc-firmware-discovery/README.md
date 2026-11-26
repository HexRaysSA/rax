# PC firmware discovery and software I/O APIC ownership

Cold direct-kernel PCs using the software controllers publish an Intel MP 1.4
floating pointer at `0xf0000` and an explicit configuration table at `0xf0010`.
The table describes the configured CPUs and the guest-visible CPUID signature,
features, local APIC version, I/O APIC identity/version, and interrupt wiring.
The software/HVF PIT route uses input 2; KVM retains input 0.

The baseline owning test observes no MP pointer in the software PC. A real
guest also scans the reserved BIOS window and fails discovery for one, two, and
four configured CPUs. Publishing the table exposed a second defect: software
CPU I/O APIC accesses reached padded RAM instead of the controller owned by the
PC buses and checkpoints. The guest rejected the advertised I/O APIC version.

Software CPU MMUs now bind that same controller. Physical and typed accesses
dispatch to it before RAM, and speculative native-memory admission excludes its
window. A physical request straddling the window is rejected before invoking
the model. The straddling controls cover contiguous physical requests;
cross-page virtual requests retain the MMU's page splitting and require their
own MMIO-profile qualification.
The new `RAXX8604` private-context tag records this mapping policy without
changing the previous positional payload. Old tags retain their original RAM
policy. CPU restore preserves the target controller object; complete VM restore
requires its PC controller image before publishing any state.

The independently assembled guest in `discover.S` checks both checksums, table
length and record counts, CPU identity and APIC IDs, controller versions and the
PIT route. It derives its own CPU count and starts each AP with INIT/SIPI. Each
AP executes work and acknowledges two fixed IPIs with EOI. Host code does not
populate the discovery count. Checksum-valid identity and route corruptions are
negative controls. Source-free resume preserves guest-modified firmware bytes.

The 496-byte preamble is compared with the actual compiled Intel consumer's
`--emit-discovery-program` output. Its BSP and AP bodies retain the prior
qualified startup program. The Intel consumer adds three discovery cases to
the existing 203 cases. A source-pinned native 206-case run is required before
claiming native discovery qualification; compiling and signing locally does
not establish native guest execution.

`qualification.json` records the assumptions, validation state, source digests,
and limitations. `baseline.json` and `baseline.stderr` retain the observed
pre-fix failure. `assembly.json` and `guest-program-sources.json` identify the
guest bytes. The compatibility comparison covers all 255 CPU counts: KVM pin-0
tables are unchanged, and pin-2 tables differ only in the PIT destination and
checksum.

The primary source is Intel's *MultiProcessor Specification*, version 1.4,
May 1997, order 242016-006, sections 4.1-4.3. The local reference is
`docs/specifications/x86_64/multiprocessor-1.4/24201606.pdf`, SHA-256
`2d030e6045895b3e1fb0fee5775a8025a1f76d7c97b29437fe4783d9ef4981cc`.
The BIOS window is reserved by the existing E820 map. The PC ELF loader rejects
load segments below `0x100000`.

This group addresses direct-kernel firmware discovery and software I/O APIC
mapping. The complete A32-FP, C-STATE, C-SMP, and C-HVF findings remain open,
including complete KVM checkpoint production and the outstanding native ARM
streaming-FPSR behavior.

The frozen source passed the complete Apple Silicon library target (12,457
passed, 36 ignored) and x86/Rosetta library target (13,415 passed, five ignored),
both without filters or test failures. The 73 Intel owner tests, ten real-mode
tests, 38 Python tooling tests, Linux KVM cross-check, Clippy and signed consumer
emission also pass in their recorded domains. These counts do not establish
physical AArch32 or native Intel discovery execution.

Native Intel run [42063093601](https://github.com/HexRaysSA/rax/actions/runs/42063093601)
passes all 206 actual HVF guest controls, including cold firmware discovery for
one, two, and four CPUs. The guest derives its CPU count and APIC IDs from the
published tables, starts every AP, and observes two acknowledged IPIs per AP.
[Native qualification](native206-qualification.json) binds the signed consumer,
both consumer source files, and all 4491 engine inputs to commit `3d500416f`.
Both artifact ZIP digests and every member hash were independently verified.
The runner reports a native Intel process and `hypervisor_guest=1`; these
results do not establish a bare-metal host or untested native profiles.

Upstream Windows ARM64EC commit `551302a7` arrived during the final x86 run.
It was fast-forwarded without a merge commit and changes 37 engine inputs,
disjoint from this group. The qualification preserves the compiled source
digest, accounts for that exact upstream overlay, and records separate
Clippy and 22-test PC replays on the integrated source. Its failed aggregate
source guard is retained; the actual complete x86 test process returned zero.

## Multiprocessor ISO boot

Cold x86 PC boot from an El Torito image with two or more configured vCPUs
publishes the MP table before any CPU enters the guest. The software-controller
and KVM paths share the placement calculation. The 16-byte-aligned floating
pointer starts at `0xf0000` or at the first aligned address beyond the loaded
image if the image would overlap the table. The configuration records follow
the pointer. Construction rejects an SMP image that leaves too little usable
space in `0xf0000..0x100000`. Single-vCPU ISO boot retains its existing path.
Resume restores the guest's saved firmware bytes. Placement and boot-catalog
range calculation use constant time and space. Table generation and writes
scale linearly with the configured vCPU count.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| A real-mode PC guest can discover and start every configured AP. | High | Boot the assembled `iso-smp.S` image with two and four CPUs. Start with APs offline and empty result slots. Require a guest-discovered count and a RAM marker written by every AP after INIT/SIPI. |
| Relocated tables stay in the BIOS discovery window and leave the boot image intact. | High | Load a 512 B sentinel at `0xf0000` and verify its bytes plus the pointer at `0xf0200`. Cover the entire 64 KiB window and require rejection for the two-vCPU VM. |

Both regressions failed on `847f3b003`. The generated boot image is 1,055 B
with SHA-256 `eba2b88c9400396bbd8e6330d3e52ba9a1493f451174c0976df43f9cffe9b46e`.
The original image booted on QEMU 11.1.2 and found one processor in the
available firmware's MP table at both configured counts. A second control
placed an independently generated table in ordinary boot RAM and changed the
scan start to that address. The same startup sequence then collected every AP
marker and powered off at two and four CPUs. The QMP receipt has SHA-256
`443da2f85a54702af603227c4f42aea3cb8845b05a3cb0238675e86365df2818`.
All 31 tests in the PC firmware and machine library modules passed. The
unfiltered `realmode_boot` target passed all ten tests on x86-64 under Rosetta.
Clippy with warnings denied passed. The Linux x86-64 KVM library and the
native witness compiled and linked. The macOS Arm64 unfiltered library run
reproduced the existing Darwin `kern.hostname` assertion failure, also
observed on `aa89a1e80`.
The KVM workflow runs the same ISO with the in-kernel interrupt controller
and requires an explicit passing result for the native test. Native run
`45866780395` at `733098a39` passed direct-boot secondary startup and fixed
IPIs at two and four CPUs. The ISO guest wrote its failure marker in the
same run. Its original marker did not distinguish discovery from peer
startup. [Native KVM run](https://github.com/HexRaysSA/rax/actions/runs/45866780395/job/140071535914)

The current ISO witness checks the published MP pointer before boot, then
lets the guest discover the processor count. It records distinct guest
failure stages for the pointer, table header, processor records, and peer
startup. While waiting for each AP, the guest uses at most 4,096 port
`0x80` writes to yield VMM turns, matching the scheduling technique used
by the direct-boot KVM witness. The revised boot image SHA-256 is
`b53d60bdc5e897ca62da2cede7bf5fe78155d8cc1fd670c4e8876d879f4a1ae8`.
The QEMU control again observed all peer markers and shutdown in both CPU
configurations using an independently generated MP table. A corrupt table
header reported failure stage 2. Advertising four CPUs on a two-CPU VM
reported failure stage 4 with the two existing CPU markers intact. Both
negative controls shut down. All seven local firmware tests passed with the
revised image.

Hosted Linux x86-64 KVM passed the revised native ISO witness on
`392341ed5` in run `45870691656`, attempt 2. The test uses the in-kernel
interrupt controller and requires the guest to discover two and four CPUs,
start every secondary with INIT/SIPI, and observe all CPU-written markers.
The Actions receipt SHA-256 is
`b76a4e09057f11d4a8d15d12043fa2165ca086e6d8f6eb087916706247641fb3`.
Intel HVF ISO execution and broader SMP coverage remain open.
[Hosted KVM ISO test](https://github.com/HexRaysSA/rax/actions/runs/45870691656/job/140090652262)
Inputs, commands and results are under
`/Users/int/dev/rax-audit-work/four-findings-pc-iso-smp-2026-11-26/`.

The signed Intel HVF workflow runs the same ISO with two and four vCPUs
under both bounded turns and opt-in parallel rounds. Each run begins with
only CPU 0 online. The guest must find the MP pointer and table, start every
secondary, and write the expected RAM markers before requesting power-off.
The workflow checks an explicit pass record for each combination and keeps
the native log with the signed harness digest. The cross-built x86-64 harness
registered the native case. Under Rosetta it passed all seven software
firmware tests and all 39 PC machine tests. The workflow passed `actionlint`,
and the receipt check rejected each control that omitted a required record.
The current native ISO result is unknown until the workflow executes the
four cases.

| Assumption | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| Intel HVF executes the real-mode AP startup and the selected coordinator mode services it. | Cold Intel HVF ISO reaches every configured CPU. | Run the signed, untranslated harness with two and four CPUs in each mode and require guest-discovered counts, all CPU markers and successful exit. | High |
| The host test measures actual guest entry under the requested backend. | Local harness registration and hosted execution remain distinct evidence. | Require the native availability probe, the signed executable's digest and a pass receipt from each guest run. | High |

### Real-mode task and local descriptor state

Cold El Torito boot now initializes the task-register cache as a present,
usable busy 32-bit TSS and marks the unconfigured local descriptor table unusable.
Intel VM entry checks the task register even with unrestricted guest enabled.
The HVF adapter encodes the machine's segment records into the corresponding
VMCS access-rights fields. The earlier boot record passed type 0 and present
clear for both fields. The local regression at `0027e29b8` observed type 0
instead of 11. This change initializes two fixed-size records and adds no
checkpoint fields. [Intel SDM, Vol. 3C, §28.3.1.2](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The x86-64 tests under Rosetta passed 39 PC library cases, seven firmware
cases and all ten real-mode integration cases. This includes the software
ISO boot with two and four vCPUs. Clippy passed with warnings denied. The
Intel HVF witness registered and remained ignored on the translated host.

The native ISO witness records the CPU count and scheduling mode before
constructing each VM and again before invoking the VMM run loop. The hosted
run on `1e58c0e68` had already passed pending-MMIO and legacy PAE restore
when the ISO step began. Its ISO result and the runtime effect of the task
register correction on that host remain unknown.
[Original Intel HVF run](https://github.com/HexRaysSA/rax/actions/runs/45888006650/job/140143432895)

| Assumption | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| The cold boot record supplies VMX-compatible system segment caches. | Native boot can pass these two segment checks. | Assert a present, usable busy TSS with the TR selector's TI bit clear and an unusable LDTR in the generated boot state. | High |
| Entry and AP startup work with the complete corrected boot state. | Intel HVF qualifies the ISO in both coordinator modes. | Require all four native ISO pass records after the pre-entry markers. | High |
