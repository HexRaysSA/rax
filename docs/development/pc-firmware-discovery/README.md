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
and requires an explicit passing result for the native test. Native KVM and
Intel HVF ISO execution remain unverified.
Inputs, commands and results are under
`/Users/int/dev/rax-audit-work/four-findings-pc-iso-smp-2026-11-26/`.
