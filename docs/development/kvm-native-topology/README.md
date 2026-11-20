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

Independent final-CLI Linux activates exactly 1/2/4 CPUs, detects KVM clock
MSRs and a 3491.912 MHz TSC, and no longer reports die-conversion warnings.
Periodic LAPIC timer verification still fails; complete timer/IRQ correctness
is not established by CPU startup. All eighteen canonical workspace commands
pass; receipts and assumptions are in `qualification.json`. Native
private/shared/in-flight checkpoint production, coordinated restore, full
clocks/replay, remaining A32/HVF profiles and physical Intel HVF execution
remain separate full requirements. AMD/Hygon
field matrices are synthetic; no physical AMD/Hygon runtime result is claimed.

`native-profile.S`, `encoding.json`, and `queries.json` retain the guest witness.
The adjacent primary Linux references preserve their original notices. Intel
SDM and AMD APM section/page provenance is in `references/provenance.json`.
