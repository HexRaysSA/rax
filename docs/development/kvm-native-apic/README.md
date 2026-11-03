# Native APIC feature admission

Managed native CPUs select interrupt features from the controller actually
created for their VM. Kernel-supported CPUID deliberately clears TSC-deadline;
the separate `KVM_CAP_TSC_DEADLINE_TIMER` capability and an in-kernel LAPIC permit
userspace to enable it. The supplied x2APIC and KVM PV-unhalt bits also require
that LAPIC. Raw SDK CPUs retain explicit CPUID ownership.

| Kernel LAPIC | Deadline capability | TSC-deadline | x2APIC / PV-unhalt |
| --- | --- | --- | --- |
| Absent | Either | Clear | Clear |
| Present | Absent | Clear | Retain supplied bits |
| Present | Present | Set | Retain supplied bits |

Admission changes only these documented dependencies. Other CPUID records and
KVM feature bits remain intact. IRQchip creation and native CPU allocation use
the same profile lock: successful controller creation and its admission flag
become visible before any CPU selects its profile. Failed/late kernel creation
does not publish a controller flag. Projection and admission precede native
CPU allocation; raw SDK CPUID configuration remains the caller's responsibility.
Admission uses O(E) time and O(1) extra storage for E CPUID entries.

The unchanged complete topology library passes twenty cases and fails seven
in the expanded 27-case owning SMP target: four configured/unconfigured SDK
admission cases and three deadline IRQ cases. The actual changed pure profile
and admission modules pass all nine component tests. The complete changed
production library passes all 27 owning SMP cases, 10 owning I/O cases,
13 profile/admission cases and 16 public-state cases. All 18 canonical commands
pass, including workspace formatting, Clippy, all-target build, no-JIT check,
doctests and the complete owning native targets. See
`qualification.json` and `production-v2.json`. Linux 6.8.0-138 startup
activates the configured 1/2/4 CPUs and reports the admitted TSC-deadline
timer in every run; the complete serial observations are in
`linux-startup.json`. Observation ends at CPU activation, before a full
operating-system boot.

The assembly witness starts every configured CPU and requests two periodic or
deadline IRQs per CPU, with EOI and secondary CPU halt/wake. A BSP TSC bound and
an outer 40 s owned-process limit prevent a missing IRQ from hanging the test.
The three unchanged periodic controls pass at 1/2/4 CPUs. This does not explain
Linux's separate periodic calibration failure or establish timer migration,
clock continuity, native private/shared state or coordinated restoration.

Primary API requirements are in the adjacent topic's archived
`../kvm-public-state/references/kvm-api-v6.8.rst`, sections 4.46 and 9.1.
The unmodified Linux sources identified in `references/provenance.json`
establish kernel controller-creation ordering and native timer/interrupt paths.
The existing archived `kernel-x86-v6.8.c` is reused byte for byte.
