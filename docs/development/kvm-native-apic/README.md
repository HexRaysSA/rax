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

The assembly witness starts every configured CPU and exercises periodic and
TSC-deadline delivery, EOI, and secondary CPU halt/wake. In periodic mode it
waits for a third vector to enter IRR while the second vector is in service.
It captures IRR before and after masking, then requires the queued vector to
be delivered after EOI. Deadline mode requires two deliveries and an empty
IRR at the mask. The final count in both modes follows a quiet window of
100,000,000 guest TSC cycles. A BSP TSC bound and an outer 40 s owned-process
limit prevent a missing event from hanging the test.

QEMU 11.1.2 delivered exactly three periodic IRQs per CPU for the revised
guest with 1, 2, and 4 vCPUs. Removing the mask produced extra IRQs in all
three cases. The Linux x86-64 SMP test binary cross-built with the exact
guest bytes. Native KVM deadline delivery, timer migration, and checkpoint
clock continuity require separate evidence.

Primary API requirements are in the adjacent topic's archived
`../kvm-public-state/references/kvm-api-v6.8.rst`, sections 4.46 and 9.1.
The unmodified Linux sources identified in `references/provenance.json`
establish kernel controller-creation ordering and native timer/interrupt paths.
The existing archived `kernel-x86-v6.8.c` is reused byte for byte.
