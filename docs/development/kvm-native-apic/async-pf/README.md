# LAPIC-dependent paravirtual feature admission

Managed CPUs admit KVM asynchronous-PF feature bits 4, 10 and 14, and
paravirtual IPI bit 11, from the kernel controller actually created for the VM.
Both configured and unconfigured managed CPU constructors use this admission.
The raw `create_vcpu_fd` interface retains explicit caller-owned CPUID selection.

| Kernel LAPIC | Asynchronous PF bits 4/10/14 | PV IPI bit 11 |
| --- | --- | --- |
| Absent | Clear all three | Clear |
| Present | Retain each supplied bit | Retain supplied bit |

Existing x2APIC, TSC-deadline and PV-unhalt admission remains in force. Other
CPUID fields are retained, and the KVM feature leaf is interpreted only under
the KVM signature. Admission takes O(E) time and O(1) additional space for E
CPUID entries.

The archived Linux 6.8 [x86.c](../../kvm-public-state/references/kernel-x86-v6.8.c)
functions `kvm_pv_enable_async_pf` and `kvm_pv_enable_async_pf_int` establish the
controller requirements. Without the kernel LAPIC, the former accepts only a
zero enable value and the latter rejects interrupt control. The archived
[lapic.c](../references/linux-kvm-lapic-v6.8.c) `kvm_pv_send_ipi` requires the
kernel APIC map. Feature numbers are defined by the archived
[KVM CPUID specification](../../kvm-native-topology/references/linux-kvm-cpuid-v6.8.rst).
Adjacent provenance records identify the unmodified upstream sources.

## Native regressions

The actual managed guest in
[async-enable-guest-baseline.rs](async-enable-guest-baseline.rs) reads CPUID and
writes MSR_KVM_ASYNC_PF_EN using a real registered guest page. Its real-mode
#GP vector points to a distinct output marker. Both the basic enable and
VM-exit enable request reach that handler without a kernel LAPIC, despite
advertised feature bits 4 and 10. Both controller-present controls reach the
success marker. The four observations are retained in
[async-enable-guest-baseline.json](async-enable-guest-baseline.json).

The earlier [PV IPI witness](pv-ipi-guest-baseline.json) reads advertised bit 11
and receives -95 (`EOPNOTSUPP`) without the controller; its controller-present
request returns 0. That return value establishes acceptance, rather than a
count of delivered interrupts. The whole SMP target separately exercises CPU
startup, discovery, timer interrupts, EOI and secondary halt/wake.

| Complete target | Prior candidate under expanded assertions | Expanded candidate |
| --- | --- | --- |
| CPUID/admission component | 8 passed, 2 failed | 10 passed, 0 failed |
| Owning native SMP | 25 passed, 2 failed | 27 passed, 0 failed |
| Owning native I/O | Earlier retained control | 10 passed, 0 failed |
| Owning native minimal backend | Earlier retained control | 14 passed, 0 failed |

The final three native targets have no ignored or top-level filtered cases.
`production.json` retains all seven compile/run commands, full-source and
candidate identities, coverage counts and the complete library hash. Earlier
APF-only and interrupt-v3 observations remain separately named; they do not
qualify the expanded candidate.

The complete product reuses one immutable source export. Three path-only
module dispatchers select the changed admission module. Reversing their path
transformations reconstructs each original source exactly, including existing
relative module attributes. All other modules, SDK types and executable helpers
come from the original full product. Source-location metadata can differ in
these three dispatchers. No second full export or worktree is created.

The exact three qualified source files are applied in the main checkout.
[main-workspace.json](main-workspace.json) records final-tree packaged formatting
and workspace all-target Clippy. KVM is Linux-target-gated on that macOS host;
[native-clippy.json](native-clippy.json) records separate native library and
unfiltered root-test compilation using the complete qualified production graph.
The native root compilation reports four pre-existing numeric-literal warnings
in unrelated SMIR tests. Neither record claims additional native test execution
or a post-integration Linux Cargo workspace run.

## Assumptions and remaining scope

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| APIC1 | Nonzero asynchronous-PF controls require the kernel LAPIC | Primary kernel functions plus distinct guest #GP/success handlers for both enable modes; a successful controller-free enable would falsify this dependency | Confirmed for the examined implementation and host |
| APIC2 | PV IPI requires the kernel APIC map | Primary kernel delivery function and actual controller-free rejection; successful delivery without that map would falsify the dependency | Confirmed for the examined implementation and host |
| APIC3 | Unrelated fields and hypervisor namespaces retain their meaning | Complete pure namespace tests and native guest observations; any unexpected record delta falsifies preservation | Confirmed for exercised records |
| APIC4 | Native qualification applies to this physical host | Physical Haswell Linux KVM; each other native implementation requires its own experiment | Retained host boundary |

The qualification receipt explicitly records whether the candidate is applied
to `master`. High-impact remaining requirements include the complete native
CPU/private/shared and in-flight checkpoint producer with coordinated restore.
Physical Intel macOS qualification and the remaining A32/HVF profiles also stay
open under the full audit objective.
