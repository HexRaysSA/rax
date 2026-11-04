# Native migration-MSR image prototype

This helper captures the selected kernel migration-MSR list using the actual
native SDK and retains advancing counters in a distinct serialized bank.
It restores the stored-register bank on an exclusively stopped disposable
CPU. It is not wired into RAX's complete native producer.

Each KVM paravirtual MSR is admitted by its documented guest feature bit.
ASYNC_PF_INT additionally needs the kernel LAPIC. The source implementation is
[archived x86.c](../../kvm-public-state/references/kernel-x86-v6.8.c), specifically
its common GET/SET MSR switch and asynchronous-PF enable functions.

| Bank | Selected registers per CPU without LAPIC | With LAPIC |
| --- | --- | --- |
| Stored migration registers | 89 | 92 |
| Retained advancing counters | 3 | 3 |

The counters are TSC (0x10), Hyper-V VP runtime (0x40000010) and partition
reference time (0x40000020). The first experiment classified VP runtime as
ordinary stored data. Its two-CPU case failed exact readback; the only differing
entry was 0x40000010. `counter-failure.json` and its exact source preserve this
failure. The corrected image preserves the raw captured value in its counter
bank. No counter is discarded to obtain a matching stored-bank comparison.

The archived [Hyper-V implementation](../references/linux-hyperv-v6.8.c)
computes VP runtime from current-task CPU runtime plus a saved offset. A
host-initiated write adjusts that offset; a later read advances with task
runtime. The [primary definitions](../references/linux-hyperv-tlfs-v6.8.h)
identify 0x40000010 and its 100 ns units. Both source copies are unmodified,
retain their notices and have adjacent URL/retrieval/digest provenance.

Six actual source-free graphs cover1/2/4 CPUs with and without a kernel LAPIC.
Source CPU, VM, run-mapping and backing owners are destroyed before each fresh
destination is created. Nonzero syscall, KERNEL_GS_BASE, TSC_AUX, SYSENTER and
paravirtual control values exercise14 CPU banks. Every stored field reads back
exactly. Codec round trips retain both banks. Eight malformed stored/counter
membership/order records per CPU produce112 rejections with the stored bank
unchanged. `native.json` retains the complete commands, values, dependency
hashes and executable cleanup receipt; `probe.rs` and `checkpoint/msrs.rs` are
the exact observed implementation.

## Setter count and value admission

The expanded regression changes a writable LSTAR field and tampers with one
read-only Hyper-V frequency field. The previous helper reports success even
though the kernel retains the original frequency and changes LSTAR. That actual
failure is retained in `value-admission-baseline.json`.

The corrected helper reads back the stored bank after a complete SET_MSRS count
and rejects any mismatch. Both read-only frequency fields are exercised on
all14 source-free CPU destinations:28 tampered-value controls reject. The
ordinary valid images and all112 malformed membership/order controls still
pass. Each tampered-value observation explicitly confirms the writable prefix
changed inside the disposable destination; valid source values are then
reapplied and checked. This is value-admission evidence, not a promise of
transactional kernel batches or whole-VMM rollback.


| ID | Assumption and dependency | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| MSR1 | The host migration list alone defines guest-readable/writable MSRs | Disable advertised paravirtual features and restore with/without the kernel controller; a rejected batch falsifies unconditional membership | Falsified; the plan applies each examined guest feature gate |
| MSR2 | Only TSC and partition reference time advance between stopped SDK reads | Source-free multi-CPU exact readback; another differing counter falsifies that partition | Falsified by VP runtime; all three observed counters remain in the wire image |
| MSR3 | SET_MSRS batches are transactional | A rejected index after an accepted prefix falsifies atomicity | Falsified by retained earlier native observations; the helper requires a disposable target or full rollback guard |
| MSR5 | A complete setter count means the requested stored image was installed | Tamper with read-only frequency data and a writable prefix; successful count with different readback falsifies this assumption | Falsified by the old helper; the corrected helper rejects all28 controls |
| MSR4 | The selected stored bank survives source destruction with nonzero values | Fresh1/2/4-CPU destinations and raw register equality; any mismatching field falsifies restoration | Confirmed for14 banks on the recorded physical host |

High-impact remaining requirements are coordinated counter/clock restoration,
shared aliases, full cross-bank/CPUID profile admission, all other native CPU and shared
banks, native completion, and transactional integration. A successful kernel
setter count alone does not validate ignored/read-only field values; the helper
now checks stored readback. The complete producer must perform that admission
on an isolated target before publication. This helper does not establish the
remaining requirements or close C-STATE.

Plan construction uses expected O(M) time and O(M) storage for M kernel indices.
Capture, envelope validation and stored-bank application use O(M) time and
O(M) temporary storage. The complete coordinator must define the common clock
cut and publication order before this image becomes a full producer.
