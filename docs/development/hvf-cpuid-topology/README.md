# Configured Intel HVF CPUID topology

Configured HVF machines previously projected each CPU's APIC identity while
retaining a one-processor package count, an eight-core cache description and
fixed topology shifts. The owner regression reproduces the old behavior in
[owner-baseline.stderr](owner-baseline.stderr). The corrected dispatcher derives
the package geometry from the VM's immutable configured CPU count.

One hardware thread represents each virtual core. A package contains at most
64 cores because CPUID.4 has six bits for cores per package minus one. Further
CPU IDs occupy additional packages; the last package may be partly populated.
For `C` configured CPUs, package capacity is `min(C, 64)` and the package shift
is `ceil(log2(capacity))`, with shift zero for one CPU. CPUID projection takes
constant time and constant auxiliary space.

| Configured CPUs | Cores/package | Package shift, bits | Packages occupied |
|---|---|---|---|
| 1 | 1 | 0 | 1 |
| 2 | 2 | 1 | 1 |
| 3 | 3 | 2 | 1 |
| 4 | 4 | 2 | 1 |
| 33 | 33 | 6 | 1 |
| 64 | 64 | 6 | 1 |
| 65 | 64 | 6 | 2 |
| 255 | 64 | 6 | 4 |

Leaf 1 reports package capacity and initial APIC ID, and clears HTT for a
single-core package. Leaf 4 reports the matching core capacity, private L1/L2
caches and a package-shared L3 cache. Leaf 0B reports SMT and core domains,
including the caller's full APIC ID on invalid terminal subleaves. Leaf 1F
remains unavailable under the existing maximum-basic-leaf profile. Other
feature bits and the XSAVE dynamic overlay retain their existing behavior.

The primary source is Intel SDM revision 086, Volume 2A, Table 3-17, CPUID
leaves 1, 4 and 0B; PDF pages 815, 816 and 823 in the
[retained manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
The [archive provenance](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)
records its revision, checksum and historical URL limitation.

The shared checkpoint tag versions the CPUID policy. Its serialized body stays
byte-compatible with the historical body; the tag supplies the additional
policy bit. The ordinary codec does not serialize a second copy of that bit.

| Shared tag | CPUID geometry on restore | Subsequent capture |
|---|---|---|
| `RAXHVG01` | Historical fixed geometry; existing low-RAM restriction | `RAXHVG02` |
| `RAXHVG02` | Historical fixed geometry | `RAXHVG02` |
| `RAXHVG03` | Configured package geometry | `RAXHVG03` |

```text
new configured VM -> configured geometry -> RAXHVG03
old file          -> legacy geometry     -> RAXHVG02
failed import     -> rollback restores the destination's original policy
```

Unconfigured public SDK consumers retain their original responses. A new
configured-policy record cannot restore to an unconfigured SDK VM. Admission
checks precede policy publication; restore and rollback publish the policy
while the native VM boundary excludes guest entry.

The owner tests cover 15 CPU-count partitions through 255, first and last IDs,
cache sharing, terminal subleaves, legacy SDK compatibility, both checkpoint
policies and rollback. These tests substitute SDK storage and exits: no guest
instruction executes. The complete owning target passed all 73 cases before the physical-validation
cache change. The earlier library run was explicitly superseded after the native
timeout and is not counted as a pass. The full combined-source owner target passes 73 cases, and the unfiltered
library target passes 12,445 with zero failures, 36 ignored and zero filtered.
The physical-memory integration target passes all 30 cases. Clippy and full
formatting pass. The owned build cache is removed. Actual native155 execution
remains required.

Native cases 152-154 add actual guest CPUID execution on every CPU of 1-, 2-
and 4-CPU VMs to the existing 152 controls. The guest stores all four words
from each of 14 CPUID queries before the next query clobbers registers. The
actual consumer's emit-only mode produces the exact 560 bytes independently
assembled from [queries.S](queries.S) by LLVM and decoded by NDISASM. This local
emission check runs through Rosetta without creating a VM. The native gate
always invokes the ordinary observation mode. Run `42031432817` pins the
155-case consumer. The current consumer retains these cases and adds
[48 double-shift controls](../hvf-mmio-double-shifts/README.md), requiring all
203 ordered Boolean pass records. No native topology qualification follows
from emission.

[qualification.json](qualification.json) records exact source fingerprints,
baseline and focused results, assembly bytes and compiler/signature checks.
Complete local gates pass; actual native155 results remain pending.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| T1 | Configured count and CPU IDs define a stable VM geometry | New CPUID responses | Owner dispatch over boundary counts and first/last IDs | Complete local gates pass; native155 pending |
| T2 | Old shared records used the historical geometry | Legacy restoration | Retained pre-fix dispatcher, tag-specific codec roundtrips and owner restore/rollback | Complete local gates pass |
| T3 | Native guest query bytes express the intended register stores | Native observer | Actual consumer emission equals independent LLVM output; guest results must satisfy all fields | Emission and local gates confirmed; native155 pending |

High-impact remaining work includes firmware/OS CPU discovery, complete KVM
private state, in-flight native/control profiles and the remaining A32-FP
controls. CPUID package capacity does not enumerate the active CPU set; these
changes do not supply missing MP/ACPI firmware tables. Hosted Intel validation
also does not establish bare-metal behavior (medium impact). No direct ISA,
SMIR, KVM CPUID, public C ABI or dependency behavior changes in this group.
