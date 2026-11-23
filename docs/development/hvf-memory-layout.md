# Intel HVF memory and device routing

[Scalar guest TF completion](hvf-mmio-guest-debug/README.md) now supersedes the historical TF rejection below; data/I/O breakpoint synthesis remains open.

Intel HVF now maps reported RAM, excluding fixed MMIO pages and exact live PCI
BAR windows rounded outward to 4096-byte pages. It retains the backing mmap for
the lifetime of the shared mapping owner. The wrapper's extra 4 GiB allocation
does not become native guest RAM. RAM above 4 GiB remains eligible for mapping;
the fixed APIC windows are excluded independently of the RAM size.

Previously, registration mapped the entire padded backing, and EPT inspection
classified that same backing as RAM. Independently, an actual VMM regression
showed the e1000 STATUS register returning `03 00 00 00` through its attached PCI
model and `FF FF FF FF` through the hardware-exit MMIO bus.

## Ownership and publication

`src/backend/hvf/memory_layout.rs` computes two interval sets: native page
mappings and logical byte-level RAM. Padding belongs to neither. Ordinary RAM
bytes sharing a page with a subpage device remain logical RAM, although that
whole page must trap. Instruction and page-table inspection reads only logical
RAM, while EPT classification uses the native mapping set.

`native_memory.rs` retains backing and a VM-wide layout lock shared by all
CPUs. Before each SDK entry, it compares the exact live BAR decode with the
published layout. Relocation, COMMAND memory-decode changes, size probing, and
restored PCI state are reconciled before entry. Equal page layouts require no
SDK calls, including byte-level relocation inside one page. A shared guard
excludes remapping throughout each native entry; updates use an exclusive guard.
CPU construction can precede registration, preserving the existing call order;
guest entry requires registration of the exact backing supplied to that CPU.

Mapping changes remove only obsolete intervals, then add new intervals. Layout
publication follows successful completion. A failure reverses completed calls
in reverse order. The installed SDK's `hv.h` documents page alignment and
success/error return codes but does not establish failure atomicity. Therefore
**every production SDK map/unmap error prohibits further entry**, even when all
recorded inverse calls succeed. Portable atomic test adapters can establish a
recoverable rollback; that is not a claim about the native SDK.

The VMM constructs fixed devices before Intel registration. Its MMIO bus gives
fixed mappings priority, then dispatches exact active PCI BARs, then collateral
reported RAM, then open bus. Only Intel HVF enables the RAM fallback. PCI routing
also serves other hardware-exit producers. Reads/writes preserve one callback
per contiguous owner. RMW holds the bridge and endpoint transaction; collateral
RAM RMW holds its physical memory domain across read, transform, invalidation,
and write. Cross-owner RMW is rejected before any device callback or RAM write.

### Split MMIO admission

The bus resolves each span of a read or write before it invokes the first
device callback. For collateral RAM spans it checks the backing and access
permissions during admission. A failed admission leaves the caller's read
buffer and any earlier device spans untouched. The transfer plan uses no
heap storage for a single span and stores one routing entry per additional
span. The VMM serializes PCI configuration and device dispatch.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Availability of a later PCI route determines whether a split transfer can start. | High | Start a 32-byte transfer in a fixed device window with a poisoned PCI lock. Require zero device callbacks and unchanged input bytes. An access confined to the fixed window must still succeed. |
| A live BAR owns its span even if overlapping collateral RAM lacks backing. | High | Split a 32-byte transfer across the BAR and unbacked RAM. Require zero callbacks for the rejected transfer and one callback for an access confined to the BAR. |

Both regressions reached an earlier device callback on the parent revision.
The candidate passed all 25 bus tests. Eight unfiltered Linux binaries passed
212 tests with 40 ignored. They cover portable HVF plans, PC boot, PCI and
runtime checkpoint restoration, and the running native KVM cases. The
Linux test log SHA-256 is
`688db0c51482b1b103aba89572ca8ff428f849ea942a03f21128697f67b11db9`.
These checks cover pre-dispatch admission under the VMM's serialized
device and bridge ownership.

The unfiltered macOS arm64 library run reported 13,314 passed, one failed
and five ignored. The sole failure was the procfs TID-reuse assertion in
the archived fixture. Commit `510a9b766` subsequently switched that
fixture to explicit `clone3` TID selection. The corrected case passes
independently on Intel Linux. The full macOS log SHA-256 is
`7af156d94fd2786167865bfc9fab12aa38fa59142aff32290cec469f05a171ca`.

### PCI BAR boundaries and dispatch priority

The first live PCI BAR that contains the start address owns the span
until its end or the start of an earlier BAR. A lower-priority BAR
boundary or a collateral RAM boundary inside that span cannot split
the device callback. A true change of owner still splits a read or
write. Read-modify-write rejects that change before notifying either
owner. Dispatch follows the bridge's existing iteration order. Planning
scans the live ranges until it finds the owner, taking O(number of
ranges) time and space per span, including the live range list.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The bridge dispatches to the first live BAR in priority order. | High | Cross the beginning and end of both earlier and later BARs inside a wider BAR, and compare each endpoint's observed transfer width and contents. |
| Collateral RAM has lower priority than a live BAR. | High | Put the reported RAM end inside the eight-byte BAR transfer and require one eight-byte callback for reads and writes and one pair for RMW. |

The parent failed both BAR-boundary regression tests. The candidate passed
all 28 focused bus cases. The complete Intel Linux library and eight
integration targets reported 14,499 passed and 140 ignored, with zero
failures or filtered tests. The complete log SHA-256 is
`da05fb621198b6f7ae739a150641d230cee0817c86387e74930f8cefc3e7a821`.

## Validation and boundaries

Recorded local validation passed **136 selected tests**: 14 mapping/adapter,
45 library, 65 adjacent MMIO/translation/event/SDK, and 12 CI tooling tests.
Intel-target compilation, workspace library checking, Clippy, formatting,
workflow YAML parsing, and test registration checks passed. Physical Intel
execution and remote CI were not performed.

The `hvf_memory` Cargo target tests the actual interval policy and actual native
mapping adapter with a substituted SDK. It covers reported limits, fixed holes,
subpage ownership, RAM above 4 GiB, overlapping holes, checked extents, relocation,
decode changes, restored PCI configuration, rollback, terminal error admission,
backing identity/lifetime, and the entry guard. These tests execute no hardware
virtualization and no guest instructions.

Library tests exercise real runtime PCI attachment and bus routing, device
transaction widths, RAM/padding boundaries, RMW, lock failures, existing bus
behavior, and tracked memory writers. See the adjacent qualification JSON for
exact command results and source identity. The pre-fix VMM failure is retained
outside the checkout at `four-findings-hvf-rmw/memory-layout-v1` in the audit
workspace. Intel target compilation is separate from physical Intel execution.

Assumptions and falsification probes:

| ID | Assumption | Probe |
|---|---|---|
| M1 | Reported size defines native RAM; padding is backing only | Boundary tests and exact SDK map arguments |
| M2 | Device/configuration callbacks are serialized between VMM turns | Runtime dispatch, relocation/restore tests; native entry guard test |
| M3 | Intel HVF uses 4096-byte pages | Native Intel host/SDK qualification; portable rounding tests establish policy only |
| M4 | A failed SDK call may have partial effects | Default terminal entry fence; simulated SDK failure tests |

High-impact remaining gates include physical Intel SDK execution, complete
native private/in-flight checkpoint state, interrupt-controller coherence,
bounded multi-CPU native scheduling, and complete instruction profiles. The
existing EPT decoder still rejects certain cross-page mixed RAM/MMIO operands,
atomic forms outside its supported table, string/vector accesses, and TF cases.
Native instruction or page-table fetch from a collateral unmapped RAM page also
requires an execution/translation fallback that this scalar data-exit path does
not provide.
This group does not establish their semantics. PC firmware/E820 consistency for
large RAM and relocated BARs also needs independent validation. External bridge
configuration mutations concurrent with hardware entry are outside the current
single-owner VMM servicing contract. Source inspection and simulated calls do
not establish native Intel behavior or complete C-HVF/C-STATE/C-SMP/A32-FP.
