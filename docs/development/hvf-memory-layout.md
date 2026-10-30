# Intel HVF memory and device routing

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
