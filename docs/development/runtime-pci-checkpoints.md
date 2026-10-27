# Runtime PCI state ownership

`vm::runtime::pci_state::PciDevices` owns the typed controller handles registered
behind the x86 PCI bridge. `Vmm` retains this set, including the host bridge when
optional endpoints are disabled. Firmware assignments and guest DMA memory stay
identical to the previous registrations. Shared MMIO adapters preserve typed
ownership rather than erasing the only handle into `Box<dyn MmioDevice>`.

`checkpoint()` holds the bridge lock across every endpoint capture. This excludes
concurrent bridge MMIO/PIO operations and their synchronous DMA while the device
set is collected. It does not stop independent CPU or RAM writers: callers must
establish a VM-wide quiescent boundary separately. Calls acquire bridge before
endpoint locks; callers must release any bridge guard before capture/restore.

Restore parses every endpoint into a detached candidate before touching the live
set. It then acquires bridge and endpoint guards, atomically validates/restores
the bridge and replaces each model without a fallible operation between swaps.
Any malformed record, mismatched topology or poisoned lock before commit leaves
live bridge/endpoints unchanged. RAM and source image files are not modified.
Restored writable media remain detached, with read-only protection retained.
NVMe/AHCI/UHCI device origins must remain zero behind BAR-relative dispatch.

The original registration topology is checked before capture/restore. External
registration of untracked functions/handlers is rejected; arbitrary private
handler state cannot be silently omitted. Ordinary guest writes to config bytes,
BARs and decode controls remain valid. The same live handler adapters and Arc
identities remain registered across restoration.

| ID | Assumption / dependency | Stress/falsification probe | Status |
|---|---|---|---|
| R1 | Typed handles identify the actual registered controllers. | Actual PCI configuration, DMA writes, BAR moves, mixer/USB/NIC changes and checkpoint export must match. | Locally tested. |
| R2 | Bridge locking excludes concurrent guest I/O during device capture. | Concurrent bridge writes/captures and correlated media/control states; independent RAM writers still require VM quiescence. | Locally tested. |
| R3 | Restore is atomic across all models. | Corrupt each component and the bridge after otherwise valid changes; before/after exports, guest RAM and host files must match on error. | Locally tested. |
| R4 | Restored backing must not repeat external writes. | Actual persistent images, restored changed media, subsequent guest writes and source-file byte comparison. | Locally tested. |
| R5 | BAR-relative origins and registration topology are runtime invariants. | Nonzero endpoint origins, missing/extra endpoints and untracked registrations must reject before mutation. | Locally tested. |

High impact: container sections, all CPU/private/platform state, complete VM
quiescence, replay policy and native/boot validation remain open. Image-backed
`Vmm` checkpoint capture/restore guards remain until that integration is complete.
Medium impact: all media are resident and captured with fallible copies; aggregate
RAM/media admission is separate. Low impact: adding another endpoint requires
explicit typed ownership and a corresponding record.

The complete `runtime_pci_checkpoint` owner runs 15 tests. It exercises actual
bridge configuration and coherent guest-memory DMA, COW/persistent/readonly
media, CQ backpressure without replay of a completed write, fatal AHCI state,
all component failures, topology/origin rejection, concurrent correlated MMIO
updates and a poisoned bridge. The original failed audio-window expectation is
retained: input 0x56 is masked to 0x16 by the existing volume-register model;
the corrected expectation preserves that same input.

The independent model predicts five source/restored/continued fixtures and
four acknowledgement writes. It checks 29,126 control bytes, 65,536 media bytes,
1,310,720 guest-RAM bytes and 32,768 source-file bytes. It composes explicit PCI,
NVMe and AHCI expectations with the earlier independent endpoint model; it does
not call product decoders. Source/library/tool/artifact hashes bind each run.

For p total media/network-state bytes and f bridge functions, capture takes
O(p + f log f) time and O(p + f) additional space. Restore validates and moves
media into detached candidates in O(p + f) time/space; the final live swaps have
constant work for the fixed five-endpoint profile. The caller still owns the
RAM/CPU quiescence and aggregate memory budget.
