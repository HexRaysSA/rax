# AHCI DMA, completion and recovery

The single-port, 32-slot controller implements non-NCQ READ DMA EXT, WRITE
DMA EXT, IDENTIFY DEVICE, FLUSH CACHE and FLUSH CACHE EXT over 512-byte sectors.
Public command-header, PRD and FIS parsing types retain their field layouts.
The architectural source is [AHCI 1.3.1](../specifications/ahci/serial-ata-ahci-1-3-1.pdf);
[provenance](../specifications/ahci/PROVENANCE.md) records the original bytes.

Command headers and the declared 20-byte Register H2D FIS are validated before
payload DMA. A complete PRDT plan checks all descriptor reads, word alignment,
even byte counts and 64-bit address extents. An exclusive end at 2^64 is valid;
a subsequent memory-provider rejection remains a host-bus failure. PRDTL is a
16-bit entry count and DBC is a 22-bit, zero-based byte count: at most 65,535
entries, each at most 4 MiB. ATA sector count zero selects 65,536 sectors, or
32 MiB. Planning takes O(p) time and space; transferring n bytes takes O(p+n)
time. Payload staging uses at most 32 MiB, in addition to descriptor metadata.

WRITE stages every source byte before modifying media. A later source or
metadata fault preserves all media bytes. READ cannot roll back writes already
accepted by the memory provider: a later failure can leave a prefix in guest
memory. A short READ publishes its actual byte count and overflow status. A
short or oversized WRITE aborts before media changes. These policies follow
sections 6.1.5-6.1.6; they do not claim transactional guest-memory DMA.

Successful commands publish PRDBC and their completion FIS before clearing the
issued PxCI bit. A failed completion write retains PxCI even if the media write
already occurred. The engine stops and prevents implicit execution of that
command again. Software must inspect outstanding commands and perform explicit
ST stop/start recovery, as described in section 6.2.2. Software then decides
whether to issue another command. Host-bus failures set HBFS without fabricating
an ATA ABRT; ATA command errors set TFES and retain the failed slot. CCS identifies
that slot, including slot 31. ST falling clears CI, SACT and CCS. COMRESET resets
the link/device and preserves host pending bits; it does not substitute for ST
recovery. HBA reset retains media and clears controller command state.

IDENTIFY publishes a PIO Setup FIS, including transfer count and ending status,
and PSS. DMA/non-data commands publish a D2H Register FIS. Completed DMA advances
the returned LBA and clears the sector count; failed ATA commands retain their
input task-file address/count. Exhausting an IOC-marked PRD sets DPS. The
interrupt layers are separate:

```text
PxIS & PxIE -> sticky HBA IS -> GHC.IE -> interrupt_pending()
```

Clearing HBA IS while an enabled port source remains asserted immediately sets
it again. Clearing port status alone leaves sticky HBA status. Global masking
does not discard status; enabling an already-pending source asserts the line.
`clear_interrupt()` refreshes this level and does not acknowledge status.
Byte writes to W1C and RW1S registers apply only explicitly written bits. Multiword
bus accesses process their addressed register lanes without replaying W1C bits.
CAP.SAM makes GHC.AE read-only one, including immediately after HBA reset.

## Reproducible evidence

`cargo test --test ahci_dma` runs the complete owning binary: 54 tests. It includes
23 existing controls and 31 new regressions. Running the unchanged test source
against the actual original controller produces 25 passes and 29 failures.
Tests cover late/partial DMA failures, completion faults, no implicit retry,
malformed descriptors, 64-bit extent boundaries, short/excess transfers,
interrupt masks/acknowledgements, register lanes, slot identity, recovery and
an actual 32 MiB count-zero transfer through eight maximum-sized PRDs.

Build the selected checkout's library, then run:

```sh
python3 tools/ahci-diff/dma_oracle.py --repo . \
  --work-dir /path/to/empty-evidence-directory \
  --target-dir /path/to/cargo-target --llvm-bin /path/to/llvm-bin
```

The tool assembles a bare-metal x86 PCI/AHCI guest and executes it under installed
QEMU TCG. Eleven scenarios issue 18 actual commands. Inputs, guest source/ELF,
all raw register/FIS records, outputs and before/after media are retained and
hashed. An independent Python byte-addressed model checks QEMU payload/media
before current production controller sources replay the identical inputs.
Product records and a field/byte difference file retain every raw difference.
The shared result includes CI, PRDBC, global interrupt, ATA error/ready/busy/DRQ,
link presence, 8,448 payload bytes and 360,448 media bytes.

Raw profiles differ: QEMU reports ATA DSC, Gen1 link speed and different command
slot/running-bit readback, lacks the observed IOC/DPS reports, and produces extra
D2H/PIO status for IDENTIFY. The 512-byte IDENTIFY profiles differ in 84 bytes;
both report the actual 64-sector reference capacity. These are recorded differences,
not whole-controller equivalence. Shared D2H task-file address/count bytes match.
QEMU execution is independent emulation evidence, not physical SATA execution.

## Assumption register

| ID | Assumption and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| A1 | `Mem` false means failed DMA; it does not identify parity vs bad address. HBFS classification depends on this abstraction. | Header/FIS/late PRD/data/PRDBC/FIS failures; partial failed writes. Any false completion or fabricated ATA success falsifies it. | Tested locally; parity classification unknown. |
| A2 | READ prefixes cannot be undone; WRITE sources can be staged before media effects. | Late-source failure preserves every media byte; read-prefix tests explicitly retain accepted bytes. | Tested. |
| A3 | PRD bounds use byte counts and exclusive u128 ends. | Odd addresses/counts, wrap, exact 2^64 end and 4 MiB entries; count-zero 32 MiB transfer. | Tested. |
| A4 | Completion errors require explicit recovery, even after committed media effects. | PRDBC/D2H faults, repeated issue, queued later slots, slot31, ST/reset recovery. Automatic replay falsifies this contract. | Tested. |
| A5 | COMRESET preserves CI/SACT; ST falling clears them. | Direct primary register/state tables and pending-bit/media regression. Initial clearing hypothesis was rejected by the primary source. | Corrected and tested. |
| A6 | QEMU is an independent reference with a distinct device profile. | Raw records and explicit field/byte differences; independent payload/media model. Hidden normalization or a shared-result mismatch fails comparison. | Bounded evidence; no complete equivalence claim. |
| A7 | Vec-backed FLUSH has no pending host writes. | Both FLUSH opcodes complete without PRDT/payload DMA and preserve media. | Tested; physical persistence unknown. |
| A8 | Host controller consistency is separate from VM scheduling/checkpoint closure. | Future boot, PCI interrupt routing, outstanding DMA and snapshot tests. | Integration remains open. |

## Bounded scope and quality gates

High impact: full Linux AHCI boot, PCI interrupt routing, storage image durability
and complete checkpoint device/media state remain integration requirements.
Medium impact: NCQ/FPDMA, ATAPI, SATA wire timing, software-reset control FISes,
hot-plug and staggered spin-up remain unsupported. Invalid software that posts CI
with ST clear retains the pre-existing local queue-until-start behavior; the AHCI
specification requires software to issue with ST set. Malformed outgoing command
FIS rejection is a bounded local policy, not a model of physical link corruption.
Low impact: model/serial/link-speed differences belong to explicit device profiles.

Delivery requires all owning tests on native Apple Silicon and translated Intel,
complete unfiltered native/translated library inventories, C API tests, build,
Clippy, formatting, documentation, CI selection checks, source-bound independent
capture/replay and exact owned-path staging. These are gates, not assertions that
an unfinished validation run has passed. Native KVM, Intel HVF, physical SATA,
full-state checkpoint and Linux boot are separate evidence boundaries.
