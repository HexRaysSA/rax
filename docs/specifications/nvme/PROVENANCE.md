# Audit reference inputs

These unmodified snapshots preserve the exact sources used by the remediation.
They satisfy AGENTS.md section10.4;applicable copyright/license notices remain
in each original. Local source archival does not establish installed-reference
binary identity or permission to redistribute elsewhere. No publication is performed.

- NVM Express Base Specification,Revision1.4c,2021-06-28
  - Source: https://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_4c-2021.06.28-Ratified.pdf
  - Retrieved: 2026-10-24
  - File: `NVM-Express-1_4c-2021-06-28.pdf`
  - SHA-256: `ff92005660e8b58e248b2ff1416acc8c8c1aba1b3b7c14f6de9b80f2181649bc`
  - Size: 4832211 bytes.
- QEMU NVM Express Controller,upstream tagv11.1.0,hw/nvme/ctrl.c
  - Source: https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/nvme/ctrl.c
  - Retrieved: 2026-10-24
  - File: `qemu-v11.1.0-nvme-ctrl.c`
  - SHA-256: `4acb4a66699130a22b2492845e6341be24c51b5c55d1aa601d3ccd17f2dc5dc2`
  - Size: 314987 bytes.

Size justification:these bounded vendor specifications/source snapshots are needed
for field/encoding/status verification and reproducible review. They are reference
inputs,not generated corpora. Derived scratch text/images remain external evidence.

The QEMU source retains its GPL-2.0-or-later header. Its tag/hash explains
reference implementation limits;the executed Homebrew QEMU11.1.2 is a separate
artifact. NVMe1.4c supplies the architectural contract.
