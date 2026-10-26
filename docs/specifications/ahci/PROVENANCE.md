# AHCI implementation reference

| Field | Value |
|---|---|
| Title | Serial ATA Advanced Host Controller Interface (AHCI) 1.3.1 |
| Issuer | Intel Corporation |
| Revision | 1.3.1; cover identifier `1_3_1.doc` |
| Publication date | Unknown; no date inferred from retrieval or filename |
| Source | https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf |
| Retrieved | 2026-10-25 |
| File | `serial-ata-ahci-1-3-1.pdf` |
| Bytes | 1705346 |
| SHA-256 | `3bbd4b7fc7dbef60948f3e56575d860ffc02a4d3571a20cd757aa2b22fa8e56a` |

The original PDF is retained without transformation, including any embedded
notices. No additional redistribution license is asserted. Its size is required
for the register, descriptor, completion, interrupt and recovery tables used by
the AHCI remediation. It is a reference input, not a runtime dependency.

Relevant sections: 3.1.1-3.1.3 (capabilities, mode and interrupt aggregation),
3.3.1-3.3.14 (port registers), 4.2.2-4.2.3 (command header and PRDT), 5.3.2,
5.3.8-5.3.9 (command/FIS transitions), 6.1-6.2 (errors/recovery), and 10.7
(interrupts). Executed QEMU reference results record the installed version and
raw inputs/outputs separately; the specification is the architectural source.
