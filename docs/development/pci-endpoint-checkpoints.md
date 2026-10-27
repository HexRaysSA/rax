# Optional PCI endpoint checkpoints

The e1000, UHCI and AC'97 state APIs preserve the represented endpoint-private
state separately from PCI configuration, guest RAM and VM scheduling. Capture and
restore do not run DMA, advance a frame, transmit queued network output or consume
audio. Restore validates the complete record before changing the destination.
These APIs alone do not establish a complete VM checkpoint.

| Endpoint | Tag | Representation |
|---|---|---|
| e1000 | `RAXE1K01` | All registers, EEPROM words and serial shift phase, MAC/filter tables, partial TX frame and ordered completed TX frames |
| UHCI | `RAXUHC01` | 39 bytes: I/O base, operational registers, frame base/number/modifier and every boolean of both root ports |
| AC'97 | `RAXAC901` | 316 bytes: 128 mixer words, all three 12-byte DMA channels, global control/status and sink byte counter |

Integers are fixed-width little endian; boolean bytes must be exactly 0 or 1.
Readonly model fields are restored internally without replaying register write
side effects. Guest DMA descriptor contents remain in the separately captured RAM.
Network output frames remain queued in order; the external-effect broker must
control delivery after VM restoration.

| ID | Assumption / dependency | Stress and falsification probe | Status |
|---|---|---|---|
| E1 | Every endpoint-owned field is retained. | Register/port/mixer/EEPROM-phase and DMA continuation fixtures; a missing field changes subsequent observations. | Locally tested. |
| E2 | Restore never performs DMA or external output. | Pending TX/USB/audio work, separate guest RAM and output counters; any consumption during import fails. | Locally tested. |
| E3 | Malformed input does not mutate the destination. | All prefixes, trailing bytes, strict booleans, frame geometry and DMA indices; before/after state must match on error. | Locally tested. |
| E4 | Large e1000 output queues require bounded lossless admission. | Explicit total/count/frame limits; over-limit capture must fail rather than omit frames. | Locally tested. |

High impact: the runtime must capture all endpoint and bridge records with guest
RAM/CPU state under a consistent quiescence barrier; replay output suppression and
native/boot proof remain open. Medium impact: e1000 output can accumulate without
an external consumer; checkpoint limits must be explicit. Low impact: represented
model field changes require a new record revision.

The complete endpoint owner contains 16 tests. Two additional e1000 module tests
reject capture beyond the frame-count and encoded-byte limits without dropping
state. Direct owning-source execution also covers all 57 existing endpoint tests
(75 total). The independent model checks nine actual fixtures and six explicit
continuation events, including one halted no-op: 6,669 control bytes, 98,304 RAM
bytes and 68 event bytes. All raw records and hashes are retained. These fixtures
exercise represented model behavior and do not establish full USB transfer,
audio hardware or network conformance.

e1000 capture and import admit at most 65,536 queued frames, 16,384 bytes per
frame/partial frame and 67,108,864 total encoded bytes (64 MiB). Exact byte/count
boundaries and one-over inputs are tested. Allocation is fallible. For b encoded
bytes and n frames, capture/import take O(b + n) time and additional space. UHCI
and AC'97 records require constant work/space.

The original models store all eight bits of UHCI SOFMOD and AC'97 LVI. Import
preserves those capturable values; it does not silently impose a narrower
hardware field model. The first AC'97 decoder test exposed and corrected an
incorrect LVI restriction; its failed run is retained. DMA indices that the
models internally wrap, frame alignment, EEPROM serial phases, strict booleans
and all truncated prefixes are checked before live replacement.

The [runtime-owned PCI set](runtime-pci-checkpoints.md) now coordinates bridge and endpoint capture and atomic replacement. Full VM/container and CPU/RAM quiescence remain separate.
