# S5L8900 NAND checkpoint component

The NAND controller can now capture a versioned, self-contained component image
and admit it into a detached owner. The full S5L CPU/device producer, shared UART
publication and matching RAM transaction remain required; these methods alone do
not make S5L VM checkpoints complete.

The image preserves all controller fields, cached data and spare bytes, FIFO
position, pending page writes, all 512 DMA bank/page entries, multi-page position,
kernel stage, cached VFL discoveries, unread canonical page data, the uncached VFL
scan index and five media transformation controls. Restored reads use immutable
bytes and saved controls. They never reopen the source directory or consult target
environment variables. Empty present files remain distinct from missing pages:
missing pages return zero data with spare byte 0x0a set to 0xff.

Host-backed execution keeps its existing dynamic diagnostic options. Capture
freezes their current values. Numeric noncanonical filenames such as
`00128.page` influence VFL discovery, but only canonical names such as `128.page`
can satisfy ordinary page reads. Both observations are preserved. At most 2,112
bytes per page are observable: 2,048 data bytes plus 64 spare bytes. File tails
are excluded. The 128-page block index remains sorted and deduplicated.

Capture leaves the live FIFO, buffers, cached indices and binding unchanged. It
requires externally stable media. Two complete observations detect changes
between passes; this is not an atomic filesystem snapshot and cannot prove the
absence of arbitrary concurrent writers. Numeric nonregular files and uncertain
read failures reject capture. The caller must quiesce external media writers.

The private `RAXNND01` component format uses little-endian fixed-width fields,
strict boolean/option tags, fixed-size page/spare/DMA buffers, bounded page
records and ordered block indices. It rejects truncation, trailing bytes, invalid
geometry/order/counts and excessive component size before exposing an owner.
Collection byte lengths are admitted against remaining input before allocation.
The caller supplies the component byte budget, capped at 64 GiB, and must enforce
the bundle's aggregate RAM/media budget. Component checksums/resource identity
and coordinated publication belong to the full machine producer.

Two parent regressions independently reproduced host panics from guest-visible
state: FIFO count 2,048 underflowed its page offset; bank 31 overflowed a shift.
The controller now returns zero for an out-of-buffer FIFO read while preserving
the wrapping counter, and deasserts bank selection for invalid DMA bank numbers.
An exhausted signed DMA position saturates. These are model robustness rules,
not newly claimed physical FMSS behavior. The finite BBT bitmap now handles even
`GOOD_UPTO=u32::MAX` without constructing a vector proportional to that value.
Its inclusive limit is checked at bit and byte boundaries.

The NAND implementation moved into its semantic module with its existing public
re-exports retained. The remaining oversized parent module was not otherwise
restructured. There are no ISA, SMIR, JIT, C ABI, dependency or firmware changes.


| Validation | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| New NAND checkpoint cases | 12 | 0 | 0 |
| Guest-input panic regressions | 2 | 0 | 0 |
| Complete S5L device/runtime selection | 42 | 0 | 0 |
| Unfiltered root library | 11873 | 0 | 35 |
| Unfiltered C API library | 240 | 0 | 0 |
| CI workflow regression binary | 12 | 0 | 0 |

Counts overlap: focused cases are in the unfiltered root library. The independent
wire witness additionally executes one source and one target child. Workspace
format and all-target build/check/Clippy passed. Doctests execute zero examples
with five ignored. The root suite's 35 ignored cases were not reclassified as
passing. Physical Intel/ARM1176/NAND and the known native streaming-FPSR defect
are outside this component's evidence.

Validation results and exact commands are in [qualification.json](qualification.json).
Tests use owned synthetic media; user firmware/NAND dumps and the live primary
binary are untouched. Each tested group is committed directly to `master` with
explicit `git add` paths followed by `red -m --staged --run` over the same paths.
Idle owned build/scratch roots are removed after commit. No branch/worktree is
created and no push is performed.

| Impact | Remaining requirement or evidence boundary |
| --- | --- |
| High | Full S5L core/device/in-flight/UART producer, family selection and coordinated RAM publication remain required. |
| High | External NAND media must remain stable while captured; two observations do not establish a filesystem transaction. |
| High | A32-FP, full C-STATE/C-SMP/C-HVF, native streaming-FPSR and physical Intel validation remain open. |
| Medium | Capture uses two media observations plus output storage; its logical byte limit is not a resident-memory ceiling. |
| Medium | Synthetic component tests establish model state transport, not physical NAND/ECC/FTL or firmware conformance. |

A separate public-API witness for the following clock/private-state group found
an existing host panic with deterministic divisor 1 and multiplier 2^64 - 1:
the control retires three mapped instructions, while the large multiplier
retires one and overflows before the second. That runtime timer defect remains
open; the current NAND component does not modify timer arithmetic.

Final review reproduced a budget boundary defect in the initial candidate:
128 VFL context pages in one block produced a 278,205-byte image, but live
recapture at that exact limit failed while frozen recapture succeeded. Charging
only unique block entries fixes the disagreement. The regression also repeats
numeric filename aliases and checks that one byte below the limit still fails.
The initial complete root run passed but was superseded by qualification of the
corrected source; it is not used as the final result.

The boundary fixture is exact integer byte arithmetic:
`6289 + 128 * (12 + 2112) + 8 + 32 + 4 = 278205 bytes`
(controller header, page records, page count, bank block counts, one unique block).
The initial preflight overcharged context entries by `512 - 4 = 508 bytes`;
after its omitted 40-byte media envelope, the erroneous excess was 468 bytes.

An allocator-guarded parent/control probe observed the legacy maximum BBT option
request 17,179,869,184 bytes. A 1 MiB per-request guard rejected that allocation
without granting it; the parent small-limit control and both corrected controls
completed. This is allocation-request evidence, not an unbounded host-OOM test
or a total-resident-memory bound. Unsafe allocator delegation exists only in
the isolated external reproducer, with local safety arguments; product code
adds no unsafe blocks.
