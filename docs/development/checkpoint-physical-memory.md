# Physical backing in checkpoint bundles

Base snapshots record bytes `[0, reported_size)`. That omits other writable
backing, including AArch64's RAM at a nonzero physical base and explicitly loaded
high-address ELF segments. The predecessor probe preserves zero-based controls
but loses three cookie bytes after successful base restore: x86 padding,
AArch64 RAM and an actual RISC-V ELF load segment at `0x80000000`.

The RISC-V model's default `ram_base()` is zero. The test retains that successful
control separately from the explicit high-address ELF case; it does not infer a
Linux memory layout from the machine name. The ELF is produced by the installed
LLVM assembler/linker from retained assembly and linker script, then loaded by
the actual VM constructor. No guest instruction is executed.

The expanded container records every region of the supplied guest-memory map,
including physical start, length, SHA-256 and a separate bounded zstd stream.
Metadata are canonical and admitted before compressed payload allocation. Restore
requires an exact destination layout, verifies all regions before writing, then
streams chunks into the backing. Caller-controlled CPU/DMA/RAM writers must be
quiescent across capture and restore.

Section 10 (schema 1) begins with `RAXRAM01`, u32 region count and a complete
metadata table. Each entry has u64 start, u64 uncompressed bytes, 32 digest bytes
and u64 compressed bytes. Payloads follow in table order. There are at most 128
nonempty, nonoverlapping regions and 68 GiB total backing (the existing maximum
64 GiB reported RAM plus 4 GiB backing padding). Physical backing plus captured
PCI media must also fit that aggregate limit. Region data and projection checks
use fixed 64 KiB chunks with fallible output growth.

A base-only reader rejects required physical memory at its section header.
Bundle extraction must reject unhandled required components. The newly added,
unreleased `into_parts` operation becomes fallible; component-take methods permit
explicit handling without silently dropping physical state.

| ID | Assumption / dependency | Stress and falsification probe | Status |
|---|---|---|---|
| P1 | All mapped writable backing can contain state. | Actual offset RAM, padding and high ELF cookies plus discontiguous regions; every byte must survive. | Owning regression; validation receipts in remediation ledger. |
| P2 | Metadata must identify the exact target physical layout. | Duplicate/overlap/order/overflow/count/size/layout failures before payload writes. | Owning regression; validation receipts in remediation ledger. |
| P3 | Invalid compressed content must not partially restore RAM. | Late-region digest/length/truncation failures after otherwise valid records; destination bytes must remain unchanged. | Owning regression; validation receipts in remediation ledger. |
| P4 | Snapshot writers are quiescent by caller contract. | Current single-threaded VM boundary and explicit independent-writer/SMP coordination requirement. | Full coordinator remains open. |
| P5 | Reported projection and physical state describe the same bytes. | Projection digest checks, base-reader refusal and explicit required-component extraction. | Owning regression; validation receipts in remediation ledger. |

High impact: additional CPU/private/platform state, full VM/SMP quiescence,
replay and native setter transactions remain open. Medium impact:
compressed snapshots remain resident; large checkpoints require explicit resource
admission. Low impact: future region/schema changes require reader negotiation.

`Vmm::take_snapshot_bundle` captures the represented CPU-0/four-legacy-device
base, the typed PCI/device/media set when registered, and every mapped physical
region. `PhysicalMemorySnapshot::restore` also provides a standalone physical
operation. `Vmm::restore_snapshot_bundle` coordinates the represented CPU0,
private, legacy, PCI/media and physical components; its admission/publication
contract is documented in `runtime-checkpoint-bundles.md`. Additional CPUs and
platform state remain separate. Console/periodic capture and `--checkpoint` now use represented bundles and
typed detached construction; see `checkpoint-resume.md`.

For N physical bytes in R regions, capture, verification and each restore pass
are O(N) time. The projection shares the capture read pass. Restore uses a full
verification pass before its write pass. Scratch space is O(R + 65536) bytes,
plus codec state and resident compressed output O(C). The decoder window is
bounded to 2^27 bytes. Host allocation/mapping failures during the second pass
are outside the content-validation transaction guarantee. The base compressed
projection is retained separately for compatibility and contributes additional
resident compressed bytes.

Unix mappings are checked for readable capture and writable restore permissions
before dereferencing their backing. During restore, readable target chunks are
compared before writing; identical bytes retain sparse zero backing. Dirty
zero-valued source chunks still clear their target bytes. This optimization
assumes the same caller quiescence as the rest of capture/restore; it does not
assume fresh target memory is zero. Write-only Unix mappings use the write path
without a comparison read. The byte transfer costs also include bounded region
lookup work: O(N + ceil(N / 65536) log R), with R <= 128.

The pinned SHA-256 dependency is compiled with optimization level 3 in development
and inherited test profiles, with debug assertions and overflow checks retained.
The initial unoptimized dependency hashed 67,108,864 zero bytes in 10.590170709 s
on this host. Before/after probes retain the actual dependency hashes, compiler
commands, elapsed times and the digest independently checked with Python's
SHA-256. Full guest/backing byte domains, assertions and test timeouts remain
required. This changes development hashing cost; release settings are unchanged.

The matching optimized-dependency observation was 0.123441542 s for the same
67,108,864 zero bytes and independently matched digest. These are single host
observations, not confidence bounds or a guaranteed throughput ratio.
