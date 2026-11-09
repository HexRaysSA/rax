# Checked Windows RAM commitment

Windows VM RAM retains the reported RAM length and the historical 4 GiB backing
padding. Its private adapter reserves the complete anonymous address range and
commits admitted subranges with `VirtualAlloc`. A failed commitment rejects the
checked memory access. The reservation and committed pages remain live through
every region alias, and the last owner releases the reservation.

The owner records committed native pages in a mutex-protected bitmap. Commitment
is monotonic: an existing page retains its contents, and a newly committed page
starts at zero. Snapshot capture and publication already require independent
writers to be stopped. At that boundary, reads copy committed pages through
vm-memory's volatile accessor and fill scratch with zeros for untouched pages.
This avoids charging all padding to the paging-file commit limit merely to hash
or compare a checkpoint. Ordinary mappings retain the existing read path.

The x86 MMU's cached physical, typed and bulk pointers admit their complete byte
range through the Windows mapping accessor before dereference. Bounds, MMIO
routing, guest translation and other hosts retain their existing contracts.
These methods live in `src/isa/x86_64/memory/ram.rs`; their public method paths
remain unchanged. Raw external aliases retain the mapping constructor's range
admission and lifetime requirements.

## Reproduced failure

The preceding unpublished adapter used private sparse files. An immutable native
Windows ARM64 image, SHA-256
`7a8092b85c8847d1c66ae4f448d88783dcf5e9deca6c7f9abff316ad920c610d`,
reproduced the failure in exactly
`vm::runtime::aarch64_cluster_tests::complete_shared_platform_restores_and_missing_smp_state_rejects_before_mutation`
on kernel 10.0.29698.0. Its debugger observed first- and second-chance
`STATUS_IN_PAGE_ERROR` (`0xC0000006`). The three exception parameters identified a
read, address `0x0000024abb570000`, and underlying `STATUS_DISK_FULL`
(`0xC000007F`). `VirtualQueryEx` and `K32GetMappedFileNameW` associated that address
with the adapter's private `rax-ram-*.tmp` mapping. The faulting instruction was
inside the installed `vcruntime140.dll`. The original full run had the same
exception/module signature; its original exception parameters were not captured.

Microsoft documents that reading or writing a mapped sparse-file hole can
allocate disk space and raise an in-page exception when the disk is full. Skipping
identical checkpoint writes therefore did not remove the read-side failure.
The anonymous reservation replaces that unpublished file-backed adapter.

## Verification surface and limits

The owning tests cover allocation failure without publishing commitment bits,
invalid and empty ranges, cross-page contents, aliases, independent allocations,
foreign-mapping fallback, and complete zero scanning of a 4 GiB + 65,536-byte
extent while bounding private commit. A shared x86 test exercises cached physical
access, all typed widths, a page-crossing write, and subsequent snapshot reads.
Checkpoint reservation invalidation, physical-memory cache tests and the original
failing shared-platform test remain required owning gates on all three hosts.

This does not change a checkpoint format, public C ABI, advertised RAM length or
backing padding. Whole-VM restoration retains its existing host-resource failure
and stopped-writer requirements. The complete library and process-support gates
remain separate from focused tests. Full checkpoints still hash and compress all
logical backing bytes; reducing that CPU cost is outside this change.

For a backing length of `B` bytes and native page size `P` bytes, the bitmap uses
`8 * ceil(ceil(B / P) / 64)` bytes. At the maximum 68 GiB backing length and a
4,096-byte native page, this is 2,228,224 bytes (2.125 MiB). Commitment examines
the requested pages; a stopped read visits its covered pages and output bytes.
Lookup among live private mappings is linear in their count. The bitmap and
scratch, rather than eagerly committed padding, hold the adapter's bookkeeping.

Primary contracts:

- [VirtualAlloc reservation, zeroing and recommit semantics](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).
- [Exception parameters, including the underlying in-page NTSTATUS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record).
- [Sparse and compressed file-view paging failures](https://learn.microsoft.com/en-us/windows/win32/memory/reading-and-writing-from-a-file-view).
- Windows SDK `shared/ntstatus.h`: `STATUS_DISK_FULL = 0xC000007F`.
