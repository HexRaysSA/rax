# Windows user-mode frame storage

`src/user/mm/windows_arena.rs` implements the Windows mechanics behind
`FrameArena`. Private pages and shared file extents retain one contiguous host
address range, including during replacement. CPU physical-memory caches keep
valid addresses while a view changes. An extent is 262144 bytes (64 guest pages
of 4096 bytes); its mapped file prefix is page-aligned and its remaining bytes
are private memory.

The adapter dynamically resolves `VirtualAlloc2`, `MapViewOfFile3`, and
`UnmapViewOfFile2`. Missing exports retain the pre-existing private-memory
allocator; `FrameArena::attach` explicitly returns `Unsupported` there. The
address-space fault interface classifies failed shared attachment as
`OutOfMemory`. `FrameArena::supports_shared_mappings()` exposes the OS capability
separately, and Linux process startup explicitly rejects unavailable placeholder
APIs before guest execution.

Replacement first creates the section, retains the old section handles, then
converts owned allocations to placeholders. It coalesces and splits placeholders
into exactly the new view sizes. On failure it reconstructs the old layout. If
reconstruction fails, the owner retains all reservations but revokes access.
Checked `GuestMemoryMmap` operations reject inaccessible storage; all four
user-mode CPU adapters reject run/step entry before using cached pointers.
Arbitrary external raw-pointer consumers must obey the documented quiescence
and validity contract; pointers cannot be asynchronously revoked.

Read-only objects use host copy-on-write views. Guest and debugger writes still
obey the address-space checks. This also prevents an accidental safe physical
memory write from violating host page protection. Writable objects use shared
read/write views. Synchronization flushes the view and retained backing file.
Positional file access uses bounded views plus kernel memory-copy APIs, so it
neither moves a shared file cursor nor relies on ordinary file-I/O coherence.

Windows file identities compare the complete volume serial and 128-bit file
identifier. A live interned token provides the existing two-word identity API;
no hash or truncated file ID can alias two live mapping objects.

## Assumptions and probes

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| W1 | Mapping mutations and guest execution are serialized, as required by `mm/mod.rs` | Cached pointers remain usable between API calls | Concurrent mutation would violate the owning address-space contract; test every CPU entry after injected rollback failure | retained |
| W2 | Placeholder replacement and preservation follow the archived Microsoft memoryapi contracts | Stable addresses, rollback, cleanup | Native Windows partial-view, rollback, and lifetime tests in `windows_arena::tests` | native validation required |
| W3 | Mapping identity lasts while a mapping source retains its file | Extent deduplication and read-only upgrade | Full-width identity collision partitions, concurrent registration, last-owner removal, upgrade test | covered by executable tests |

The adapter tracks n allocation fragments in a `BTreeMap`: storage O(n), lookup
O(log n), and extent replacement O(k log n) for k fragments. Current extent
layouts have at most two fragments. Arena construction takes O(n log n).

### Partial section lengths

The native Windows probe records a distinction not expressed by the
`MapViewOfFile3` documentation's page-multiple wording: a 4097-byte file maps
into an 8192-byte placeholder when `ViewSize=4097`. `ViewSize=0` fails with
error 87; `ViewSize=8192` fails with error 5. The file remains 4097 bytes long.
The adapter therefore retains both the logical view count and the page-rounded
placeholder length. Archived [native observations](windows-section-observations.json)
identify the probe commit, OS runner and job; `tools/ci/windows_section_probe.py`
independently checks the accepted request, including a nonzero file offset.
The arena regression additionally exercises guest access and the EOF boundary.
The attempted legacy `NtMapViewOfSection` replacement was rejected even for a
page-sized file on that host; it is not used by the adapter.

## Change surface and bounded findings

Affected: host memory ownership, shared backing I/O/identity, address-space
translation, four CPU execution entry points, library tests, and native CI.
Instruction decode, architectural state, SMIR semantics, ABI layouts, device
models, and hypervisor backends are unchanged. Linux/macOS retain their mmap
adapter; the shared positional I/O and identity wrappers are tested there too.

High: guest mutation must never resume execution after failed mapping rollback;
the access and CPU-entry guards are required together. Medium: native Windows file resizing while a section is mapped requires separate
lifecycle handling. The closed Linux profile rejects file resizing and memfd
creation on every host; legacy Unix host-service ftruncate is unchanged. This
adapter alone does not establish a mutable Windows-hosted Linux filesystem.
Remote-file cross-machine coherence is not supplied by Windows file mapping.

## Verification ownership

The C API CI job runs the complete `user::mm::` library slice on Windows,
macOS, and Linux. Windows-only tests exercise partial file views, cross-arena
coherence, read-only upgrade, extent reuse, retained memory ownership, successful
rollback, and quarantine at all CPU entry points. A cross-build or a non-Windows
run does not establish native placeholder behavior. The separate four-test
`user_windows_memory` target covers the vendored memory-owner/access contract.

Primary API references and retrieval hashes are retained in
`docs/specifications/windows/services/shared-memory/sources.json`.
