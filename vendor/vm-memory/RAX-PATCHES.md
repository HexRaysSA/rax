# vm-memory 0.17.1 local patch

Upstream: rust-vmm/vm-memory, commit
`75f3b2c96dc75920ae7e9171ee0eef4b0adb2d21`, crates.io version `0.17.1`.
`UPSTREAM.json` records SHA-256 digests of the original distributed files.
The upstream manifests, licenses, tests, and Unix implementation are retained.

The Windows `MmapRegion::from_raw_with_owner` constructor retains an external
allocation owner. Its destructor delegates release to that owner instead of
assuming the memory is one `VirtualAlloc` allocation. This permits an arena
made from multiple native allocations while preserving ownership through
`GuestRegionMmap` and cloned `GuestMemoryMmap` references. The constructor is
unsafe: its caller must prove the mapping lifetime, initialized bounds,
accessibility, aliasing, and synchronization contract documented on the method.

This additive constructor does not alter default features, the version,
existing constructors, or Unix mapping behavior. RAX's Windows ownership tests
are in `tests/suites/user/windows_memory.rs`.

Builds that use this patch require the full RAX source checkout. Cargo excludes
nested packages from the parent `.crate` archive; the parent archive does not
bundle this dependency. Native SDK packaging builds from the source checkout.

Two pre-existing trailing spaces in `CHANGELOG.md` were removed to satisfy
the repository diff check. The upstream changelog text is otherwise unchanged.

The Windows `from_raw_with_access` constructor also accepts a synchronized
`ExternalMappingAccess` validator. Volatile access and host-pointer lookup reject
inaccessible subranges before dereferencing them. This lets an external owner
quarantine a range after failed native remapping while retaining its reservation.
The owner must serialize mapping changes against every operation, borrowed slice,
and raw-pointer user. In particular, a cached CPU pointer is not automatically
revoked by the validator. The original owned constructor remains unguarded.
The additional source changes are confined to `src/mmap/windows.rs` and the
Windows branch of host-address validation in `src/mmap/mod.rs`.

Rust 1.89 and later warn `mismatched_lifetime_syntaxes` when a signature
elides a lifetime on `&self` / `&mut self` and hides that same lifetime
inside a type path (`WithBitmapSlice`, `VolatileSlice`, `VolatileRef`,
`VolatileArrayRef`, `BS`, `MS`). Those return types now spell the lifetime
as `'_`. The types are unchanged. The same signatures are adjusted on the
Unix, Windows, and Xen mmap backends so each target builds without the lint.

Hosts in `target_family = "wasm"` that are neither `unix` nor `windows`
(wasm32-unknown-unknown and WASI) use an anonymous-memory backend in
`src/mmap/wasm.rs`, selected in `src/mmap/mod.rs`. Regions are zero-filled
heap allocations aligned to 4 KiB. Protection and mapping flags are recorded
and not enforced. A file-backed region copies the file range through the
`File` cursor and then restores the cursor; it is not a shared mapping.
Emscripten is both `wasm` and `unix` and keeps the Unix backend. On these hosts
`AtomicBitmap` (`backend-bitmap`) tracks dirty pages at 4 KiB.

wasm32 is the only 32-bit host the `lib.rs` target gate admits, and
`AtomicI64`/`AtomicU64` access is enabled for `wasm32` and `wasm64`. Region
offsets are `u64`, so the `GuestMemoryRegionBytes` accessors and
`GuestRegionMmap::get_slice` convert them with `region::host_offset`, and the
slice iterator clamps a region capacity that exceeds `usize`. An offset above
`usize::MAX` is the `InvalidBackendAddress` error a 64-bit host returns for the
same offset; it no longer truncates to a lower offset. Every conversion
succeeds on 64-bit hosts, so their behavior is unchanged.

The backend tests in `src/mmap/wasm.rs` run only on a wasm target. WASI has no
`std::env::temp_dir`, so the file-backed test needs `TMPDIR` to name a
preopened directory. The `vmm-sys-util` dev-dependency does not build for
WASI, and upstream tests that spawn threads or use `catch_unwind` cannot pass
on wasm32-wasip1 (no threads; panics abort).
