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
