#![cfg(windows)]

//! Ownership regression tests for the Windows external-mapping constructor.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

#[derive(Debug)]
struct Allocation {
    region: MmapRegion<()>,
    drops: Arc<AtomicUsize>,
}

impl Allocation {
    fn new(drops: &Arc<AtomicUsize>) -> Arc<Self> {
        Arc::new(Self {
            region: MmapRegion::new(65536).unwrap(),
            drops: drops.clone(),
        })
    }

    fn view(self: &Arc<Self>) -> MmapRegion<()> {
        // SAFETY: the native region is initialized read/write memory. This
        // retained Arc owns it until every external region is dropped. Tests
        // serialize accesses and use volatile accessors only; no Rust references
        // into the allocation exist. Native MmapRegion is Send + Sync and its
        // destructor releases this allocation on the last owner's thread.
        unsafe {
            MmapRegion::from_raw_with_owner(self.region.as_ptr(), self.region.size(), self.clone())
                .unwrap()
        }
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
        // Native region's own Drop subsequently releases its VirtualAlloc block.
    }
}

#[test]
fn guest_memory_snapshot_retains_external_allocation_until_last_region_drops() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Allocation::new(&drops);
    let weak = Arc::downgrade(&owner);
    let memory = Arc::new(
        GuestMemoryMmap::from_regions(vec![
            GuestRegionMmap::new(owner.view(), GuestAddress(0)).unwrap(),
        ])
        .unwrap(),
    );
    memory.write_slice(&[0x53], GuestAddress(65535)).unwrap();
    // Clone the collection itself, as well as its outer Arc. The regions must
    // keep the owner even when the original memory collection is destroyed.
    let snapshot = memory.as_ref().clone();
    drop(owner);
    drop(memory);
    assert!(weak.upgrade().is_some());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    std::thread::spawn(move || {
        let mut byte = [0];
        snapshot.read_slice(&mut byte, GuestAddress(65535)).unwrap();
        assert_eq!(byte, [0x53]);
        snapshot.write_slice(&[0xa7], GuestAddress(0)).unwrap();
        assert!(snapshot.read_slice(&mut byte, GuestAddress(65536)).is_err());
        drop(snapshot);
    })
    .join()
    .unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn releasing_one_external_view_does_not_release_a_retained_owner() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Allocation::new(&drops);
    drop(owner.view());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    // A destructor that unconditionally VirtualFree'd the external view would
    // leave this second view dangling and fault at the first actual access.
    let memory = GuestMemoryMmap::from_regions(vec![
        GuestRegionMmap::new(owner.view(), GuestAddress(0)).unwrap(),
    ])
    .unwrap();
    memory.write_slice(&[0x19, 0x27], GuestAddress(0)).unwrap();
    let mut bytes = [0; 2];
    memory.read_slice(&mut bytes, GuestAddress(0)).unwrap();
    assert_eq!(bytes, [0x19, 0x27]);
    drop(memory);
    drop(owner);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn invalid_external_ranges_are_rejected_without_retaining_the_owner() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Allocation::new(&drops);
    for (addr, size) in [
        (std::ptr::null_mut(), 65536),
        (owner.region.as_ptr(), 0),
        (owner.region.as_ptr(), usize::MAX),
        (std::ptr::without_provenance_mut(usize::MAX - 3), 8),
    ] {
        // SAFETY: the constructor explicitly rejects these malformed ranges
        // without accessing memory. Only the non-rejected case requires a live
        // allocation spanning the supplied range.
        let result = unsafe { MmapRegion::<()>::from_raw_with_owner(addr, size, owner.clone()) };
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(Arc::strong_count(&owner), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(owner);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn inaccessible_external_ranges_reject_access_without_touching_memory() {
    use vm_memory::mmap::ExternalMappingAccess;
    use vm_memory::{GuestMemory, VolatileMemory};

    #[derive(Debug)]
    struct AccessiblePrefix(AtomicUsize);
    impl ExternalMappingAccess for AccessiblePrefix {
        fn is_accessible(&self, offset: usize, count: usize) -> bool {
            offset
                .checked_add(count)
                .is_some_and(|end| end <= self.0.load(Ordering::Acquire))
        }
    }

    // Primary API contract: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualProtect(
            base: *mut std::ffi::c_void,
            size: usize,
            protection: u32,
            old: *mut u32,
        ) -> i32;
    }
    struct NoAccess<'a> {
        owner: &'a Allocation,
        previous: u32,
    }
    impl Drop for NoAccess<'_> {
        fn drop(&mut self) {
            let mut discarded = 0;
            // SAFETY: this guard borrows the live allocation; the whole mapping
            // is one committed VirtualAlloc region with no outstanding slices.
            // Restore the protection obtained from the successful earlier call.
            assert_ne!(
                unsafe {
                    VirtualProtect(
                        self.owner.region.as_ptr().cast(),
                        self.owner.region.size(),
                        self.previous,
                        &mut discarded,
                    )
                },
                0
            );
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Allocation::new(&drops);
    let access = Arc::new(AccessiblePrefix(AtomicUsize::new(65536)));
    // SAFETY: owner retains the full allocation. Accepted subranges are
    // initialized and read/write. Accesses, protection changes, and validity
    // changes below are serialized; no borrowed slice crosses such a change,
    // and no aliasing Rust references into this allocation exist.
    let region = unsafe {
        MmapRegion::<()>::from_raw_with_access(
            owner.region.as_ptr(),
            owner.region.size(),
            owner.clone(),
            access.clone(),
        )
        .unwrap()
    };
    let memory =
        GuestMemoryMmap::from_regions(vec![GuestRegionMmap::new(region, GuestAddress(0)).unwrap()])
            .unwrap();
    memory.write_slice(&[0xa5], GuestAddress(65535)).unwrap();
    access.0.store(32768, Ordering::Release);
    assert!(memory.get_host_address(GuestAddress(32767)).is_ok());
    assert!(memory.get_host_address(GuestAddress(32768)).is_err());
    let mut bytes = [0x19, 0x27];
    assert!(memory.read_slice(&mut bytes, GuestAddress(32767)).is_err());
    assert_eq!(bytes, [0x19, 0x27]);
    assert!(
        memory
            .write_slice(&[0x53, 0x75], GuestAddress(32767))
            .is_err()
    );
    let mut last_valid = [0xff];
    memory
        .read_slice(&mut last_valid, GuestAddress(32767))
        .unwrap();
    assert_eq!(last_valid, [0]); // Failed writes do not touch the valid prefix.
    access.0.store(0, Ordering::Release);
    let mut previous = 0;
    // SAFETY: the full 64 KiB range is one committed native allocation. No
    // borrow into its bytes remains, and all mapped access is now rejected.
    // PAGE_NOACCESS=1 makes a missed validity check an actual native fault.
    assert_ne!(
        unsafe {
            VirtualProtect(
                owner.region.as_ptr().cast(),
                owner.region.size(),
                1,
                &mut previous,
            )
        },
        0
    );
    let protected = NoAccess {
        owner: &owner,
        previous,
    };
    {
        let region = memory.find_region(GuestAddress(0)).unwrap();
        assert!(region.get_slice(65536, 0).is_ok());
        assert!(matches!(
            region.get_slice(0, 1),
            Err(vm_memory::volatile_memory::Error::IOError(_))
        ));
    }
    assert!(memory.get_host_address(GuestAddress(0)).is_err());
    assert!(memory.read_slice(&mut last_valid, GuestAddress(0)).is_err());
    assert!(memory.write_slice(&[0xff], GuestAddress(0)).is_err());
    drop(protected); // Restore native access before advertising validity again.
    access.0.store(65536, Ordering::Release);
    memory
        .read_slice(&mut last_valid, GuestAddress(65535))
        .unwrap();
    assert_eq!(last_valid, [0xa5]);
    drop(memory);
    drop(owner);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
