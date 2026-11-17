use vm_memory::{Bytes, FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use super::super::{EXTENT, FrameArena};
use super::PAGE_SIZE;

fn worker_memory(arena: &FrameArena) -> GuestMemoryMmap {
    let region = MmapRegion::<()>::from_file(
        FileOffset::from_arc(arena.process_file().unwrap(), 0),
        arena.size() as usize,
    )
    .unwrap();
    GuestMemoryMmap::from_regions(vec![GuestRegionMmap::new(region, GuestAddress(0)).unwrap()])
        .unwrap()
}

#[test]
fn independent_worker_views_share_physical_writes_and_recycled_frames() {
    let arena = FrameArena::new_process_shared(2 * EXTENT, &[(PAGE_SIZE, PAGE_SIZE)]).unwrap();
    let worker = worker_memory(&arena);
    let frame = arena.alloc_zeroed().unwrap();
    assert_eq!(frame, 0);
    arena.write(frame, &[5]);
    let mut byte = [0];
    worker.read_slice(&mut byte, GuestAddress(frame)).unwrap();
    assert_eq!(byte, [5]);
    worker.write_slice(&[77], GuestAddress(frame)).unwrap();
    arena.read(frame, &mut byte);
    assert_eq!(byte, [77]);
    arena.free(frame);
    assert_eq!(arena.alloc_zeroed().unwrap(), frame);
    worker.read_slice(&mut byte, GuestAddress(frame)).unwrap();
    assert_eq!(byte, [0]);
    assert_eq!(arena.alloc_zeroed().unwrap(), 2 * PAGE_SIZE);
}

#[test]
fn retained_worker_mapping_keeps_the_physical_file_alive() {
    let arena = FrameArena::new_process_shared(EXTENT, &[]).unwrap();
    arena.alloc_zeroed().unwrap();
    arena.write(0, &[91]);
    let worker = worker_memory(&arena);
    drop(arena);
    let mut byte = [0];
    worker.read_slice(&mut byte, GuestAddress(0)).unwrap();
    assert_eq!(byte, [91]);
}

#[test]
fn removing_external_extent_restores_the_owners_shared_file() {
    use std::os::fd::AsRawFd;

    let arena = FrameArena::new_process_shared(2 * EXTENT, &[]).unwrap();
    let worker = worker_memory(&arena);
    let pa = arena.alloc_extent().unwrap();
    let external = crate::user::mm::anonymous_file().unwrap();
    external.set_len(EXTENT).unwrap();
    arena
        .attach(pa, external.as_raw_fd(), 0, EXTENT, true)
        .unwrap();
    arena.write(pa, &[42]);
    let mut byte = [0];
    worker.read_slice(&mut byte, GuestAddress(pa)).unwrap();
    assert_eq!(byte, [0]);
    arena.detach(pa);
    assert!(arena.available());
    arena.write(pa, &[73]);
    worker.read_slice(&mut byte, GuestAddress(pa)).unwrap();
    assert_eq!(byte, [73]);
    arena.free_extent(pa);
    assert_eq!(arena.alloc_extent().unwrap(), pa);
}

#[test]
fn private_arena_retains_its_existing_storage_policy() {
    let arena = FrameArena::new(EXTENT, &[]).unwrap();
    assert!(arena.process_file().is_none());
    assert!(arena.available());
}

#[test]
fn rejects_empty_physical_storage_and_rounds_to_guest_pages() {
    assert!(FrameArena::new_process_shared(0, &[]).is_err());
    assert!(FrameArena::new_process_shared(PAGE_SIZE - 1, &[]).is_err());
    let arena = FrameArena::new_process_shared(PAGE_SIZE + 1, &[]).unwrap();
    assert_eq!(arena.size(), PAGE_SIZE);
    assert_eq!(
        arena.process_file().unwrap().metadata().unwrap().len(),
        PAGE_SIZE
    );
}

#[test]
fn native_fork_preserves_shared_writes_and_private_isolation() {
    if crate::user::test_fork::isolated(
        "user::mm::arena::process_backing::tests::native_fork_preserves_shared_writes_and_private_isolation",
    ) {
        return;
    }
    for shared in [false, true] {
        let arena = if shared {
            FrameArena::new_process_shared(EXTENT, &[])
        } else {
            FrameArena::new(EXTENT, &[])
        }
        .unwrap();
        let frame = arena.alloc_zeroed().unwrap();
        arena.write(frame, &[5]);
        let at = arena.host_address(frame);
        // SAFETY: the child only writes this live allocated byte and calls
        // _exit. It allocates nothing, acquires no inherited Rust/libc locks,
        // and runs no destructors. The parent keeps the arena alive and does
        // not access the byte until waitpid confirms the child's termination.
        let pid = unsafe { libc::fork() };
        assert!(
            pid >= 0,
            "native fork failed: {}",
            std::io::Error::last_os_error()
        );
        if pid == 0 {
            // SAFETY: the initialized pointer remains mapped in the child;
            // no reference aliases this write, and the child cannot return.
            unsafe {
                std::ptr::write_volatile(at, 77);
                libc::_exit(23);
            }
        }
        let mut status = 0;
        loop {
            // SAFETY: status is writable and pid is this test's owned child.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 23);
        let mut byte = [0];
        arena.read(frame, &mut byte);
        assert_eq!(byte, [if shared { 77 } else { 5 }]);
    }
}
