use super::*;
use crate::user::mm::process_owner::View;
use vm_memory::GuestMemory;

#[test]
fn native_imported_views_follow_shared_and_private_fork_storage() {
    const NAME: &str = "user::mm::process_owner::broker::tests::view::native_imported_views_follow_shared_and_private_fork_storage";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase != "root" {
            client
                .with(lease, |session| {
                    let view = View::import(session.access())?;
                    let mut bytes = [0];
                    view.read(BASE, &mut bytes, ReadKind::Read)?;
                    assert_eq!(bytes, [if phase == "private" { 42 } else { 43 }]);
                    view.write(BASE, &[if phase == "private" { 77 } else { 99 }], false)?;
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (view, private, shared) = client.with(lease, |session| {
            let view = Arc::new(View::import(session.access())?);
            view.write(BASE, &[42], false)?;
            let private = session.fork(true)?;
            view.write(BASE, &[43], false)?;
            let shared = session.fork(false)?;
            let foreign = view.clone();
            std::thread::spawn(move || {
                assert!(!foreign.active());
                assert!(matches!(foreign.write(BASE, &[9], false), Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied));
                assert!(foreign.physical_memory().is_err());
            }).join().unwrap();
            Ok((view, private, shared))
        }).unwrap();
        spawn(private, lease, NAME, "private").wait();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                let mut bytes = [0];
                view.read(BASE, &mut bytes, ReadKind::Read)?;
                assert_eq!(bytes, [99]);
                assert_eq!(read(session, BASE, 1), [99]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    let (mut broker, client, _) = Broker::new(
        lease.clone(),
        &initial,
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    let mut byte = [0];
    initial.read(BASE, &mut byte).unwrap();
    assert_eq!(
        byte,
        [5],
        "owner adopted independent storage before any worker ran"
    );
}

#[test]
fn native_physical_view_shares_owner_pages_and_preflights_complete_accesses() {
    const NAME: &str = "user::mm::process_owner::broker::tests::view::native_physical_view_shares_owner_pages_and_preflights_complete_accesses";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let view = client.with(lease, |session| {
            session.call(map(BASE, 20 * PAGE_SIZE, None, false))?;
            let view = View::import(session.access())?;
            assert!(view.active());
            assert_eq!(view.physical_memory()?.num_regions(), 1);
            let bytes = vec![0xa5; 18 * PAGE_SIZE as usize + 17];
            view.write(BASE + 3, &bytes, false)?;
            let mut readback = vec![0; bytes.len()];
            view.read(BASE + 3, &mut readback, ReadKind::Read)?;
            assert_eq!(readback, bytes);
            assert_eq!(read(session, BASE + 3, 3), [0xa5; 3], "owner sees worker's actual arena stores");
            write(session, BASE + 3, vec![4, 5, 6]);
            view.read(BASE + 3, &mut readback[..3], ReadKind::Read)?;
            assert_eq!(&readback[..3], &[4, 5, 6]);

            let physical = view.translate(BASE + 3, MemoryAccessKind::Read, false)?;
            let memory = view.physical_memory()?;
            let domain = crate::vm::memory::reservations::MemoryDomain::for_memory(memory);
            let monitor = domain.register();
            assert_eq!(monitor.read_exclusive(memory, physical, 1).unwrap(), [4]);
            view.write(BASE + 3, &[4], false)?;
            assert!(
                !monitor.write_exclusive(memory, physical, &[0x88]).unwrap(),
                "even a same-value worker store invalidates local exclusives"
            );
            assert_eq!(read(session, BASE + 3, 1), [4]);

            session.call(Operation::Protect { start: BASE + 18 * PAGE_SIZE, len: PAGE_SIZE, perms: Perms::READ.bits() })?;
            let first = read(session, BASE + 3, 3);
            assert!(matches!(view.write(BASE + 3, &vec![0x33; bytes.len()], false), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.address == BASE + 18 * PAGE_SIZE && fault.kind == MemoryFaultKind::Permission));
            assert_eq!(read(session, BASE + 3, 3), first, "late-page fault cannot write the prefix");
            session.call(Operation::Unmap { start: BASE + 18 * PAGE_SIZE, len: PAGE_SIZE })?;
            readback.fill(0x77);
            assert!(matches!(view.read(BASE + 3, &mut readback, ReadKind::Read), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.address == BASE + 18 * PAGE_SIZE));
            assert!(readback.iter().all(|byte| *byte == 0x77), "late read fault leaves caller output intact");
            Ok(view)
        }).unwrap();
        assert!(!view.active());
        assert!(
            matches!(view.write(BASE, &[9], false), Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        client
            .with(lease, |_| {
                view.write(BASE, &[42], false)?;
                Ok(())
            })
            .unwrap();
        drop(client);
        assert!(
            matches!(view.write(BASE, &[9], false), Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::NotConnected)
        );
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(
        lease.clone(),
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_physical_view_maps_actual_file_and_replaces_reused_extents() {
    const NAME: &str = "user::mm::process_owner::broker::tests::view::native_physical_view_maps_actual_file_and_replaces_reused_extents";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let view = View::import(session.access())?;
                session.call(map(SHARED, PAGE_SIZE, Some(BackingId(1)), true))?;
                let old = view.translate(SHARED, MemoryAccessKind::Write, false)?;
                view.write(SHARED, &[31, 32], false)?;
                assert_eq!(read(session, SHARED, 2), [31, 32]);
                session.call(Operation::Unmap {
                    start: SHARED,
                    len: PAGE_SIZE,
                })?;
                session.call(map(SHARED, PAGE_SIZE, Some(BackingId(2)), true))?;
                let new = view.translate(SHARED, MemoryAccessKind::Write, false)?;
                assert_eq!(
                    old, new,
                    "fixture must exercise actual physical extent reuse"
                );
                let mut bytes = [0; 2];
                view.read(SHARED, &mut bytes, ReadKind::Read)?;
                assert_eq!(
                    bytes,
                    [7, 8],
                    "old file overlay cannot survive physical extent reuse"
                );
                view.write(SHARED, &[41, 42], false)?;
                assert_eq!(read(session, SHARED, 2), [41, 42]);
            session.call(Operation::Unmap { start: SHARED, len: PAGE_SIZE })?;
            let Operation::Map { mut mapping } = map(SHARED, PAGE_SIZE, Some(BackingId(3)), true) else { unreachable!() };
            mapping.perms = Perms::READ.bits();
            session.call(Operation::Map { mapping })?;
            let physical = view.translate(SHARED, MemoryAccessKind::Read, false)?;
            assert_eq!(physical, old);
            // SAFETY: sysconf takes no caller-owned pointers.
            let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
            use vm_memory::{Bytes, GuestAddress};
            let mut tail = [0];
            view.physical_memory()?.read_slice(&mut tail, GuestAddress(physical + host_page)).unwrap();
            assert_eq!(tail, [0], "short replacement must restore the old overlay's entire tail to the arena file");
            assert!(matches!(view.write(SHARED, &[9], false), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.kind == MemoryFaultKind::Permission));
            assert!(matches!(view.write(SHARED, &[9], true), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.kind == MemoryFaultKind::Permission));
            assert!(matches!(view.read(SHARED, &mut bytes, ReadKind::Fetch), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.access == MemoryAccessKind::Fetch));
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let one = Arc::new(SharedObject::anonymous(EXTENT).unwrap());
    let two = Arc::new(SharedObject::anonymous(EXTENT).unwrap());
    two.write_all_at(0, &[7, 8]).unwrap();
    // SAFETY: sysconf takes no caller-owned pointers.
    let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    two.write_all_at(host_page, &[0x66]).unwrap();
    let short = Arc::new(SharedObject::fixed(
        one.host_file().unwrap().try_clone().unwrap(),
        false,
        host_page,
    ));
    let (mut broker, client, worker_id) = Broker::new(
        lease.clone(),
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    for object in [&one, &two, &short] {
        broker
            .register_backing(
                worker_id,
                Backing::Shared {
                    object: object.clone(),
                    offset: 0,
                },
            )
            .unwrap();
    }
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    use std::os::unix::fs::FileExt;
    let mut bytes = [0; 2];
    one.host_file()
        .unwrap()
        .read_exact_at(&mut bytes, 0)
        .unwrap();
    assert_eq!(bytes, [31, 32]);
    two.host_file()
        .unwrap()
        .read_exact_at(&mut bytes, 0)
        .unwrap();
    assert_eq!(
        bytes,
        [41, 42],
        "native host file sees worker stores without a broker copy"
    );
}
