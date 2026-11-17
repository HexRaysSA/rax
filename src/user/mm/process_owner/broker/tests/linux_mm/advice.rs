use super::*;
use crate::user::linux::abi::errno_table::EINVAL;
use crate::user::linux::abi::open::O_RDWR;
use crate::user::linux::fs::fd::{FileObject, FileType, OpenFile};
use crate::user::linux::fs::memfd::{Memfd, seal};
use crate::user::mm::anonymous_file;

const FILE: u64 = HEAP + 4 * PAGE_SIZE;

#[test]
fn native_advice_keeps_actual_closed_memfd_inode_across_private_and_shared_workers() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::advice::native_advice_keeps_actual_closed_memfd_inode_across_private_and_shared_workers";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "private" || phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(
                        remote::madvise(&session.access(), FILE, PAGE_SIZE, 9)?,
                        Err(Errno(EPERM))
                    );
                    assert!(session.access().active());
                    assert_eq!(read(session, FILE, 1), [87]);
                    assert_eq!(read(session, HEAP, 1), [17]);
                    assert_eq!(
                        remote::madvise(&session.access(), HEAP, PAGE_SIZE, 4)?,
                        Ok(0)
                    );
                    assert_eq!(read(session, HEAP, 1), [0]);
                    if phase == "private" {
                        write(session, HEAP, vec![29]);
                        write(session, FILE + PAGE_SIZE, vec![37]);
                    } else {
                        assert_eq!(read(session, FILE + PAGE_SIZE, 1), [37]);
                        write(session, HEAP, vec![41]);
                    }
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (private, shared) = client
            .with(lease, |session| {
                session.call(Operation::ReleaseBacking {
                    backing: BackingId(1),
                })?;
                assert_eq!(
                    remote::madvise(&session.access(), FILE, PAGE_SIZE, 9)?,
                    Err(Errno(EPERM))
                );
                assert!(session.access().active());
                Ok((session.fork(true)?, session.fork(false)?))
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [41]);
                assert_eq!(read(session, FILE, 1), [87]);
                assert_eq!(read(session, FILE + PAGE_SIZE, 1), [37]);
                assert_eq!(
                    remote::madvise(&session.access(), FILE, PAGE_SIZE, 9)?,
                    Err(Errno(EPERM))
                );
                assert_eq!(
                    remote::munmap(&session.access(), LinuxAbi::Aarch64, FILE, 2 * PAGE_SIZE)?,
                    Ok(0)
                );
                session.call(Operation::Stats)?;
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let original = space();
    original
        .map(HEAP, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    original.write(HEAP, &[17]).unwrap();
    let mut file = anonymous_file().unwrap();
    file.write_all(&vec![87; 2 * PAGE_SIZE as usize]).unwrap();
    let identity_owner = SharedObject::file(file.try_clone().unwrap(), true).unwrap();
    let identity = identity_owner.identity();
    let inode = Memfd::new(0, false, identity).unwrap();
    let retained = Arc::downgrade(&inode);
    let description = OpenFile::with_memfd(
        FileObject::Host(file),
        FileType::Regular,
        "/memfd:owner-advice",
        None,
        O_RDWR,
        Some(inode.clone()),
    );
    let closed = Arc::downgrade(&description);
    let object = Arc::new(
        SharedObject::file_keeping(
            description.host_file().unwrap().try_clone().unwrap(),
            true,
            description.mapping_keep(),
        )
        .unwrap(),
    );
    assert_eq!(object.identity(), identity);
    drop(identity_owner);
    let backing = Backing::Shared { object, offset: 0 };
    original
        .map(
            FILE,
            2 * PAGE_SIZE,
            Mapping {
                perms: RW,
                backing: backing.clone(),
                shared: true,
                name: None,
                flags: 0,
            },
        )
        .unwrap();
    // Sealing happens after the writable mapping is admitted. Only the mapping
    // and catalog keep the inode when the workers start; no guest fd remains.
    inode.add(seal::FUTURE_WRITE);
    drop(inode);
    drop(description);
    assert!(closed.upgrade().is_none());
    let (mut broker, client, root) = Broker::new(lease.clone(), &original, metadata()).unwrap();
    drop(original);
    assert_eq!(
        broker.register_backing(root, backing).unwrap(),
        BackingId(1)
    );
    let mut worker = spawn(client, &lease, NAME, "root");
    let mut released_while_live = false;
    assert_eq!(
        drive_observing(&mut broker, &mut worker, |broker| {
            released_while_live |= retained.upgrade().is_none() && !broker.endpoints.is_empty();
        }),
        0
    );
    assert!(
        released_while_live,
        "last unmap releases inode before endpoint EOF"
    );
    assert!(retained.upgrade().is_none());
    assert!(Memfd::find(identity).is_none());
}

#[test]
fn native_lost_advice_reply_preserves_partial_effects_for_the_surviving_shared_peer() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::advice::native_lost_advice_reply_preserves_partial_effects_for_the_surviving_shared_peer";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [0]);
                assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [23]);
                assert_eq!(
                    remote::madvise(&session.access(), HEAP, 3 * PAGE_SIZE, 4)?,
                    Err(Errno(EINVAL))
                );
                assert!(session.access().active());
                assert_eq!(
                    remote::madvise(&session.access(), HEAP + 2 * PAGE_SIZE, PAGE_SIZE, 24)?,
                    Ok(0)
                );
                assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [0]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let original = space();
    original
        .map(HEAP, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    let mut locked = Mapping::anonymous(RW);
    locked.flags = vma_flags::LOCKED;
    original
        .map(HEAP + 2 * PAGE_SIZE, PAGE_SIZE, locked)
        .unwrap();
    original.write(HEAP, &[17]).unwrap();
    original.write(HEAP + 2 * PAGE_SIZE, &[23]).unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, metadata()).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Madvise {
        address: HEAP,
        length: 3 * PAGE_SIZE,
        advice: 4,
    })
    .unwrap();
    channel
        .send(
            &serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap(),
            &[],
        )
        .unwrap();
    channel.close();
    assert!(matches!(broker.serve_one(), Err(OwnerError::Io(_))));
    holder.release();
    holder.stop();
    let mut worker = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}
