use super::*;
use crate::user::linux::abi::errno_table::{EFAULT, EINVAL};
use crate::user::mm::anonymous_file;
use std::io::{Read, Seek, SeekFrom};

const VECTOR: u64 = HEAP + 8 * PAGE_SIZE;
const FILE: u64 = HEAP + 4 * PAGE_SIZE;

#[test]
fn native_residency_output_and_sync_keep_private_shared_workers_and_real_storage() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::queries::native_residency_output_and_sync_keep_private_shared_workers_and_real_storage";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "private" {
            client
                .with(lease, |session| {
                    write(session, HEAP, vec![23]);
                    assert_eq!(
                        remote::mincore(
                            &session.access(),
                            LinuxAbi::Aarch64,
                            HEAP,
                            2 * PAGE_SIZE,
                            VECTOR
                        )?,
                        Ok(0)
                    );
                    assert_eq!(read(session, VECTOR, 2), [1, 1]);
                    write(session, FILE + 7, vec![31, 37]);
                    assert_eq!(remote::msync(&session.access(), FILE, 1, 4)?, Ok(0));
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(
                        read(session, VECTOR, 2),
                        [0, 1],
                        "private child's vector write stayed private"
                    );
                    assert_eq!(read(session, FILE + 7, 2), [31, 37]);
                    write(session, HEAP, vec![41]);
                    assert_eq!(
                        remote::mincore(
                            &session.access(),
                            LinuxAbi::Aarch64,
                            HEAP,
                            2 * PAGE_SIZE,
                            VECTOR
                        )?,
                        Ok(0)
                    );
                    assert_eq!(read(session, VECTOR, 2), [1, 1]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (private, shared) = client
            .with(lease, |session| {
                for operation in [
                    map(HEAP, 2 * PAGE_SIZE, None, false),
                    map(VECTOR, PAGE_SIZE, None, false),
                    map(FILE, PAGE_SIZE, Some(BackingId(1)), true),
                ] {
                    let Operation::Map { mut mapping } = operation else {
                        unreachable!()
                    };
                    // The generic broker fixture uses 0x40, which is Linux's
                    // SEALED bit. These VMAs must allow the final unmap.
                    mapping.flags = 0;
                    session.call(Operation::Map { mapping })?;
                }
                session.call(Operation::ReleaseBacking {
                    backing: BackingId(1),
                })?;
                write(session, HEAP + PAGE_SIZE, vec![17]);
                assert_eq!(
                    remote::msync(&session.access(), FILE, 1, 5)?,
                    Err(Errno(EINVAL))
                );
                assert_eq!(
                    remote::mincore(&session.access(), LinuxAbi::Aarch64, HEAP, 2 * PAGE_SIZE, 0)?,
                    Err(Errno(EFAULT))
                );
                assert!(
                    session.access().active(),
                    "guest errno leaves the acknowledged turn usable"
                );
                assert_eq!(
                    remote::mincore(
                        &session.access(),
                        LinuxAbi::Aarch64,
                        HEAP,
                        2 * PAGE_SIZE,
                        VECTOR
                    )?,
                    Ok(0)
                );
                assert_eq!(read(session, VECTOR, 2), [0, 1]);
                Ok((session.fork(true)?, session.fork(false)?))
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, VECTOR, 2), [1, 1]);
                assert_eq!(read(session, HEAP, 1), [41]);
                assert_eq!(read(session, FILE + 7, 2), [31, 37]);
                assert_eq!(
                    remote::munmap(&session.access(), LinuxAbi::Aarch64, HEAP, 9 * PAGE_SIZE)?,
                    Ok(0)
                );
                session.call(Operation::Stats)?;
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, root) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
    let mut file = anonymous_file().unwrap();
    file.write_all(&vec![5; PAGE_SIZE as usize]).unwrap();
    let mut observer = file.try_clone().unwrap();
    let keep = Arc::new(());
    let retained = Arc::downgrade(&keep);
    let object = Arc::new(SharedObject::file_keeping(file, true, Some(keep)).unwrap());
    assert_eq!(
        broker
            .register_backing(root, Backing::Shared { object, offset: 0 })
            .unwrap(),
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
    observer.seek(SeekFrom::Start(7)).unwrap();
    let mut bytes = [0; 2];
    observer.read_exact(&mut bytes).unwrap();
    assert_eq!(
        bytes,
        [31, 37],
        "same actual host file; no durability guarantee is inferred"
    );
    assert!(released_while_live);
    assert!(retained.upgrade().is_none());
}

#[test]
fn native_lost_residency_reply_keeps_completed_vector_for_surviving_shared_peer() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::queries::native_lost_residency_reply_keeps_completed_vector_for_surviving_shared_peer";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert_eq!(read(session, VECTOR, 2), [0, 1]);
                assert_eq!(
                    remote::mincore(
                        &session.access(),
                        LinuxAbi::Aarch64,
                        HEAP,
                        2 * PAGE_SIZE,
                        VECTOR
                    )?,
                    Ok(0)
                );
                assert_eq!(
                    read(session, VECTOR, 2),
                    [0, 1],
                    "query did not demand-page the untouched page"
                );
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let original = space();
    original
        .map(HEAP, 2 * PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    original.write(HEAP + PAGE_SIZE, &[17]).unwrap();
    original
        .map(VECTOR, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    original.write(VECTOR, &[71, 73]).unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, metadata()).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Mincore {
        abi: LinuxAbi::Aarch64,
        address: HEAP,
        length: 2 * PAGE_SIZE,
        vector: VECTOR,
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
