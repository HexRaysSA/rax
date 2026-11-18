use super::*;
use crate::user::linux::abi::errno_table::EINVAL;
use crate::user::linux::process::mm::{LockPolicy, RemapArgs, pending_fixture};

const RING: u64 = 0x2_0000;
const MOVED: u64 = RING + 4 * PAGE_SIZE;
const FINAL: u64 = RING + 8 * PAGE_SIZE;

fn lock_policy() -> LockPolicy {
    LockPolicy {
        abi: LinuxAbi::Aarch64,
        privileged: false,
        memlock_limit: 0,
    }
}

fn arguments(old: u64, new: u64) -> RemapArgs {
    RemapArgs {
        old_address: old,
        old_length: PAGE_SIZE,
        new_length: PAGE_SIZE,
        flags: 3,
        new_address: new,
    }
}

#[test]
fn native_remap_uses_live_aio_table_for_shared_workers_and_empty_private_child() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::remap::native_remap_uses_live_aio_table_for_shared_workers_and_empty_private_child";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "private" || phase == "shared" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    assert_eq!(
                        read(session, MOVED + 512, 1),
                        if phase == "private" { [41] } else { [17] }
                    );
                    if phase == "private" {
                        assert_eq!(
                            remote::mremap(&access, lock_policy(), arguments(MOVED, RING))?,
                            Err(Errno(EINVAL))
                        );
                        assert!(access.active(), "guest errno preserves the turn");
                        assert_eq!(read(session, MOVED + 512, 1), [41]);
                        write(session, MOVED + 512, vec![29]);
                    } else {
                        assert_eq!(
                            remote::mremap(&access, lock_policy(), arguments(MOVED, FINAL))?,
                            Ok(FINAL)
                        );
                        write(session, FINAL + 512, vec![41]);
                    }
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (private, shared) = client
            .with(lease, |session| {
                assert_eq!(
                    remote::mremap(&session.access(), lock_policy(), arguments(RING, MOVED))?,
                    Ok(MOVED)
                );
                assert_eq!(read(session, MOVED + 512, 1), [17]);
                Ok((session.fork(true)?, session.fork(false)?))
            })
            .unwrap();
        spawn(shared, lease, NAME, "shared").wait();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                assert_eq!(
                    read(session, FINAL + 512, 1),
                    [29],
                    "inherited shared ring retains its actual object"
                );
                assert_eq!(
                    remote::mremap(&session.access(), lock_policy(), arguments(FINAL, RING))?,
                    Ok(RING)
                );
                assert_eq!(read(session, RING + 512, 1), [29]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (original, resources, witness) = pending_fixture(LinuxAbi::Aarch64, RING);
    original.write(RING + 512, &[17]).unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, resources).unwrap();
    drop(original);
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    assert!(witness.file.upgrade().is_none());
    assert!(witness.resfd.upgrade().is_none());
    assert!(witness.ring.upgrade().is_none());
}

#[test]
fn native_lost_remap_reply_keeps_ring_move_and_real_resources_for_shared_peer() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::remap::native_lost_remap_reply_keeps_ring_move_and_real_resources_for_shared_peer";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert!(matches!(
                    session.call(Operation::Read {
                        address: RING,
                        len: 1,
                        kind: ReadKind::Read
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                assert_eq!(read(session, MOVED + 512, 1), [17]);
                assert_eq!(
                    remote::mremap(&session.access(), lock_policy(), arguments(MOVED, FINAL))?,
                    Ok(FINAL)
                );
                assert_eq!(read(session, FINAL + 512, 1), [17]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (original, resources, witness) = pending_fixture(LinuxAbi::Aarch64, RING);
    original.write(RING + 512, &[17]).unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, resources).unwrap();
    drop(original);
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Mremap {
        policy: lock_policy(),
        arguments: arguments(RING, MOVED),
    })
    .unwrap();
    channel
        .send(
            &serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap(),
            &[],
        )
        .unwrap();
    channel.close();
    finish_lost_reply(&mut broker);
    assert!(witness.file.upgrade().is_some());
    assert!(witness.resfd.upgrade().is_some());
    holder.release();
    holder.stop();
    let mut worker = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    assert!(witness.file.upgrade().is_none());
    assert!(witness.resfd.upgrade().is_none());
    assert!(witness.ring.upgrade().is_none());
}
