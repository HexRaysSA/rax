use super::*;
use crate::user::linux::process::mm::LockPolicy;

const ONFAULT: u32 = 1;
const FUTURE_ONFAULT: i32 = 2 | 4;

fn lock_policy(pages: u64) -> LockPolicy {
    LockPolicy {
        abi: LinuxAbi::Aarch64,
        privileged: false,
        memlock_limit: pages * PAGE_SIZE,
    }
}

#[test]
fn native_lock_transactions_share_policy_and_preserve_private_fork_reset() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::locks::native_lock_transactions_share_policy_and_preserve_private_fork_reset";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "shared" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    assert_eq!(
                        remote::mlock(&access, lock_policy(2), HEAP, 2 * PAGE_SIZE, ONFAULT)?,
                        Ok(0)
                    );
                    // MCL_FUTURE does not replace a peer's calling-process limit
                    // or release existing charges above this caller's limit.
                    assert_eq!(
                        remote::mlockall(&access, lock_policy(1), FUTURE_ONFAULT)?,
                        Ok(0)
                    );
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "private" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    // Parent had one charged page. A fresh private account admits
                    // this different page under a one-page calling-process limit.
                    assert_eq!(
                        remote::mlock(
                            &access,
                            lock_policy(1),
                            HEAP + PAGE_SIZE,
                            PAGE_SIZE,
                            ONFAULT
                        )?,
                        Ok(0)
                    );
                    assert_eq!(remote::munlockall(&access)?, Ok(0));
                    assert_eq!(
                        remote::mlock(&access, lock_policy(2), HEAP, 2 * PAGE_SIZE, ONFAULT)?,
                        Ok(0)
                    );
                    assert_eq!(
                        remote::mlockall(&access, lock_policy(2), FUTURE_ONFAULT)?,
                        Ok(0)
                    );
                    assert_eq!(brk(session, HEAP + 3 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                    assert_eq!(brk(session, HEAP + 4 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (shared, private) = client
            .with(lease, |session| {
                let access = session.access();
                assert_eq!(brk(session, HEAP + 2 * PAGE_SIZE), HEAP + 2 * PAGE_SIZE);
                assert_eq!(
                    remote::mlock(&access, lock_policy(1), HEAP, PAGE_SIZE, ONFAULT)?,
                    Ok(0)
                );
                Ok((session.fork(false)?, session.fork(true)?))
            })
            .unwrap();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                let access = session.access();
                assert_eq!(brk(session, HEAP + 3 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 4 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                assert_eq!(
                    remote::mlock(&access, lock_policy(1), HEAP, PAGE_SIZE, ONFAULT)?,
                    Err(Errno(ENOMEM))
                );
                assert!(access.active());
                assert_eq!(remote::munlock(&access, HEAP, 2 * PAGE_SIZE)?, Ok(0));
                assert_eq!(brk(session, HEAP + 5 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 6 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                assert_eq!(remote::munlockall(&access)?, Ok(0));
                assert_eq!(brk(session, HEAP + 10 * PAGE_SIZE), HEAP + 10 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                assert_eq!(brk(session, 0), HEAP + 10 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let mut mm = metadata();
    mm.mm.def_lock = 0;
    let (mut broker, client, _) = Broker::new(lease.clone(), &space(), mm).unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_lost_lock_reply_preserves_partial_charge_for_surviving_shared_peer() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::locks::native_lost_lock_reply_preserves_partial_charge_for_surviving_shared_peer";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let access = session.access();
                assert_eq!(
                    remote::mlockall(&access, lock_policy(3), FUTURE_ONFAULT)?,
                    Ok(0)
                );
                // The first page remained charged before the lost ENOMEM reply;
                // the page after the hole was never changed or charged.
                assert_eq!(brk(session, HEAP + 5 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 6 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                assert_eq!(remote::munlock(&access, HEAP, PAGE_SIZE)?, Ok(0));
                assert_eq!(brk(session, HEAP + 6 * PAGE_SIZE), HEAP + 6 * PAGE_SIZE);
                assert_eq!(remote::munlockall(&access)?, Ok(0));
                assert_eq!(brk(session, HEAP + 12 * PAGE_SIZE), HEAP + 12 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    initial
        .map(HEAP, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    initial
        .map(HEAP + 2 * PAGE_SIZE, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    let mut mm = metadata();
    mm.mm.brk = HEAP + 3 * PAGE_SIZE;
    mm.mm.def_lock = 0;
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, mm).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Mlock {
        policy: lock_policy(3),
        address: HEAP,
        length: 3 * PAGE_SIZE,
        flags: ONFAULT,
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
    holder.release();
    holder.stop();
    let mut peer = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut peer), 0);
}
