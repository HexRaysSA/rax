use super::*;
use crate::user::linux::abi::errno_table::EAGAIN;
use crate::user::linux::aio::{AIO_MAX_NR, RING_MAGIC};
use crate::user::linux::process::mm::LockPolicy;

fn lock_policy() -> LockPolicy {
    LockPolicy {
        abi: LinuxAbi::Aarch64,
        privileged: false,
        memlock_limit: 0,
    }
}

fn context(session: &mut Session<'_>, pointer: u64) -> u64 {
    u64::from_le_bytes(read(session, pointer, 8).try_into().unwrap())
}

fn assert_header(session: &mut Session<'_>, ring: u64, index: u32) {
    let header = read(session, ring, 32);
    assert_eq!(&header[..4], &index.to_le_bytes());
    assert_eq!(&header[16..20], &RING_MAGIC.to_le_bytes());
    assert_eq!(&header[28..], &32_u32.to_le_bytes());
}

#[test]
fn native_setup_uses_one_shared_table_and_a_fresh_private_table_with_inherited_rings() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::aio::native_setup_uses_one_shared_table_and_a_fresh_private_table_with_inherited_rings";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "shared" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    let first = context(session, BASE);
                    assert_header(session, first, 0);
                    assert_eq!(
                        remote::aio_setup(&access, lock_policy(), AIO_MAX_NR as u32, BASE + 8)?,
                        Err(Errno(EAGAIN)),
                        "the parent's live context consumes the shared quota"
                    );
                    assert!(access.active(), "guest errno keeps the turn usable");
                    assert_eq!(context(session, BASE + 8), 0);
                    assert_eq!(
                        remote::aio_setup(&access, lock_policy(), 8, BASE + 8)?,
                        Ok(0)
                    );
                    let second = context(session, BASE + 8);
                    assert_ne!(first, second);
                    assert_header(session, second, 1);
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "private" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    let inherited = context(session, BASE);
                    assert_header(session, inherited, 0);
                    assert_eq!(
                        context(session, BASE + 8),
                        0,
                        "private pointer page snapshot"
                    );
                    assert_eq!(
                        remote::aio_setup(&access, lock_policy(), AIO_MAX_NR as u32, BASE + 16)?,
                        Ok(0),
                        "inherited ring VMAs do not retain a private child's contexts"
                    );
                    let created = context(session, BASE + 16);
                    assert_ne!(created, inherited);
                    assert_header(session, created, 0);
                    assert_eq!(
                        remote::aio_setup(&access, lock_policy(), 1, BASE + 24)?,
                        Err(Errno(EAGAIN))
                    );
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (shared, private) = client
            .with(lease, |session| {
                assert_eq!(
                    remote::aio_setup(&session.access(), lock_policy(), 8, BASE)?,
                    Ok(0)
                );
                let ring = context(session, BASE);
                assert_header(session, ring, 0);
                Ok((session.fork(false)?, session.fork(true)?))
            })
            .unwrap();
        spawn(shared, lease, NAME, "shared").wait();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                let first = context(session, BASE);
                let second = context(session, BASE + 8);
                assert_header(session, first, 0);
                assert_header(session, second, 1);
                assert_eq!(
                    context(session, BASE + 16),
                    0,
                    "private setup did not edit parent MM"
                );
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    initial.write(BASE, &[0; 32]).unwrap();
    let mut resources = metadata();
    resources.mm.def_lock = 0;
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, resources).unwrap();
    drop(initial);
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_lost_setup_reply_retains_the_published_ring_and_charge_for_a_shared_peer() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::aio::native_lost_setup_reply_retains_the_published_ring_and_charge_for_a_shared_peer";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let first = context(session, BASE);
                assert_header(session, first, 0);
                assert_eq!(
                    remote::aio_setup(
                        &session.access(),
                        lock_policy(),
                        AIO_MAX_NR as u32,
                        BASE + 8
                    )?,
                    Err(Errno(EAGAIN)),
                    "a lost reply did not undo the committed charge"
                );
                assert_eq!(
                    remote::aio_setup(&session.access(), lock_policy(), 8, BASE + 8)?,
                    Ok(0)
                );
                let second = context(session, BASE + 8);
                assert_header(session, second, 1);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    initial.write(BASE, &[0; 16]).unwrap();
    let mut resources = metadata();
    resources.mm.def_lock = 0;
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, resources).unwrap();
    drop(initial);
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::AioSetup {
        policy: lock_policy(),
        nr_events: 8,
        context: BASE,
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
