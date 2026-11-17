//! Actual Linux MM operations through native worker IPC. The controlled
//! lost-reply test uses a separate native lease holder so dispatch cannot race
//! lease release; a surviving shared peer then uses the ordinary client.

use super::*;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{ENOMEM, EPERM};
use crate::user::linux::abi::{LinuxAbi, vma_flags};
use crate::user::linux::process::mm::ProtectPolicy;
use crate::user::linux::process::{
    BrkPolicy,
    mm::{MmResources, remote},
};
use crate::user::linux::syscall::mem::mman::PROT_READ;
use crate::user::mm::process_lease::test_worker::{LeaseWorker, serve_if_requested};

const HEAP: u64 = SOURCE;

mod advice;
mod aio;
mod aio_reap;
mod inheritance;
mod locks;
mod mapping;
mod queries;
mod remap;

fn metadata() -> MmResources {
    let mut mm = crate::user::linux::process::mm::initial_state(LinuxAbi::Aarch64);
    mm.start_brk = HEAP;
    mm.brk = HEAP;
    mm.def_lock = vma_flags::LOCKED_MASK;
    mm.locked_vm = 0;
    MmResources::new(mm, crate::user::linux::aio::Table::default())
}

fn policy() -> BrkPolicy {
    BrkPolicy {
        abi: LinuxAbi::Aarch64,
        persona: 0,
        privileged: false,
        memlock_limit: 3 * PAGE_SIZE,
    }
}

fn brk(session: &Session<'_>, address: u64) -> u64 {
    remote::brk(&session.access(), policy(), address)
        .unwrap()
        .unwrap()
}

#[test]
fn native_brk_transaction_shares_mm_and_private_fork_resets_lock_policy() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::native_brk_transaction_shares_mm_and_private_fork_resets_lock_policy";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(brk(session, 0), HEAP + PAGE_SIZE);
                    assert_eq!(brk(session, HEAP + 2 * PAGE_SIZE), HEAP + 2 * PAGE_SIZE);
                    write(session, HEAP + PAGE_SIZE, vec![23]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "private" {
            client
                .with(lease, |session| {
                    assert_eq!(brk(session, 0), HEAP + PAGE_SIZE);
                    assert_eq!(read(session, HEAP, 1), [17]);
                    assert!(matches!(
                        session.call(Operation::Read {
                            address: HEAP + PAGE_SIZE,
                            len: 1,
                            kind: ReadKind::Read
                        }),
                        Err(RemoteError::Memory(Failure::Fault { .. }))
                    ));
                    assert_eq!(
                        brk(session, HEAP + 5 * PAGE_SIZE),
                        HEAP + 5 * PAGE_SIZE,
                        "private fork cleared MCL_FUTURE and starts fresh accounting"
                    );
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (shared, private) = client
            .with(lease, |session| {
                assert_eq!(brk(session, HEAP + PAGE_SIZE), HEAP + PAGE_SIZE);
                write(session, HEAP, vec![17]);
                Ok((session.fork(false)?, session.fork(true)?))
            })
            .unwrap();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(brk(session, 0), HEAP + 2 * PAGE_SIZE);
                assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [23]);
                assert_eq!(brk(session, HEAP + 4 * PAGE_SIZE), HEAP + 2 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 3 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                assert_eq!(brk(session, 0), HEAP + 3 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

fn begin_peer(
    broker: &mut Broker<MmResources>,
    channel: &mut Channel,
    holder: &LeaseWorker,
) -> (u64, Client) {
    channel
        .send(
            &serde_json::to_vec(&Request::Begin { pid: holder.pid() }).unwrap(),
            &[],
        )
        .unwrap();
    assert_eq!(broker.serve_one().unwrap(), Event::Completed);
    let Response::Grant { serial, .. } =
        serde_json::from_slice(&channel.receive().unwrap().bytes).unwrap()
    else {
        panic!("expected grant")
    };
    channel
        .send(
            &serde_json::to_vec(&Request::Fork {
                serial,
                private: false,
            })
            .unwrap(),
            &[],
        )
        .unwrap();
    assert_eq!(broker.serve_one().unwrap(), Event::Completed);
    let mut frame = channel.receive().unwrap();
    assert!(matches!(
        serde_json::from_slice::<Response>(&frame.bytes).unwrap(),
        Response::Forked
    ));
    assert_eq!(frame.files.len(), 1);
    let stream = std::os::unix::net::UnixStream::from(frame.files.pop().unwrap());
    (serial, Client::new(Channel::new(stream).unwrap()))
}

#[test]
fn native_lost_brk_reply_leaves_shared_peer_with_complete_mapping_and_accounting() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::native_lost_brk_reply_leaves_shared_peer_with_complete_mapping_and_accounting";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert_eq!(brk(session, 0), HEAP + 2 * PAGE_SIZE);
                assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [0]);
                assert_eq!(
                    brk(session, HEAP + 4 * PAGE_SIZE),
                    HEAP + 2 * PAGE_SIZE,
                    "completed growth charged the shared account"
                );
                assert_eq!(brk(session, HEAP), HEAP);
                assert_eq!(
                    brk(session, HEAP + 3 * PAGE_SIZE),
                    HEAP + 3 * PAGE_SIZE,
                    "shrink released the same account"
                );
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Brk {
        policy: policy(),
        address: HEAP + 2 * PAGE_SIZE,
    })
    .unwrap();
    channel
        .send(
            &serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap(),
            &[],
        )
        .unwrap();
    channel.close();
    assert!(
        matches!(broker.serve_one(), Err(OwnerError::Io(_))),
        "operation completes but cannot return its reply"
    );
    holder.release();
    holder.stop();
    let mut peer = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut peer), 0);
}

#[test]
fn native_invalid_personality_requests_retire_only_the_caller_before_mutation() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::native_invalid_personality_requests_retire_only_the_caller_before_mutation";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert_eq!(brk(session, 0), HEAP);
                assert!(matches!(
                    session.call(Operation::Read {
                        address: HEAP,
                        len: 1,
                        kind: ReadKind::Read
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                assert_eq!(brk(session, HEAP + 3 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let valid = serde_json::to_vec(&remote::Operation::Brk {
        policy: policy(),
        address: HEAP + PAGE_SIZE,
    })
    .unwrap();
    let mut unknown_field: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    unknown_field["unexpected"] = true.into();
    let corpus = [
        (true, valid),
        (false, serde_json::to_vec(&unknown_field).unwrap()),
        (false, br#"{"operation":"Unknown"}"#.to_vec()),
        (false, br#"{"operation":"Mmap","policy":{"lock":{"abi":"Aarch64","privileged":false,"memlock_limit":12288},"persona":0},"arguments":{"address":327680,"length":4096,"protection":3,"flags":18,"offset":0},"source":{"source":"Registered","backing":0,"name":null,"flags":0}}"#.to_vec()),
        (false, br#"{"operation":"Mmap","policy":{"lock":{"abi":"Aarch64","privileged":false,"memlock_limit":12288},"persona":0},"arguments":{"address":327680,"length":4096,"protection":3,"flags":18,"offset":0},"source":{"source":"Anonymous"}}"#.to_vec()),
        (false, br#"{"operation":"Mmap","policy":{"lock":{"abi":"Aarch64","privileged":false,"memlock_limit":12288},"persona":0},"arguments":{"address":327680,"length":4096,"protection":3,"flags":50,"offset":0,"unexpected":true},"source":{"source":"Anonymous"}}"#.to_vec()),
        (false, br#"{"operation":"Munlockall","unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"Msync","address":327680,"length":4096,"flags":4,"unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"Mincore","abi":"Unknown","address":327680,"length":4096,"vector":360448}"#.to_vec()),
        (false, br#"{"operation":"Madvise","address":327680,"length":4096,"advice":4,"unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"Madvise","address":327680,"length":4096,"advice":4294967296}"#.to_vec()),
        (false, br#"{"operation":"Mremap","policy":{"abi":"Aarch64","privileged":false,"memlock_limit":4096},"arguments":{"old_address":327680,"old_length":4096,"new_length":4096,"flags":3,"new_address":360448,"unexpected":true}}"#.to_vec()),
        (false, br#"{"operation":"Mremap","policy":{"abi":"Aarch64","privileged":false,"memlock_limit":4096},"arguments":{"old_address":327680,"old_length":4096,"new_length":4096,"flags":4294967296,"new_address":360448}}"#.to_vec()),
        (false, br#"{"operation":"Mlockall","policy":{"abi":"Aarch64","privileged":false,"memlock_limit":4096,"unexpected":true},"flags":2}"#.to_vec()),
        (false, br#"{"operation":"AioSetup","policy":{"abi":"Aarch64","privileged":false,"memlock_limit":4096},"nr_events":8,"context":65536,"unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"AioSetup","policy":{"abi":"Aarch64","privileged":false,"memlock_limit":4096},"nr_events":4294967296,"context":65536}"#.to_vec()),
        (false, br#"{"operation":"AioLookup","address":65536,"unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"AioLookup","address":-1}"#.to_vec()),
        (false, br#"{"operation":"AioRead","handle":{"slot":0,"serial":0},"min_nr":1,"nr":2,"events":65536,"got":0}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Unknown","handle":{"slot":0,"serial":0},"min_nr":1,"nr":2,"events":65536,"got":0}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Aarch64","handle":{"slot":0,"serial":0},"min_nr":1,"nr":2,"events":65536,"got":0,"unexpected":true}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Aarch64","handle":{"slot":0,"serial":0,"unexpected":true},"min_nr":1,"nr":2,"events":65536,"got":0}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Aarch64","handle":{"slot":0,"serial":-1},"min_nr":1,"nr":2,"events":65536,"got":0}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Aarch64","handle":{"slot":0,"serial":0},"min_nr":1,"nr":9223372036854775808,"events":65536,"got":0}"#.to_vec()),
        (false, br#"{"operation":"AioRead","abi":"Aarch64","handle":{"slot":0,"serial":0},"min_nr":1,"nr":2,"events":65536,"got":-1}"#.to_vec()),
        (
            false,
            vec![0; super::super::super::wire::PERSONALITY_BYTES + 1],
        ),
    ];
    for (stale, bytes) in corpus {
        let lease = Arc::new(ProcessLease::new().unwrap());
        let (mut broker, client, _) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
        let mut holder = LeaseWorker::spawn(&lease, NAME);
        holder.acquire();
        let mut channel = client.into_channel().unwrap();
        let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
        let serial = if stale { serial - 1 } else { serial };
        let request = serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap();
        // A bounded frame can exceed a native socket's buffer. The broker
        // and sender must run concurrently, as they do in separate workers.
        let sender = std::thread::spawn(move || {
            channel.send(&request, &[]).unwrap();
            channel
        });
        assert!(matches!(broker.serve_one(), Err(OwnerError::Io(_))));
        let mut channel = sender.join().unwrap();
        assert!(channel.receive().is_err());
        holder.release();
        holder.stop();
        let mut peer = spawn(peer, &lease, NAME, "peer");
        assert_eq!(drive(&mut broker, &mut peer), 0);
    }
}

fn protect_policy() -> ProtectPolicy {
    ProtectPolicy {
        abi: LinuxAbi::Aarch64,
        persona: 0,
    }
}

#[test]
fn native_range_transactions_share_protection_seals_and_unmap_lock_accounting() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::native_range_transactions_share_protection_seals_and_unmap_lock_accounting";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "shared" {
            client
                .with(lease, |session| {
                    let access = session.access();
                    assert_eq!(
                        remote::mprotect(
                            &access,
                            protect_policy(),
                            HEAP,
                            3 * PAGE_SIZE,
                            PROT_READ
                        )?,
                        Ok(0)
                    );
                    assert_eq!(remote::mseal(&access, HEAP + PAGE_SIZE, 1, 0)?, Ok(0));
                    assert_eq!(
                        remote::munmap(&access, LinuxAbi::Aarch64, HEAP, PAGE_SIZE)?,
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
                    // The snapshot precedes every shared-worker range operation.
                    write(session, HEAP, vec![29]);
                    write(session, HEAP + PAGE_SIZE, vec![31]);
                    assert_eq!(
                        remote::munmap(&session.access(), LinuxAbi::Aarch64, HEAP, 3 * PAGE_SIZE)?,
                        Ok(0)
                    );
                    assert_eq!(brk(session, HEAP), HEAP);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (shared, private) = client
            .with(lease, |session| {
                assert_eq!(brk(session, HEAP + 3 * PAGE_SIZE), HEAP + 3 * PAGE_SIZE);
                write(session, HEAP + PAGE_SIZE, vec![17]);
                Ok((session.fork(false)?, session.fork(true)?))
            })
            .unwrap();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                let access = session.access();
                assert!(matches!(
                    session.call(Operation::Read {
                        address: HEAP,
                        len: 1,
                        kind: ReadKind::Read
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [17]);
                assert!(matches!(
                    session.call(Operation::Write {
                        address: HEAP + PAGE_SIZE,
                        bytes: vec![0],
                        raw: false
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                assert_eq!(
                    remote::munmap(&access, LinuxAbi::Aarch64, HEAP + PAGE_SIZE, 2 * PAGE_SIZE)?,
                    Err(Errno(EPERM))
                );
                assert_eq!(
                    remote::mprotect(
                        &access,
                        protect_policy(),
                        HEAP + PAGE_SIZE,
                        PAGE_SIZE,
                        PROT_READ
                    )?,
                    Err(Errno(EPERM))
                );
                assert!(access.active(), "guest errno must retain the active window");
                // Removing one locked page admitted exactly one page of growth.
                assert_eq!(brk(session, HEAP + 4 * PAGE_SIZE), HEAP + 4 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 5 * PAGE_SIZE), HEAP + 4 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [17]);
                assert_eq!(brk(session, 0), HEAP + 4 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_lost_protection_reply_preserves_partial_guest_error_and_shared_account() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::native_lost_protection_reply_preserves_partial_guest_error_and_shared_account";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let access = session.access();
                assert!(matches!(
                    session.call(Operation::Write {
                        address: HEAP,
                        bytes: vec![0],
                        raw: false
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                write(session, HEAP + 2 * PAGE_SIZE, vec![41]);
                assert_eq!(
                    remote::mprotect(&access, protect_policy(), HEAP, 3 * PAGE_SIZE, PROT_READ)?,
                    Err(Errno(ENOMEM))
                );
                assert!(access.active());
                assert_eq!(
                    remote::munmap(&access, LinuxAbi::Aarch64, HEAP, PAGE_SIZE)?,
                    Ok(0)
                );
                assert_eq!(brk(session, HEAP + 5 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                assert_eq!(brk(session, HEAP + 6 * PAGE_SIZE), HEAP + 5 * PAGE_SIZE);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    let mut mapping = Mapping::anonymous(RW);
    mapping.flags = vma_flags::LOCKED_MASK;
    initial.map(HEAP, PAGE_SIZE, mapping.clone()).unwrap();
    initial
        .map(HEAP + 2 * PAGE_SIZE, PAGE_SIZE, mapping)
        .unwrap();
    let mut mm = metadata();
    mm.mm.brk = HEAP + 3 * PAGE_SIZE;
    mm.mm.locked_vm = 2;
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, mm).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Mprotect {
        policy: protect_policy(),
        address: HEAP,
        length: 3 * PAGE_SIZE,
        protection: PROT_READ,
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
    let mut peer = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut peer), 0);
}
