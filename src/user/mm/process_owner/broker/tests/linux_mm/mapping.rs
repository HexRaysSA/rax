use super::*;
use crate::user::linux::abi::errno_table::EAGAIN;
use crate::user::linux::process::mm::{LockPolicy, MmapArgs, MmapPolicy};
use crate::user::linux::syscall::mem::mman::*;
use crate::user::mm::{HostFileSource, anonymous_file};

fn mmap_policy() -> MmapPolicy {
    MmapPolicy {
        lock: LockPolicy {
            abi: LinuxAbi::Aarch64,
            privileged: false,
            memlock_limit: 3 * PAGE_SIZE,
        },
        persona: 0,
    }
}

fn arguments(address: u64, length: u64, shared: bool, anonymous: bool) -> MmapArgs {
    MmapArgs {
        address,
        length,
        protection: PROT_READ | PROT_WRITE,
        flags: MAP_FIXED
            | if shared { MAP_SHARED } else { MAP_PRIVATE }
            | if anonymous { MAP_ANONYMOUS } else { 0 },
        offset: 0,
    }
}

#[test]
fn native_mmap_retains_real_source_across_catalog_release_and_private_shared_workers() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::mapping::native_mmap_retains_real_source_across_catalog_release_and_private_shared_workers";
    const SHARED: u64 = HEAP + 4 * PAGE_SIZE;
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "private" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, HEAP, 1), [17]);
                    write(session, HEAP, vec![29]);
                    write(session, SHARED, vec![23]);
                    let mut policy = mmap_policy();
                    policy.lock.memlock_limit = 0;
                    assert_eq!(
                        remote::mmap(
                            &session.access(),
                            policy,
                            arguments(HEAP + 8 * PAGE_SIZE, 4 * PAGE_SIZE, false, true),
                            remote::MmapSource::Anonymous {}
                        )?,
                        Ok(HEAP + 8 * PAGE_SIZE),
                        "private fork cleared future locks"
                    );
                    assert_eq!(
                        remote::munmap(&session.access(), LinuxAbi::Aarch64, HEAP, 12 * PAGE_SIZE)?,
                        Ok(0)
                    );
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, HEAP, 1), [17]);
                    assert_eq!(read(session, SHARED, 1), [23]);
                    let a = arguments(HEAP + 6 * PAGE_SIZE, PAGE_SIZE, false, true);
                    let mut limited = mmap_policy();
                    limited.lock.memlock_limit = 0;
                    assert_eq!(
                        remote::mmap(
                            &session.access(),
                            limited,
                            a,
                            remote::MmapSource::Anonymous {}
                        )?,
                        Err(Errno(EAGAIN))
                    );
                    assert!(session.access().active());
                    assert_eq!(
                        remote::mmap(
                            &session.access(),
                            mmap_policy(),
                            a,
                            remote::MmapSource::Anonymous {}
                        )?,
                        Ok(a.address)
                    );
                    write(session, a.address, vec![47]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (private, shared) = client
            .with(lease, |session| {
                let mut a = arguments(HEAP, PAGE_SIZE, false, false);
                a.offset = PAGE_SIZE;
                assert_eq!(
                    remote::mmap(
                        &session.access(),
                        mmap_policy(),
                        a,
                        remote::MmapSource::Registered {
                            backing: BackingId(1),
                            name: Some("real-kept-file".into()),
                            flags: 0
                        }
                    )?,
                    Ok(HEAP)
                );
                assert_eq!(read(session, HEAP, 1), [17]);
                session.call(Operation::ReleaseBacking {
                    backing: BackingId(1),
                })?;
                let a = arguments(SHARED, PAGE_SIZE, true, true);
                assert_eq!(
                    remote::mmap(
                        &session.access(),
                        mmap_policy(),
                        a,
                        remote::MmapSource::Anonymous {}
                    )?,
                    Ok(SHARED)
                );
                Ok((session.fork(true)?, session.fork(false)?))
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [17]);
                assert_eq!(read(session, SHARED, 1), [23]);
                assert_eq!(read(session, HEAP + 6 * PAGE_SIZE, 1), [47]);
                assert_eq!(
                    remote::munmap(&session.access(), LinuxAbi::Aarch64, HEAP, 8 * PAGE_SIZE)?,
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
    let mut bytes = vec![11; 2 * PAGE_SIZE as usize];
    bytes[PAGE_SIZE as usize] = 17;
    file.write_all(&bytes).unwrap();
    let keep = Arc::new(());
    let retained = Arc::downgrade(&keep);
    let source = Arc::new(HostFileSource::keeping(file, Some(keep)).unwrap());
    assert_eq!(
        broker
            .register_backing(root, Backing::Source { source, offset: 0 })
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
    assert!(
        released_while_live,
        "the last owner VMA releases Keep before endpoint EOF"
    );
    assert!(retained.upgrade().is_none());
}

#[test]
fn native_lost_mmap_reply_preserves_complete_mapping_and_shared_charge() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::mapping::native_lost_mmap_reply_preserves_complete_mapping_and_shared_charge";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [0]);
                write(session, HEAP, vec![53]);
                assert_eq!(read(session, HEAP, 1), [53]);
                let a = arguments(HEAP + 4 * PAGE_SIZE, 2 * PAGE_SIZE, false, true);
                assert_eq!(
                    remote::mmap(
                        &session.access(),
                        mmap_policy(),
                        a,
                        remote::MmapSource::Anonymous {}
                    )?,
                    Err(Errno(EAGAIN))
                );
                assert_eq!(
                    remote::munmap(&session.access(), LinuxAbi::Aarch64, HEAP, 2 * PAGE_SIZE)?,
                    Ok(0)
                );
                assert_eq!(
                    remote::mmap(
                        &session.access(),
                        mmap_policy(),
                        a,
                        remote::MmapSource::Anonymous {}
                    )?,
                    Ok(a.address)
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
    let bytes = serde_json::to_vec(&remote::Operation::Mmap {
        policy: mmap_policy(),
        arguments: arguments(HEAP, 2 * PAGE_SIZE, false, true),
        source: remote::MmapSource::Anonymous {},
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

#[test]
fn native_mmap_backing_ids_remain_endpoint_scoped_before_publication() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::mapping::native_mmap_backing_ids_remain_endpoint_scoped_before_publication";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert!(matches!(
                    session.call(Operation::Read {
                        address: HEAP,
                        len: 1,
                        kind: ReadKind::Read
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                let a = arguments(HEAP, PAGE_SIZE, false, false);
                assert_eq!(
                    remote::mmap(
                        &session.access(),
                        mmap_policy(),
                        a,
                        remote::MmapSource::Registered {
                            backing: BackingId(1),
                            name: None,
                            flags: 0
                        }
                    )?,
                    Ok(HEAP)
                );
                assert_eq!(read(session, HEAP, 1), [19]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, root) = Broker::new(lease.clone(), &space(), metadata()).unwrap();
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let other = *broker
        .backings
        .keys()
        .find(|worker| **worker != root)
        .unwrap();
    assert_eq!(
        broker
            .register_backing(
                other,
                Backing::Source {
                    source: Arc::new(BytesSource::new(Arc::from([19]))),
                    offset: 0
                }
            )
            .unwrap(),
        BackingId(1)
    );
    let bytes = serde_json::to_vec(&remote::Operation::Mmap {
        policy: mmap_policy(),
        arguments: arguments(HEAP, PAGE_SIZE, false, false),
        source: remote::MmapSource::Registered {
            backing: BackingId(1),
            name: None,
            flags: 0,
        },
    })
    .unwrap();
    channel
        .send(
            &serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap(),
            &[],
        )
        .unwrap();
    assert!(matches!(broker.serve_one(), Err(OwnerError::Io(_))));
    assert!(channel.receive().is_err());
    holder.release();
    holder.stop();
    let mut peer = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut peer), 0);
}
