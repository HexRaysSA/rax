use super::*;

fn omitted(session: &mut Session<'_>, address: u64) {
    assert!(matches!(
        session.call(Operation::Read {
            address,
            len: 1,
            kind: ReadKind::Read
        }),
        Err(RemoteError::Memory(Failure::Fault { .. }))
    ));
}

#[test]
fn native_inheritance_keeps_shared_bytes_and_wipes_nested_private_workers() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::inheritance::native_inheritance_keeps_shared_bytes_and_wipes_nested_private_workers";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "nested" {
            client
                .with(lease, |session| {
                    omitted(session, HEAP);
                    assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [0]);
                    assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [41]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "private" {
            let nested = client
                .with(lease, |session| {
                    omitted(session, HEAP);
                    assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [0]);
                    assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [31]);
                    write(session, HEAP + PAGE_SIZE, vec![29]);
                    write(session, HEAP + 2 * PAGE_SIZE, vec![41]);
                    session.fork(true)
                })
                .unwrap();
            spawn(nested, lease, NAME, "nested").wait();
            client
                .with(lease, |session| {
                    assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [29]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, HEAP, 1), [17]);
                    assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [23]);
                    assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [31]);
                    write(session, HEAP + 2 * PAGE_SIZE, vec![37]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (private, shared) = client
            .with(lease, |session| {
                assert_eq!(
                    remote::madvise(&session.access(), HEAP, PAGE_SIZE, 10)?,
                    Ok(0)
                );
                assert_eq!(
                    remote::madvise(&session.access(), HEAP + PAGE_SIZE, PAGE_SIZE, 18)?,
                    Ok(0)
                );
                Ok((session.fork(true)?, session.fork(false)?))
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [17]);
                assert_eq!(read(session, HEAP + PAGE_SIZE, 1), [23]);
                assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [37]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let original = space();
    original
        .map(HEAP, 3 * PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    for (index, value) in [17, 23, 31].into_iter().enumerate() {
        original
            .write(HEAP + index as u64 * PAGE_SIZE, &[value])
            .unwrap();
    }
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, metadata()).unwrap();
    drop(original);
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_lost_inheritance_reply_keeps_flags_for_the_surviving_shared_peers_fork() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::inheritance::native_lost_inheritance_reply_keeps_flags_for_the_surviving_shared_peers_fork";
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        if std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap() == "private" {
            client
                .with(lease, |session| {
                    omitted(session, HEAP);
                    omitted(session, HEAP + 2 * PAGE_SIZE);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let private = client
            .with(lease, |session| {
                assert_eq!(read(session, HEAP, 1), [17]);
                assert_eq!(read(session, HEAP + 2 * PAGE_SIZE, 1), [23]);
                session.fork(true)
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let original = space();
    for (address, value) in [(HEAP, 17), (HEAP + 2 * PAGE_SIZE, 23)] {
        original
            .map(address, PAGE_SIZE, Mapping::anonymous(RW))
            .unwrap();
        original.write(address, &[value]).unwrap();
    }
    let (mut broker, client, _) = Broker::new(lease.clone(), &original, metadata()).unwrap();
    drop(original);
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::Madvise {
        address: HEAP,
        length: 3 * PAGE_SIZE,
        advice: 10,
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
