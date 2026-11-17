use super::*;
use crate::user::linux::abi::errno_table::EINVAL;
use crate::user::linux::process::mm::{AioRead, AioReadResult};

/// Exercise the private protocol with an actual populated owner table. The
/// worker owns neither a second table nor the pending pipe/eventfd resources.
#[test]
fn native_reap_fault_preserves_events_and_shared_peer_consumes_the_actual_ring() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::aio_reap::native_reap_fault_preserves_events_and_shared_peer_consumes_the_actual_ring";
    const RING: u64 = BASE + 4 * PAGE_SIZE;
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        let peer = client
            .with(lease, |session| {
                let access = session.access();
                let lookup: serde_json::Value = access.transact(&serde_json::json!({
                    "operation": "AioLookup", "address": RING
                }))?;
                if phase == "private" {
                    assert_eq!(
                        lookup,
                        serde_json::json!({
                            "reply": "AioLookup", "result": {"Err": 22}
                        })
                    );
                    assert!(access.active());
                    return Ok(None);
                }
                let handle = &lookup["result"]["Ok"];
                assert_eq!(handle["slot"], 0);
                assert_eq!(lookup["reply"], "AioLookup");
                let output = if phase == "root" {
                    BASE + PAGE_SIZE - 16
                } else {
                    BASE
                };
                let result: serde_json::Value = access.transact(&serde_json::json!({
                    "operation": "AioRead", "abi": "Aarch64", "handle": handle,
                    "min_nr": 1, "nr": 2, "events": output, "got": 0
                }))?;
                if phase == "root" {
                    assert_eq!(
                        result,
                        serde_json::json!({
                            "reply": "AioRead", "result": {"Err": 14}
                        })
                    );
                    assert_eq!(read(session, RING + 8, 4), 0_u32.to_le_bytes());
                    let prefix = read(session, BASE + PAGE_SIZE - 16, 16);
                    assert_eq!(&prefix[..8], &17_u64.to_le_bytes());
                    assert_eq!(&prefix[8..], &(RING + 0x80).to_le_bytes());
                    return Ok(Some((session.fork(false)?, session.fork(true)?)));
                }
                assert_eq!(
                    result,
                    serde_json::json!({
                        "reply": "AioRead", "result": {"Ok": {"got": 1, "done": true}}
                    })
                );
                assert_eq!(read(session, RING + 8, 4), 1_u32.to_le_bytes());
                let event = read(session, BASE, 32);
                assert_eq!(&event[..8], &17_u64.to_le_bytes());
                assert_eq!(&event[8..16], &(RING + 0x80).to_le_bytes());
                assert_eq!(&event[16..24], &23_i64.to_le_bytes());
                Ok(None)
            })
            .unwrap();
        if let Some((shared, private)) = peer {
            spawn(shared, lease, NAME, "shared").wait();
            spawn(private, lease, NAME, "private").wait();
        }
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (initial, resources, witness) =
        crate::user::linux::process::mm::pending_fixture(LinuxAbi::Aarch64, RING);
    initial
        .map(BASE, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, resources).unwrap();
    drop(initial);
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    assert!(witness.file.upgrade().is_none());
    assert!(witness.resfd.upgrade().is_none());
}

#[test]
fn native_lost_reap_reply_keeps_the_committed_head_and_output_without_replaying() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux_mm::aio_reap::native_lost_reap_reply_keeps_the_committed_head_and_output_without_replaying";
    const RING: u64 = BASE + 4 * PAGE_SIZE;
    if std::env::var_os("RAX_MM_OWNER_RPC_PHASE").is_none() {
        serve_if_requested(NAME);
    }
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let access = session.access();
                let handle = remote::aio_lookup(&access, RING)?.unwrap();
                assert_eq!(read(session, RING + 8, 4), 1_u32.to_le_bytes());
                let event = read(session, BASE, 32);
                assert_eq!(&event[..8], &17_u64.to_le_bytes());
                assert_eq!(&event[16..24], &23_i64.to_le_bytes());
                let mut arguments = AioRead {
                    abi: LinuxAbi::Aarch64,
                    handle,
                    min_nr: 0,
                    nr: 2,
                    events: 0,
                    got: 0,
                };
                assert_eq!(
                    remote::aio_read(&access, arguments)?,
                    Ok(AioReadResult { got: 0, done: true }),
                    "a lost reply did not restore or repeat the consumed completion"
                );
                arguments.min_nr = 3;
                assert_eq!(remote::aio_read(&access, arguments)?, Err(Errno(EINVAL)));
                assert!(
                    access.active(),
                    "invalid guest counts preserve the endpoint"
                );
                assert_eq!(read(session, RING + 8, 4), 1_u32.to_le_bytes());
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (initial, resources, witness) =
        crate::user::linux::process::mm::pending_fixture(LinuxAbi::Aarch64, RING);
    initial
        .map(BASE, PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    let (mut broker, client, _) = Broker::new(lease.clone(), &initial, resources).unwrap();
    drop(initial);
    let mut holder = LeaseWorker::spawn(&lease, NAME);
    holder.acquire();
    let mut channel = client.into_channel().unwrap();
    let (serial, peer) = begin_peer(&mut broker, &mut channel, &holder);
    let bytes = serde_json::to_vec(&remote::Operation::AioRead(AioRead {
        abi: LinuxAbi::Aarch64,
        handle: witness.handle,
        min_nr: 1,
        nr: 2,
        events: BASE,
        got: 0,
    }))
    .unwrap();
    channel
        .send(
            &serde_json::to_vec(&Request::Personality { serial, bytes }).unwrap(),
            &[],
        )
        .unwrap();
    channel.close();
    assert!(matches!(broker.serve_one(), Err(OwnerError::Io(_))));
    assert!(witness.file.upgrade().is_some());
    assert!(witness.resfd.upgrade().is_some());
    holder.release();
    holder.stop();
    let mut worker = spawn(peer, &lease, NAME, "peer");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    assert!(witness.file.upgrade().is_none());
    assert!(witness.resfd.upgrade().is_none());
}
