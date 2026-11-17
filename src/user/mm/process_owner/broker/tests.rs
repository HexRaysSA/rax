use std::io::{self, Write};
use std::os::fd::AsFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Child;
use std::sync::Arc;

use super::{BackingId, Broker, Event, ForkMetadata};
use crate::error::{MemoryAccessKind, MemoryFaultKind};
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::process_lease::test_worker::{rpc_if_requested, spawn_rpc};
use crate::user::mm::process_owner::wire::{Failure, Request, Response, TRANSFER_BYTES};
use crate::user::mm::process_owner::{
    Channel, Client, Map, Operation, OwnerError, PreparationKind, ReadKind, RemoteError, Session,
    Value,
};
use crate::user::mm::{
    AddressSpace, Backing, BytesSource, EXTENT, Mapping, MmError, PAGE_SIZE, Perms, SharedObject,
    SpaceConfig,
};

const BASE: u64 = 0x1_0000;
const SOURCE: u64 = BASE + 0x4_0000;
const SHARED: u64 = BASE + 0x8_0000;
const RW: Perms = Perms::READ.union(Perms::WRITE);

mod cpu;
mod linux;
mod linux_mm;
mod view;

/// Resource limits are process-wide. Use a fresh test image so parallel tests
/// and the user's process limits are never affected by the exhaustion probe.
fn isolated_descriptor_test(name: &str, run: impl FnOnce()) {
    const ROLE: &str = "RAX_MM_OWNER_DESCRIPTOR_TEST";
    if std::env::var(ROLE).ok().as_deref() == Some(name) {
        run();
    } else {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env(ROLE, name)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Worker(child).wait();
    }
}

struct DescriptorLimit {
    original: libc::rlimit,
    fillers: Vec<std::fs::File>,
    restored: bool,
}

impl DescriptorLimit {
    fn exhaust() -> Self {
        let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: the pointer is writable storage for one native rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
            0
        );
        // SAFETY: a successful getrlimit initialized both fields.
        let original = unsafe { original.assume_init() };
        let limit = libc::rlimit {
            // poll rejects an nfds count above RLIMIT_NOFILE. Keep a
            // positive limit and exhaust its slots instead of setting zero.
            rlim_cur: original.rlim_cur.min(64),
            rlim_max: original.rlim_max,
        };
        // SAFETY: this isolated test process owns its soft limit. Existing
        // descriptors remain open, and the hard limit is unchanged.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let mut result = Self {
            original,
            fillers: Vec::new(),
            restored: false,
        };
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => result.fillers.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        result
    }

    fn restore(&mut self) {
        self.fillers.clear();
        // SAFETY: restore the exact saved limit in this test process.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) },
            0
        );
        self.restored = true;
    }
}

impl Drop for DescriptorLimit {
    fn drop(&mut self) {
        if !self.restored {
            // SAFETY: unwind cleanup restores only this process's saved limit.
            let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) };
        }
    }
}

#[test]
fn native_descriptor_exhaustion_preserves_parent_session_and_fork_recovery() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_descriptor_exhaustion_preserves_parent_session_and_fork_recovery";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                for private in [false, true] {
                    assert!(matches!(
                        session.fork(private),
                        Err(RemoteError::Preparation(failure))
                            if failure.kind == PreparationKind::ProcessDescriptorLimit
                                && failure.native_errno == Some(libc::EMFILE)
                    ));
                }
                assert_eq!(read(session, BASE, 1), [5]);
                write(session, BASE, vec![42]);
                assert_eq!(read(session, BASE, 1), [42]);
                Ok(())
            })
            .unwrap();
        // The broker restores its limit after acknowledging the first End.
        // A subsequent turn must prepare a real child endpoint successfully.
        let child = client.with(lease, |session| session.fork(false)).unwrap();
        drop(child);
        client
            .with(lease, |session| {
                assert_eq!(read(session, BASE, 1), [42]);
                Ok(())
            })
            .unwrap();
    });
    isolated_descriptor_test(NAME, || {
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
        let mut limit = DescriptorLimit::exhaust();
        // Begin, two failed forks, three memory requests, End. No failed
        // preparation may publish a worker or inherit its backing catalog.
        for _ in 0..7 {
            assert_eq!(broker.serve_one().unwrap(), Event::Completed);
            assert_eq!(broker.endpoints.len(), 1);
            assert_eq!(broker.backings.len(), 1);
        }
        limit.restore();
        assert_eq!(drive(&mut broker, &mut worker), 0);
    });
}

#[test]
fn native_stale_fork_is_revoked_before_descriptor_preparation() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_stale_fork_is_revoked_before_descriptor_preparation";
    rpc_if_requested(NAME, |lease, stream| {
        let mut channel = Channel::new(stream).unwrap();
        lease
            .with(|| {
                // SAFETY: getpid has no pointers or mutable caller-owned state.
                let pid = unsafe { libc::getpid() };
                channel
                    .send(&serde_json::to_vec(&Request::Begin { pid }).unwrap(), &[])
                    .unwrap();
                let frame = channel.receive().unwrap();
                let Response::Grant { serial, .. } = serde_json::from_slice(&frame.bytes).unwrap()
                else {
                    panic!("expected grant")
                };
                let stale = Request::Fork {
                    serial: serial - 1,
                    private: false,
                };
                channel
                    .send(&serde_json::to_vec(&stale).unwrap(), &[])
                    .unwrap();
                assert!(
                    channel.receive().is_err(),
                    "a stale fork must not receive a recoverable resource reply"
                );
            })
            .unwrap();
    });
    isolated_descriptor_test(NAME, || {
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
        let mut limit = DescriptorLimit::exhaust();
        assert_eq!(broker.serve_one().unwrap(), Event::Completed);
        assert!(
            matches!(broker.serve_one(), Err(OwnerError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        limit.restore();
        assert_eq!(broker.serve_one().unwrap(), Event::Empty);
        assert!(broker.backings.is_empty());
        worker.wait();
    });
}

struct Metadata {
    fail_private: bool,
}

impl ForkMetadata for Metadata {
    fn fork_private(&self, _: &AddressSpace) -> Result<Self, MmError> {
        if self.fail_private {
            Err(MmError::OutOfMemory)
        } else {
            Ok(Self {
                fail_private: false,
            })
        }
    }
}

struct Worker(Child);

impl Worker {
    fn wait(&mut self) {
        assert!(self.0.wait().unwrap().success());
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn spawn(client: Client, lease: &ProcessLease, name: &str, phase: &str) -> Worker {
    let stream = client.into_channel().unwrap().into_stream().unwrap();
    let child = spawn_rpc(lease, name, &stream, phase);
    drop(stream);
    Worker(child)
}

fn space() -> AddressSpace {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    space.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
    space.write(BASE, &[5]).unwrap();
    space
}

fn drive<M: ForkMetadata>(broker: &mut Broker<M>, worker: &mut Worker) -> usize {
    drive_observing(broker, worker, |_| {})
}

fn drive_observing<M: ForkMetadata>(
    broker: &mut Broker<M>,
    worker: &mut Worker,
    mut observe: impl FnMut(&Broker<M>),
) -> usize {
    let mut errors = 0;
    loop {
        match broker.serve_one() {
            Ok(Event::Empty) => break,
            Ok(_) => (),
            Err(OwnerError::Io(_)) => errors += 1,
            Err(error) => panic!("unexpected owner failure: {error}"),
        }
        observe(broker);
    }
    worker.wait();
    assert!(broker.backings.is_empty());
    errors
}

fn read(session: &mut Session<'_>, address: u64, len: u32) -> Vec<u8> {
    let Value::Bytes { bytes } = session
        .call(Operation::Read {
            address,
            len,
            kind: ReadKind::Read,
        })
        .unwrap()
    else {
        panic!("expected bytes")
    };
    bytes
}

#[test]
fn native_owned_access_checks_windows_threads_and_weak_endpoint_lifetime() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_owned_access_checks_windows_threads_and_weak_endpoint_lifetime";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        if std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap() == "peer" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, BASE, 1), [42]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let access = client.with(lease, |session| {
            let access = session.access();
            assert!(access.active());
            assert_eq!(access.space(), session.space());
            assert_eq!(access.call(Operation::Read { address: BASE, len: 1, kind: ReadKind::Read })?, Value::Bytes { bytes: vec![5] });
            let foreign = access.clone();
            std::thread::spawn(move || {
                assert!(!foreign.active());
                assert!(matches!(foreign.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::PermissionDenied));
            }).join().unwrap();
            // Each callback exchanges on the channel without retaining its
            // mutex across the enclosing native-leased callback window.
            session.call(Operation::Write { address: BASE, bytes: vec![42], raw: false })?;
            assert_eq!(access.call(Operation::Read { address: BASE, len: 1, kind: ReadKind::Read })?, Value::Bytes { bytes: vec![42] });
            Ok(access)
        }).unwrap();
        assert!(!access.active());
        assert!(
            matches!(access.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::PermissionDenied)
        );
        client
            .with(lease, |session| {
                assert!(
                    access.active(),
                    "same-MM callback survives a budget boundary with a fresh turn"
                );
                access.call(Operation::Stats)?;
                session.call(Operation::Stats)?;
                Ok(())
            })
            .unwrap();
        let channel = client.into_channel().unwrap();
        assert!(
            matches!(access.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::NotConnected)
        );
        let mut client = Client::new(channel);
        let (peer, retained) = client
            .with(lease, |session| {
                Ok((session.fork(false)?, session.access()))
            })
            .unwrap();
        drop(client);
        assert!(!retained.active());
        assert!(
            matches!(retained.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::NotConnected)
        );
        spawn(peer, lease, NAME, "peer").wait();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, root) = Broker::new(
        lease.clone(),
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    let mut root_retired_with_peer_live = false;
    assert_eq!(
        drive_observing(&mut broker, &mut worker, |broker| {
            root_retired_with_peer_live |=
                !broker.endpoints.contains_key(&root) && !broker.endpoints.is_empty();
        }),
        0
    );
    assert!(
        root_retired_with_peer_live,
        "escaped weak access must not postpone root EOF while a peer is live"
    );
}

fn write(session: &mut Session<'_>, address: u64, bytes: Vec<u8>) {
    assert_eq!(
        session
            .call(Operation::Write {
                address,
                bytes,
                raw: false
            })
            .unwrap(),
        Value::Unit
    );
}

fn map(start: u64, len: u64, backing: Option<BackingId>, shared: bool) -> Operation {
    Operation::Map {
        mapping: Map {
            start,
            len,
            perms: RW.bits(),
            backing,
            offset: 0,
            shared,
            copy: false,
            name: Some("owner-test".into()),
            flags: 0x40,
        },
    }
}

#[test]
fn native_client_operations_keep_faults_bounds_sources_and_owner_lifetimes() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_client_operations_keep_faults_bounds_sources_and_owner_lifetimes";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client.with(lease, |session| {
            assert_ne!(session.space(), 0);
            assert_eq!(read(session, BASE, 1), [5]);
            session.call(map(BASE, (2 * TRANSFER_BYTES) as u64, None, false))?;
            let maximum = vec![255; TRANSFER_BYTES];
            write(session, BASE, maximum.clone());
            assert_eq!(read(session, BASE, TRANSFER_BYTES as u32), maximum);
            assert!(matches!(session.call(Operation::Write { address: BASE, bytes: vec![0; TRANSFER_BYTES + 1], raw: false }), Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::InvalidInput));
            assert_eq!(read(session, BASE, 1), [255], "size rejection leaves the session usable");
            session.call(map(SOURCE, PAGE_SIZE, Some(BackingId(1)), false))?;
            assert_eq!(read(session, SOURCE, 3), [7, 8, 9]);
            assert!(matches!(
                session.call(map(SOURCE + 2 * PAGE_SIZE, PAGE_SIZE, Some(BackingId(1)), true)),
                Err(RemoteError::Memory(Failure::InvalidArgument { .. }))
            ), "a PageSource supplies private frames, not a shared object");
            session.call(Operation::ReleaseBacking { backing: BackingId(1) })?;
            assert_eq!(read(session, SOURCE, 3), [7, 8, 9], "VMA retains a released source");
            session.call(Operation::Protect { start: BASE, len: PAGE_SIZE, perms: Perms::READ.bits() })?;
            assert!(matches!(session.call(Operation::Write { address: BASE, bytes: vec![1], raw: false }), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.address == BASE && fault.access == MemoryAccessKind::Write && fault.kind == MemoryFaultKind::Permission));
            session.call(Operation::Write { address: BASE, bytes: vec![3], raw: true })?;
            assert_eq!(read(session, BASE, 1), [3]);
            session.call(Operation::Probe { address: BASE, len: PAGE_SIZE as u32, access: MemoryAccessKind::Read })?;
            assert!(matches!(session.call(Operation::Translate { address: BASE, access: MemoryAccessKind::Read, raw: false })?, Value::Physical { .. }));
            assert!(matches!(session.call(Operation::Translate { address: BASE, access: MemoryAccessKind::Write, raw: true })?, Value::Physical { .. }));
            session.call(Operation::SetFlags { start: BASE, len: PAGE_SIZE, mask: 0xff, bits: 0x80 })?;
            session.call(Operation::Unmap { start: SOURCE, len: PAGE_SIZE })?;
            assert!(matches!(session.call(Operation::Read { address: SOURCE, len: 1, kind: ReadKind::Read }), Err(RemoteError::Memory(Failure::Fault { fault })) if fault.address == SOURCE && fault.kind == MemoryFaultKind::Unmapped));
            assert!(matches!(session.call(Operation::Protect { start: SOURCE, len: PAGE_SIZE, perms: 1 }), Err(RemoteError::Memory(Failure::NotMapped { address })) if address == SOURCE));
            session.call(map(SOURCE, PAGE_SIZE, Some(BackingId(3)), false))?;
            session.call(Operation::ReleaseBacking { backing: BackingId(3) })?;
            assert_eq!(read(session, SOURCE, 1), [4], "mapped file and Keep survive handle release");
            session.call(Operation::Unmap { start: SOURCE, len: PAGE_SIZE })?;
            session.call(Operation::Protect { start: BASE, len: PAGE_SIZE, perms: Perms::READ.union(Perms::EXEC).bits() })?;
            assert_eq!(session.call(Operation::Read { address: BASE, len: 1, kind: ReadKind::Fetch })?, Value::Bytes { bytes: vec![3] });
            session.call(Operation::Protect { start: BASE, len: PAGE_SIZE, perms: 0 })?;
            assert_eq!(session.call(Operation::Read { address: BASE, len: 1, kind: ReadKind::Raw })?, Value::Bytes { bytes: vec![3] });
            assert!(matches!(session.call(Operation::CodeChanges { epoch: 0 })?, Value::Code { epoch, .. } if epoch > 0));
            session.call(map(SOURCE, PAGE_SIZE, None, false))?;
            write(session, SOURCE, vec![21]);
            session.call(Operation::Remap { old: SOURCE, len: PAGE_SIZE, new: SOURCE + PAGE_SIZE })?;
            assert_eq!(read(session, SOURCE + PAGE_SIZE, 1), [21]);
            session.call(Operation::Discard { start: SOURCE + PAGE_SIZE, len: PAGE_SIZE })?;
            assert_eq!(read(session, SOURCE + PAGE_SIZE, 1), [0]);
            session.call(map(SHARED, PAGE_SIZE, Some(BackingId(2)), true))?;
            write(session, SHARED, vec![31]);
            let Operation::Map { mut mapping } = map(SOURCE, PAGE_SIZE, Some(BackingId(2)), false) else { unreachable!() };
            mapping.copy = true;
            session.call(Operation::Map { mapping })?;
            session.call(Operation::ReleaseBacking { backing: BackingId(2) })?;
            assert_eq!(read(session, SOURCE, 1), [31]);
            write(session, SOURCE, vec![32]);
            assert_eq!(read(session, SHARED, 1), [31]);
            session.call(Operation::FileCopyPolicy { start: SOURCE, len: PAGE_SIZE, copy: false })?;
            assert_eq!(read(session, SOURCE, 1), [32], "already-private frames remain private");
            assert!(matches!(session.call(Operation::Stats)?, Value::Stats { resident_pages, .. } if resident_pages > 0));
            assert!(matches!(session.call(Operation::Protect { start: SOURCE, len: PAGE_SIZE, perms: 0x80 }), Err(RemoteError::Memory(Failure::InvalidArgument { .. }))));
            Ok(())
        }).unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    let (mut broker, client, root) = Broker::new(
        lease.clone(),
        &initial,
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let source = Arc::new(BytesSource::new(Arc::from([7, 8, 9])));
    let lifetime = Arc::downgrade(&source);
    assert_eq!(
        broker
            .register_backing(root, Backing::Source { source, offset: 0 })
            .unwrap(),
        BackingId(1)
    );
    assert_eq!(
        broker
            .register_backing(
                root,
                Backing::Shared {
                    object: Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap()),
                    offset: 0
                }
            )
            .unwrap(),
        BackingId(2)
    );
    let mut file = crate::user::mm::anonymous_file().unwrap();
    file.set_len(PAGE_SIZE).unwrap();
    file.write_all(&[4]).unwrap();
    let keep = Arc::new(());
    let retained_token = Arc::downgrade(&keep);
    let source = Arc::new(crate::user::mm::HostFileSource::keeping(file, Some(keep)).unwrap());
    assert_eq!(
        broker
            .register_backing(root, Backing::Source { source, offset: 0 })
            .unwrap(),
        BackingId(3)
    );
    let mut worker = spawn(client, &lease, NAME, "root");
    let mut released_before_eof = false;
    assert_eq!(
        drive_observing(&mut broker, &mut worker, |broker| {
            released_before_eof |=
                retained_token.upgrade().is_none() && !broker.endpoints.is_empty();
        }),
        0
    );
    assert!(
        released_before_eof,
        "last unmap must release Keep while the worker endpoint is still live"
    );
    assert!(lifetime.upgrade().is_none());
    let mut original = [0];
    initial.read(BASE, &mut original).unwrap();
    assert_eq!(
        original,
        [5],
        "worker mutated the adopted owner MM, not the source snapshot"
    );
}

#[test]
fn native_fork_endpoints_share_or_snapshot_mm_and_inherit_backing_catalogs() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_fork_endpoints_share_or_snapshot_mm_and_inherit_backing_catalogs";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if phase == "shared" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, BASE, 1), [5]);
                    write(session, BASE, vec![77]);
                    write(session, SHARED, vec![11]);
                    session.call(Operation::Protect {
                        start: BASE,
                        len: PAGE_SIZE,
                        perms: Perms::READ.bits(),
                    })?;
                    session.call(map(SOURCE, PAGE_SIZE, Some(BackingId(1)), false))?;
                    assert_eq!(read(session, SOURCE, 1), [9]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        if phase == "private" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, BASE, 1), [5]);
                    write(session, BASE, vec![99]);
                    assert_eq!(read(session, SHARED, 1), [11]);
                    write(session, SHARED, vec![22]);
                    session.call(map(SOURCE, PAGE_SIZE, Some(BackingId(1)), false))?;
                    assert_eq!(read(session, SOURCE, 1), [9]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let (shared, private) = client
            .with(lease, |session| {
                Ok((session.fork(false)?, session.fork(true)?))
            })
            .unwrap();
        // Both native child launches and waits happen after End released the
        // family lease. Fresh exec closes inherited root/sibling endpoints.
        spawn(shared, lease, NAME, "shared").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, BASE, 1), [77]);
                assert_eq!(read(session, SOURCE, 1), [9]);
                assert!(matches!(
                    session.call(Operation::Write {
                        address: BASE,
                        bytes: vec![0],
                        raw: false
                    }),
                    Err(RemoteError::Memory(Failure::Fault { .. }))
                ));
                Ok(())
            })
            .unwrap();
        spawn(private, lease, NAME, "private").wait();
        client
            .with(lease, |session| {
                assert_eq!(read(session, BASE, 1), [77]);
                assert_eq!(read(session, SHARED, 1), [22]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    let shared = Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap());
    initial
        .map(
            SHARED,
            PAGE_SIZE,
            Mapping {
                perms: RW,
                backing: Backing::Shared {
                    object: shared,
                    offset: 0,
                },
                shared: true,
                name: None,
                flags: 0,
            },
        )
        .unwrap();
    let (mut broker, client, root) = Broker::new(
        lease.clone(),
        &initial,
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let source = Arc::new(BytesSource::new(Arc::from([9])));
    let lifetime = Arc::downgrade(&source);
    broker
        .register_backing(root, Backing::Source { source, offset: 0 })
        .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
    assert!(lifetime.upgrade().is_none());
}

#[test]
fn native_failed_private_preparation_keeps_the_current_session_usable() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_failed_private_preparation_keeps_the_current_session_usable";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                assert!(matches!(
                    session.fork(true),
                    Err(RemoteError::Memory(Failure::OutOfMemory))
                ));
                assert_eq!(read(session, BASE, 1), [5]);
                write(session, BASE, vec![8]);
                assert_eq!(read(session, BASE, 1), [8]);
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) =
        Broker::new(lease.clone(), &space(), Metadata { fail_private: true }).unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_stale_request_retires_only_its_endpoint_and_peer_retains_shared_mm() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_stale_request_retires_only_its_endpoint_and_peer_retains_shared_mm";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        if std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap() == "peer" {
            client
                .with(lease, |session| {
                    assert_eq!(read(session, BASE, 1), [5]);
                    write(session, BASE, vec![42]);
                    assert_eq!(read(session, BASE, 1), [42]);
                    Ok(())
                })
                .unwrap();
            return;
        }
        let peer = client.with(lease, |session| session.fork(false)).unwrap();
        let mut channel = client.into_channel().unwrap();
        lease
            .with(|| {
                // SAFETY: getpid has no pointers or caller-owned mutable state.
                let pid = unsafe { libc::getpid() };
                channel
                    .send(&serde_json::to_vec(&Request::Begin { pid }).unwrap(), &[])
                    .unwrap();
                let frame = channel.receive().unwrap();
                let Response::Grant { serial, .. } = serde_json::from_slice(&frame.bytes).unwrap()
                else {
                    panic!("expected grant")
                };
                assert!(serial > 1);
                let stale = Request::Memory {
                    serial: serial - 1,
                    operation: Operation::Write {
                        address: BASE,
                        bytes: vec![99],
                        raw: false,
                    },
                };
                channel
                    .send(&serde_json::to_vec(&stale).unwrap(), &[])
                    .unwrap();
                assert!(channel.receive().is_err());
            })
            .unwrap();
        spawn(peer, lease, NAME, "peer").wait();
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
    assert_eq!(drive(&mut broker, &mut worker), 1);
}

#[test]
fn malformed_unknown_and_oversized_requests_close_without_dispatching_memory() {
    let oversized = serde_json::to_vec(&Request::Memory {
        serial: 1,
        operation: Operation::Read {
            address: BASE,
            len: (TRANSFER_BYTES + 1) as u32,
            kind: ReadKind::Read,
        },
    })
    .unwrap();
    let corpus = [
        br#"{"request":"Begin","pid":1,"unknown":true}"#.to_vec(),
        br#"{"request":"Memory","serial":1,"operation":{"op":"unknown"}}"#.to_vec(),
        oversized,
    ];
    for bytes in corpus {
        let lease = Arc::new(ProcessLease::new().unwrap());
        let (mut broker, client, _) = Broker::new(
            lease,
            &space(),
            Metadata {
                fail_private: false,
            },
        )
        .unwrap();
        let mut channel = client.into_channel().unwrap();
        channel.send(&bytes, &[]).unwrap();
        assert!(
            matches!(broker.serve_one(), Err(OwnerError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(channel.receive().is_err());
        assert_eq!(broker.serve_one().unwrap(), Event::Empty);
    }
    // No request accepts ancillary descriptors. Reject and close them before
    // parsing or executing even an otherwise well-formed Begin request.
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(
        lease,
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut channel = client.into_channel().unwrap();
    let file = crate::user::mm::anonymous_file().unwrap();
    channel
        .send(br#"{"request":"Begin","pid":1}"#, &[file.as_fd()])
        .unwrap();
    assert!(
        matches!(broker.serve_one(), Err(OwnerError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert!(channel.receive().is_err());
    assert_eq!(broker.serve_one().unwrap(), Event::Empty);
}

#[test]
fn native_client_unwind_closes_turn_and_revokes_reentry() {
    const NAME: &str = "user::mm::process_owner::broker::tests::native_client_unwind_closes_turn_and_revokes_reentry";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), RemoteError> =
                client.with(lease, |_session| panic!("interrupt owner client session"));
        }));
        assert!(panic.is_err());
        assert!(
            lease.with(|| ()).is_err(),
            "caught unwind cannot authorize reentry"
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
    lease.with(|| ()).unwrap();
}

#[test]
fn malformed_reply_closes_client_without_replacing_the_first_transport_error() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        let begin: Request = serde_json::from_slice(&server.receive().unwrap().bytes).unwrap();
        assert!(matches!(begin, Request::Begin { .. }));
        super::send(
            &mut server,
            &Response::Grant {
                serial: 1,
                space: 1,
            },
            &[],
        )
        .unwrap();
        let read: Request = serde_json::from_slice(&server.receive().unwrap().bytes).unwrap();
        assert!(matches!(
            read,
            Request::Memory {
                operation: Operation::Read { len: 1, .. },
                ..
            }
        ));
        super::send(
            &mut server,
            &Response::Result {
                result: Ok(Value::Unit),
            },
            &[],
        )
        .unwrap();
        assert!(server.receive().is_err());
    });
    let lease = ProcessLease::new().unwrap();
    let mut client = Client::new(channel);
    let result = client.with(&lease, |session| {
        session.call(Operation::Read {
            address: BASE,
            len: 1,
            kind: ReadKind::Read,
        })
    });
    assert!(
        matches!(result, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert!(client.with(&lease, |_| Ok(())).is_err());
    owner.join().unwrap();
}
