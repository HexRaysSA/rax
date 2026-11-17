use std::io;

use super::*;
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::process_owner::broker::send;
use crate::user::mm::process_owner::wire::{ReadKind, Request, Response};
use crate::user::mm::process_owner::{Channel, Client};

fn receive(server: &mut Channel) -> Request {
    let frame = server.receive().unwrap();
    assert!(frame.files.is_empty());
    serde_json::from_slice(&frame.bytes).unwrap()
}

fn grant(server: &mut Channel, serial: u64, space: u64) {
    assert!(matches!(receive(server), Request::Begin { .. }));
    send(server, &Response::Grant { serial, space }, &[]).unwrap();
}

fn stats(server: &mut Channel, serial: u64) {
    assert!(
        matches!(receive(server), Request::Memory { serial: s, operation: Operation::Stats } if s == serial)
    );
    send(
        server,
        &Response::Result {
            result: Ok(Value::Stats {
                va_limit: 4096,
                resident_pages: 0,
                attached_extents: 0,
            }),
        },
        &[],
    )
    .unwrap();
}

fn end(server: &mut Channel, serial: u64) {
    assert!(matches!(receive(server), Request::End { serial: s } if s == serial));
    send(server, &Response::Ended, &[]).unwrap();
}

#[test]
fn weak_access_rejects_changed_mm_and_expires_on_channel_transfer() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        grant(&mut server, 1, 11);
        stats(&mut server, 1);
        end(&mut server, 1);
        grant(&mut server, 2, 12);
        stats(&mut server, 2);
        end(&mut server, 2);
        assert!(server.receive().is_err());
    });
    let lease = ProcessLease::new().unwrap();
    let mut client = Client::new(channel);
    let old = client
        .with(&lease, |session| {
            let access = session.access();
            assert_eq!(access.space(), 11);
            assert!(access.active());
            access.call(Operation::Stats)?;
            Ok(access)
        })
        .unwrap();
    assert!(!old.active());
    assert!(
        matches!(old.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::PermissionDenied)
    );
    client.with(&lease, |session| {
        assert_eq!(session.space(), 12);
        assert!(!old.active());
        assert!(matches!(old.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::PermissionDenied));
        session.access().call(Operation::Stats)?;
        Ok(())
    }).unwrap();
    // Weak callback capabilities cannot prevent a deliberate FD handoff.
    let channel = client.into_channel().unwrap();
    assert!(!old.active());
    assert!(
        matches!(old.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::NotConnected)
    );
    drop(channel);
    owner.join().unwrap();
}

#[test]
fn malformed_access_reply_revokes_the_window_and_preserves_first_error() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        grant(&mut server, 1, 1);
        assert!(matches!(receive(&mut server), Request::Memory { .. }));
        send(
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
        let access = session.access();
        let result = access.call(Operation::Read {
            address: 0,
            len: 1,
            kind: ReadKind::Read,
        });
        assert!(!access.active());
        result
    });
    assert!(
        matches!(result, Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::InvalidData)
    );
    owner.join().unwrap();
}

#[test]
fn poisoned_exchange_is_closed_without_restoring_access() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        grant(&mut server, 1, 1);
        assert!(server.receive().is_err());
    });
    let lease = ProcessLease::new().unwrap();
    let mut client = Client::new(channel);
    let endpoint = client.endpoint.clone();
    let result = client.with(&lease, |session| {
        let endpoint = endpoint.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = endpoint.channel.lock().unwrap();
                panic!("inject exchange mutex poison");
            })
            .join()
            .is_err()
        );
        session.access().call(Operation::Stats)
    });
    assert!(matches!(result, Err(RemoteError::Transport(_))));
    assert!(endpoint.current(1, None).is_err());
    let channel = endpoint.channel.lock().unwrap_err().into_inner();
    assert!(
        channel.poll_fd().is_err(),
        "poisoned transport must be closed, not retained until Client drop"
    );
    drop(channel);
    owner.join().unwrap();
}

#[test]
fn lost_reply_revokes_access_before_returning_the_first_transport_error() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        grant(&mut server, 1, 1);
        assert!(matches!(receive(&mut server), Request::Memory { .. }));
        // Close after consuming the request, before producing any reply.
        // Retrying the operation would risk applying an ambiguous mutation.
    });
    let lease = ProcessLease::new().unwrap();
    let mut client = Client::new(channel);
    let result = client.with(&lease, |session| {
        let access = session.access();
        let result = access.call(Operation::Stats);
        assert!(matches!(&result, Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::UnexpectedEof));
        assert!(!access.active(), "revocation must precede callback return");
        assert!(matches!(access.call(Operation::Stats), Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::PermissionDenied));
        result
    });
    assert!(
        matches!(result, Err(RemoteError::Transport(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    owner.join().unwrap();
}

#[test]
fn bounded_personality_calls_check_admission_before_io_and_keep_local_rejection_usable() {
    let (mut server, channel) = Channel::pair().unwrap();
    let owner = std::thread::spawn(move || {
        grant(&mut server, 1, 1);
        stats(&mut server, 1);
        let Request::Personality { serial, bytes } = receive(&mut server) else {
            panic!("expected personality operation");
        };
        assert_eq!(serial, 1);
        assert_eq!(
            bytes.len(),
            crate::user::mm::process_owner::wire::PERSONALITY_BYTES
        );
        assert_eq!(
            serde_json::from_slice::<String>(&bytes).unwrap().len(),
            bytes.len() - 2
        );
        send(
            &mut server,
            &Response::Personality {
                bytes: b"true".to_vec(),
            },
            &[],
        )
        .unwrap();
        end(&mut server, 1);
        assert!(server.receive().is_err());
    });
    let lease = ProcessLease::new().unwrap();
    let mut client = Client::new(channel);
    let access = client.with(&lease, |session| {
        let access = session.access();
        let original = access.execution_identity()?;
        let oversize: Result<bool, _> = access.transact(&"a".repeat(crate::user::mm::process_owner::wire::PERSONALITY_BYTES - 1));
        assert!(matches!(oversize, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::InvalidInput));
        assert!(access.active());
        assert_eq!(access.execution_identity()?, original);
        access.call(Operation::Stats)?;
        let maximum: bool = access.transact(&"a".repeat(crate::user::mm::process_owner::wire::PERSONALITY_BYTES - 2))?;
        assert!(maximum);
        assert_eq!(access.execution_identity()?, (original.0, original.1 + 1));
        let foreign = access.clone();
        assert!(std::thread::spawn(move || {
            let result: Result<bool, _> = foreign.transact(&true);
            matches!(result, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        }).join().unwrap());
        Ok(access)
    }).unwrap();
    assert!(!access.active());
    let result: Result<bool, _> = access.transact(&true);
    assert!(
        matches!(result, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    drop(client);
    owner.join().unwrap();
}

#[test]
fn malformed_or_lost_personality_reply_revokes_access_without_retry() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        #[allow(dead_code)]
        result: bool,
    }
    for case in 0..5 {
        let (mut server, channel) = Channel::pair().unwrap();
        let owner = std::thread::spawn(move || {
            grant(&mut server, 1, 1);
            assert!(matches!(receive(&mut server), Request::Personality { .. }));
            let reply = match case {
                0 => Response::Personality {
                    bytes: br#"{"result":true,"unexpected":0}"#.to_vec(),
                },
                1 => Response::Personality {
                    bytes: vec![0; crate::user::mm::process_owner::wire::PERSONALITY_BYTES + 1],
                },
                2 => Response::Ended,
                3 => Response::Personality {
                    bytes: br#"{"result":true}"#.to_vec(),
                },
                4 => return, // Lost after consuming the request.
                _ => unreachable!(),
            };
            let file = crate::user::mm::anonymous_file().unwrap();
            let files = if case == 3 {
                vec![std::os::fd::AsFd::as_fd(&file)]
            } else {
                vec![]
            };
            send(&mut server, &reply, &files).unwrap();
            assert!(server.receive().is_err());
        });
        let lease = ProcessLease::new().unwrap();
        let mut client = Client::new(channel);
        let result = client.with(&lease, |session| {
            let access = session.access();
            let result: Result<Reply, _> = access.transact(&true);
            assert!(!access.active());
            let repeated: Result<Reply, _> = access.transact(&true);
            assert!(matches!(repeated, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied));
            result
        });
        let expected = if case == 4 {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::InvalidData
        };
        assert!(matches!(result, Err(RemoteError::Transport(error)) if error.kind() == expected));
        assert!(client.with(&lease, |_| Ok(())).is_err());
        owner.join().unwrap();
    }
}

#[test]
fn linux_reply_for_a_different_operation_revokes_access_before_returning() {
    use crate::user::linux::abi::LinuxAbi;
    use crate::user::linux::process::mm::{
        BrkPolicy, LockPolicy, MmapArgs, MmapPolicy, ProtectPolicy, RemapArgs, remote,
    };

    for case in 0..14 {
        let (mut server, channel) = Channel::pair().unwrap();
        let owner = std::thread::spawn(move || {
            grant(&mut server, 1, 1);
            let Request::Personality { bytes, .. } = receive(&mut server) else {
                panic!("expected Linux MM operation");
            };
            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                request["operation"],
                [
                    "Brk",
                    "Munmap",
                    "Mprotect",
                    "Mseal",
                    "Mlock",
                    "Munlock",
                    "Mlockall",
                    "Munlockall",
                    "Mmap",
                    "Msync",
                    "Mincore",
                    "Madvise",
                    "Mremap",
                    "AioSetup"
                ][case]
            );
            let wrong = [
                "Munmap",
                "Mprotect",
                "Mseal",
                "Mlock",
                "Munlock",
                "Mlockall",
                "Munlockall",
                "Mmap",
                "Msync",
                "Mincore",
                "Madvise",
                "Brk",
                "Brk",
                "Brk",
            ][case];
            let bytes =
                serde_json::to_vec(&serde_json::json!({"reply": wrong, "result": {"Ok": 0}}))
                    .unwrap();
            send(&mut server, &Response::Personality { bytes }, &[]).unwrap();
            assert!(
                server.receive().is_err(),
                "no retry or End after fatal decoding"
            );
        });
        let lease = ProcessLease::new().unwrap();
        let mut client = Client::new(channel);
        let result = client.with(&lease, |session| {
            let access = session.access();
            let result = match case {
                0 => remote::brk(&access, BrkPolicy { abi: LinuxAbi::Aarch64, persona: 0, privileged: false, memlock_limit: 0 }, 0),
                1 => remote::munmap(&access, LinuxAbi::Aarch64, 0, 4096),
                2 => remote::mprotect(&access, ProtectPolicy { abi: LinuxAbi::Aarch64, persona: 0 }, 0, 4096, 1),
                3 => remote::mseal(&access, 0, 4096, 0),
                4 => remote::mlock(&access, LockPolicy { abi: LinuxAbi::Aarch64, privileged: false, memlock_limit: 4096 }, 0, 4096, 0),
                5 => remote::munlock(&access, 0, 4096),
                6 => remote::mlockall(&access, LockPolicy { abi: LinuxAbi::Aarch64, privileged: false, memlock_limit: 4096 }, 2),
                7 => remote::munlockall(&access),
                8 => remote::mmap(&access, MmapPolicy { lock: LockPolicy { abi: LinuxAbi::Aarch64, privileged: false, memlock_limit: 4096 }, persona: 0 }, MmapArgs { address: 327680, length: 4096, protection: 3, flags: 50, offset: 0 }, remote::MmapSource::Anonymous {}),
                9 => remote::msync(&access, 327680, 4096, 4),
                10 => remote::mincore(&access, LinuxAbi::Aarch64, 327680, 4096, 360448),
                11 => remote::madvise(&access, 327680, 4096, 4),
                12 => remote::mremap(&access, LockPolicy { abi: LinuxAbi::Aarch64, privileged: false, memlock_limit: 4096 }, RemapArgs { old_address: 327680, old_length: 4096, new_length: 4096, flags: 3, new_address: 360448 }),
                13 => remote::aio_setup(&access, LockPolicy { abi: LinuxAbi::Aarch64, privileged: false, memlock_limit: 4096 }, 8, 65536),
                _ => unreachable!(),
            };
            assert!(!access.active());
            assert!(matches!(access.call(Operation::Stats), Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::PermissionDenied));
            result.map(|_| ())
        });
        assert!(
            matches!(result, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(client.with(&lease, |_| Ok(())).is_err());
        owner.join().unwrap();
    }
}
