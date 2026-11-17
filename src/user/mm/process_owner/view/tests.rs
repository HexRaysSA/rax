use super::*;
use crate::user::mm::anonymous_file;
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::process_owner::broker::send;
use crate::user::mm::process_owner::wire::{Request, Response, ViewFailure};
use crate::user::mm::process_owner::{Channel, Client};
use std::os::fd::AsFd;

fn request(channel: &mut Channel) -> Request {
    let frame = channel.receive().unwrap();
    assert!(frame.files.is_empty());
    serde_json::from_slice(&frame.bytes).unwrap()
}

fn begin(channel: &mut Channel) {
    assert!(matches!(request(channel), Request::Begin { .. }));
    send(
        channel,
        &Response::Grant {
            serial: 1,
            space: 1,
        },
        &[],
    )
    .unwrap();
}

#[test]
fn malformed_arena_imports_revoke_the_execution_window() {
    for case in 0..5 {
        let (mut server, channel) = Channel::pair().unwrap();
        let file = anonymous_file().unwrap();
        file.set_len(2 * EXTENT).unwrap();
        let worker = std::thread::spawn(move || {
            begin(&mut server);
            assert!(matches!(
                request(&mut server),
                Request::View {
                    operation: ViewOperation::Arena,
                    ..
                }
            ));
            let mut bytes = 2 * EXTENT;
            let mut files = vec![file.as_fd()];
            let value = match case {
                0 => {
                    files.clear();
                    ViewValue::Arena { bytes }
                }
                1 => {
                    bytes = 0;
                    ViewValue::Arena { bytes }
                }
                2 => {
                    bytes += PAGE_SIZE;
                    ViewValue::Arena { bytes }
                }
                3 => {
                    files.push(file.as_fd());
                    ViewValue::Arena { bytes }
                }
                4 => ViewValue::Translation {
                    translation: Translation::Private { address: 0 },
                },
                _ => unreachable!(),
            };
            send(&mut server, &Response::View { result: Ok(value) }, &files).unwrap();
            assert!(
                server.receive().is_err(),
                "malformed reply must close the endpoint"
            );
        });
        let lease = ProcessLease::new().unwrap();
        let mut client = Client::new(channel);
        let result: Result<(), RemoteError> = client.with(&lease, |session| {
            let access = session.access();
            let error = View::import(access.clone()).unwrap_err();
            assert!(!access.active());
            Err(error)
        });
        assert!(
            matches!(result, Err(RemoteError::Transport(error)) if error.kind() == io::ErrorKind::InvalidData),
            "arena case {case}"
        );
        worker.join().unwrap();
    }
}

#[test]
fn malformed_extent_imports_and_fileless_failure_revoke_before_physical_use() {
    for case in 0..12 {
        let (mut server, channel) = Channel::pair().unwrap();
        let file = anonymous_file().unwrap();
        file.set_len(2 * EXTENT).unwrap();
        let worker = std::thread::spawn(move || {
            begin(&mut server);
            assert!(matches!(
                request(&mut server),
                Request::View {
                    operation: ViewOperation::Arena,
                    ..
                }
            ));
            send(
                &mut server,
                &Response::View {
                    result: Ok(ViewValue::Arena { bytes: 2 * EXTENT }),
                },
                &[file.as_fd()],
            )
            .unwrap();
            assert!(matches!(
                request(&mut server),
                Request::View {
                    operation: ViewOperation::Translate { .. },
                    ..
                }
            ));
            let mut address = 0;
            let mut base = 0;
            let mut len = EXTENT;
            let mut offset = 0;
            let mut files = vec![file.as_fd()];
            match case {
                1 => len = 0,
                2 => len = 2 * EXTENT,
                3 => base = 1,
                4 => offset = 1,
                5 => len = 1,
                6 => address = 2 * EXTENT,
                7 | 9 | 10 => files.clear(),
                8 => files.push(file.as_fd()),
                11 => address = 1,
                _ => (),
            }
            let translation = if case == 0 {
                Translation::Private { address }
            } else {
                Translation::File {
                    address,
                    base,
                    len,
                    offset,
                    writable: true,
                    identity: [1, 1],
                }
            };
            let value = if case == 9 {
                ViewValue::Arena { bytes: 2 * EXTENT }
            } else {
                ViewValue::Translation { translation }
            };
            let result = if case == 10 {
                Err(ViewFailure::HostMemory)
            } else {
                Ok(value)
            };
            send(&mut server, &Response::View { result }, &files).unwrap();
            assert!(server.receive().is_err());
        });
        let lease = ProcessLease::new().unwrap();
        let mut client = Client::new(channel);
        let result: Result<(), RemoteError> = client.with(&lease, |session| {
            let access = session.access();
            let view = View::import(access.clone())?;
            let error = view
                .translate(0x1_0000, MemoryAccessKind::Read, false)
                .unwrap_err();
            assert!(!access.active());
            Err(error)
        });
        let expected = if case == 10 {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::InvalidData
        };
        assert!(
            matches!(result, Err(RemoteError::Transport(error)) if error.kind() == expected),
            "extent case {case}"
        );
        worker.join().unwrap();
    }
}
