//! Messages exchanged over a private parent-child tracing connection.
//!
//! These are emulator-internal messages, not guest ABI structures. A
//! connection identifies its peer; request IDs distinguish concurrent
//! callers. A decoder rejects unknown tags, trailing bytes, and truncated
//! fields so that a malformed peer cannot manufacture a partial request.
//! Signal ranges, request ownership, and stop state are validated by the
//! tracing state machine, not by this structural decoder.

use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResumeMode {
    Continue,
    Step,
    Detach,
    Kill,
    ThreadUpdate,
}

/// The initial trace relationship, a stop, and a request to resume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Message {
    TraceMe,
    Attach {
        id: u64,
        ruid: u32,
        euid: u32,
        sigexc: bool,
    },
    AttachReply {
        id: u64,
        errno: i32,
        denied: bool,
        /// Registered non-child targets report p_oppid explicitly. None
        /// retains the original parent-child wire layout.
        original_parent: Option<i32>,
    },
    Signal {
        signal: i32,
        sender: i32,
        uid: u32,
    },
    Stop {
        thread: u64,
        signal: i32,
        uid: u32,
        notify: bool,
    },
    JobStop {
        thread: u64,
        signal: i32,
        uid: u32,
    },
    JobContinue,
    Resume {
        id: u64,
        signal: i32,
        mode: ResumeMode,
        uid: u32,
    },
    Reply {
        id: u64,
        errno: i32,
    },
    ExitReport {
        status: i32,
        uid: u32,
        rusage: [u8; 144],
        reparented: bool,
    },
    ReapAck {
        id: u64,
    },
    ReapReply {
        id: u64,
        retained: bool,
    },
    ImageEpoch {
        epoch: u64,
    },
    CodeFlags {
        epoch: u64,
        flags: Option<u32>,
    },
    CommitUpdate {
        id: u64,
    },
    CommitRemoteUpdate {
        id: u64,
        instance: u64,
        thread: u64,
    },
}

impl Message {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Message::TraceMe => bytes.push(1),
            Message::Attach {
                id,
                ruid,
                euid,
                sigexc,
            } => {
                bytes.push(5);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&ruid.to_le_bytes());
                bytes.extend_from_slice(&euid.to_le_bytes());
                bytes.push(u8::from(sigexc));
            }
            Message::AttachReply {
                id,
                errno,
                denied,
                original_parent,
            } => {
                bytes.push(if original_parent.is_some() { 12 } else { 6 });
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&errno.to_le_bytes());
                bytes.push(u8::from(denied));
                if let Some(parent) = original_parent {
                    bytes.extend_from_slice(&parent.to_le_bytes());
                }
            }
            Message::Signal {
                signal,
                sender,
                uid,
            } => {
                bytes.push(7);
                bytes.extend_from_slice(&signal.to_le_bytes());
                bytes.extend_from_slice(&sender.to_le_bytes());
                bytes.extend_from_slice(&uid.to_le_bytes());
            }
            Message::Stop {
                thread,
                signal,
                uid,
                notify,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(&thread.to_le_bytes());
                bytes.extend_from_slice(&signal.to_le_bytes());
                bytes.extend_from_slice(&uid.to_le_bytes());
                bytes.push(u8::from(notify));
            }
            Message::JobStop {
                thread,
                signal,
                uid,
            } => {
                bytes.push(10);
                bytes.extend_from_slice(&thread.to_le_bytes());
                bytes.extend_from_slice(&signal.to_le_bytes());
                bytes.extend_from_slice(&uid.to_le_bytes());
            }
            Message::JobContinue => bytes.push(11),
            Message::Resume {
                id,
                signal,
                mode,
                uid,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&signal.to_le_bytes());
                bytes.push(match mode {
                    ResumeMode::Continue => 0,
                    ResumeMode::Step => 1,
                    ResumeMode::Detach => 2,
                    ResumeMode::Kill => 3,
                    ResumeMode::ThreadUpdate => 4,
                });
                bytes.extend_from_slice(&uid.to_le_bytes());
            }
            Message::Reply { id, errno } => {
                bytes.push(4);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&errno.to_le_bytes());
            }
            Message::ExitReport {
                status,
                uid,
                rusage,
                reparented,
            } => {
                bytes.push(13);
                bytes.extend_from_slice(&status.to_le_bytes());
                bytes.extend_from_slice(&uid.to_le_bytes());
                bytes.extend_from_slice(&rusage);
                bytes.push(u8::from(reparented));
            }
            Message::ReapAck { id } => {
                bytes.push(14);
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            Message::ReapReply { id, retained } => {
                bytes.push(16);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.push(u8::from(retained));
            }
            Message::CodeFlags { epoch, flags } => {
                bytes.push(17);
                bytes.extend_from_slice(&epoch.to_le_bytes());
                bytes.push(u8::from(flags.is_some()));
                bytes.extend_from_slice(&flags.unwrap_or(0).to_le_bytes());
            }
            Message::ImageEpoch { epoch } => {
                bytes.push(15);
                bytes.extend_from_slice(&epoch.to_le_bytes());
            }
            Message::CommitUpdate { id } => {
                bytes.push(8);
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            Message::CommitRemoteUpdate {
                id,
                instance,
                thread,
            } => {
                bytes.push(9);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&instance.to_le_bytes());
                bytes.extend_from_slice(&thread.to_le_bytes());
            }
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid tracing message");
        match bytes {
            [17, rest @ ..] if rest.len() == 13 && rest[8] <= 1 => {
                let epoch = u64::from_le_bytes(rest[..8].try_into().unwrap());
                let raw = u32::from_le_bytes(rest[9..].try_into().unwrap());
                if epoch == 0 || rest[8] == 0 && raw != 0 {
                    return Err(invalid());
                }
                Ok(Message::CodeFlags {
                    epoch,
                    flags: (rest[8] != 0).then_some(raw),
                })
            }
            [15, rest @ ..] if rest.len() == 8 => {
                let epoch = u64::from_le_bytes(rest.try_into().unwrap());
                if epoch == 0 {
                    return Err(invalid());
                }
                Ok(Message::ImageEpoch { epoch })
            }
            [14, rest @ ..] if rest.len() == 8 => Ok(Message::ReapAck {
                id: u64::from_le_bytes(rest.try_into().unwrap()),
            }),
            [16, rest @ ..] if rest.len() == 9 && rest[8] <= 1 => Ok(Message::ReapReply {
                id: u64::from_le_bytes(rest[..8].try_into().unwrap()),
                retained: rest[8] != 0,
            }),
            [13, rest @ ..] if rest.len() == 153 && rest[152] <= 1 => {
                let status = i32::from_le_bytes(rest[..4].try_into().unwrap());
                if status < 0 || status > 0xffff || status & 0x7f == 0x7f {
                    return Err(invalid());
                }
                Ok(Message::ExitReport {
                    status,
                    uid: u32::from_le_bytes(rest[4..8].try_into().unwrap()),
                    rusage: rest[8..152].try_into().unwrap(),
                    reparented: rest[152] != 0,
                })
            }
            [1] => Ok(Message::TraceMe),
            [11] => Ok(Message::JobContinue),
            [10, rest @ ..] if rest.len() == 16 => Ok(Message::JobStop {
                thread: u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?),
                signal: i32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?),
                uid: u32::from_le_bytes(rest[12..].try_into().map_err(|_| invalid())?),
            }),
            [5, rest @ ..] if rest.len() == 17 && rest[16] <= 1 => Ok(Message::Attach {
                id: u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?),
                ruid: u32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?),
                euid: u32::from_le_bytes(rest[12..16].try_into().map_err(|_| invalid())?),
                sigexc: rest[16] != 0,
            }),
            [6, rest @ ..] if rest.len() == 13 && rest[12] <= 1 => Ok(Message::AttachReply {
                id: u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?),
                errno: i32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?),
                denied: rest[12] != 0,
                original_parent: None,
            }),
            [12, rest @ ..] if rest.len() == 17 && rest[12] <= 1 => {
                let parent = i32::from_le_bytes(rest[13..17].try_into().map_err(|_| invalid())?);
                if parent < 0 {
                    return Err(invalid());
                }
                Ok(Message::AttachReply {
                    id: u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?),
                    errno: i32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?),
                    denied: rest[12] != 0,
                    original_parent: Some(parent),
                })
            }
            [7, rest @ ..] if rest.len() == 12 => Ok(Message::Signal {
                signal: i32::from_le_bytes(rest[..4].try_into().map_err(|_| invalid())?),
                sender: i32::from_le_bytes(rest[4..8].try_into().map_err(|_| invalid())?),
                uid: u32::from_le_bytes(rest[8..].try_into().map_err(|_| invalid())?),
            }),
            [2, rest @ ..] if rest.len() == 17 && rest[16] <= 1 => {
                let thread = u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?);
                let signal = i32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?);
                let uid = u32::from_le_bytes(rest[12..16].try_into().map_err(|_| invalid())?);
                Ok(Message::Stop {
                    thread,
                    signal,
                    uid,
                    notify: rest[16] != 0,
                })
            }
            [3, rest @ ..] if rest.len() == 17 && rest[12] <= 4 => {
                let id = u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?);
                let signal = i32::from_le_bytes(rest[8..12].try_into().map_err(|_| invalid())?);
                Ok(Message::Resume {
                    id,
                    signal,
                    mode: match rest[12] {
                        0 => ResumeMode::Continue,
                        1 => ResumeMode::Step,
                        2 => ResumeMode::Detach,
                        3 => ResumeMode::Kill,
                        _ => ResumeMode::ThreadUpdate,
                    },
                    uid: u32::from_le_bytes(rest[13..17].try_into().map_err(|_| invalid())?),
                })
            }
            [4, rest @ ..] if rest.len() == 12 => {
                let id = u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?);
                let errno = i32::from_le_bytes(rest[8..].try_into().map_err(|_| invalid())?);
                Ok(Message::Reply { id, errno })
            }
            [8, rest @ ..] if rest.len() == 8 => Ok(Message::CommitUpdate {
                id: u64::from_le_bytes(rest.try_into().map_err(|_| invalid())?),
            }),
            [9, rest @ ..] if rest.len() == 24 => Ok(Message::CommitRemoteUpdate {
                id: u64::from_le_bytes(rest[..8].try_into().map_err(|_| invalid())?),
                instance: u64::from_le_bytes(rest[8..16].try_into().map_err(|_| invalid())?),
                thread: u64::from_le_bytes(rest[16..].try_into().map_err(|_| invalid())?),
            }),
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_have_fixed_little_endian_layouts() {
        let cases = [
            (Message::TraceMe, vec![1]),
            (Message::JobContinue, vec![11]),
            (
                Message::JobStop {
                    thread: 1,
                    signal: 17,
                    uid: 501,
                },
                vec![10, 1, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0xf5, 1, 0, 0],
            ),
            (
                Message::CommitUpdate { id: 1 },
                vec![8, 1, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                Message::CommitRemoteUpdate {
                    id: 1,
                    instance: 2,
                    thread: 3,
                },
                vec![
                    9, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                Message::Signal {
                    signal: 17,
                    sender: 42,
                    uid: 501,
                },
                vec![7, 17, 0, 0, 0, 42, 0, 0, 0, 0xf5, 1, 0, 0],
            ),
            (
                Message::Attach {
                    id: 1,
                    ruid: 501,
                    euid: 0,
                    sigexc: true,
                },
                vec![5, 1, 0, 0, 0, 0, 0, 0, 0, 0xf5, 1, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                Message::AttachReply {
                    id: 1,
                    errno: 16,
                    denied: true,
                    original_parent: None,
                },
                vec![6, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1],
            ),
            (
                Message::Stop {
                    thread: 0x0102_0304_0506_0708,
                    signal: 17,
                    uid: 501,
                    notify: true,
                },
                vec![2, 8, 7, 6, 5, 4, 3, 2, 1, 17, 0, 0, 0, 0xf5, 1, 0, 0, 1],
            ),
            (
                Message::Resume {
                    id: 0x0102_0304_0506_0708,
                    signal: 5,
                    mode: ResumeMode::Step,
                    uid: 501,
                },
                vec![3, 8, 7, 6, 5, 4, 3, 2, 1, 5, 0, 0, 0, 1, 0xf5, 1, 0, 0],
            ),
            (
                Message::Reply { id: 1, errno: 16 },
                vec![4, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0],
            ),
        ];
        for (message, bytes) in cases {
            assert_eq!(message.encode(), bytes);
            assert_eq!(Message::decode(&bytes).unwrap(), message);
            for length in 0..bytes.len() {
                assert_eq!(
                    Message::decode(&bytes[..length]).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert_eq!(
                Message::decode(&trailing).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn unknown_tags_and_resume_modes_are_rejected() {
        assert_eq!(
            Message::decode(&[0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut bytes = Message::Resume {
            id: 1,
            signal: 0,
            mode: ResumeMode::Continue,
            uid: 501,
        }
        .encode();
        bytes[13] = 5;
        assert_eq!(
            Message::decode(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        for (wire_mode, mode) in [
            (0, ResumeMode::Continue),
            (1, ResumeMode::Step),
            (2, ResumeMode::Detach),
            (3, ResumeMode::Kill),
            (4, ResumeMode::ThreadUpdate),
        ] {
            bytes[13] = wire_mode;
            assert_eq!(
                Message::decode(&bytes).unwrap(),
                Message::Resume {
                    id: 1,
                    signal: 0,
                    mode,
                    uid: 501,
                }
            );
        }
        let mut stop = Message::Stop {
            thread: 1,
            signal: 5,
            uid: 501,
            notify: false,
        }
        .encode();
        *stop.last_mut().unwrap() = 2;
        assert_eq!(
            Message::decode(&stop).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut attach = Message::Attach {
            id: 1,
            ruid: 501,
            euid: 501,
            sigexc: false,
        }
        .encode();
        *attach.last_mut().unwrap() = 2;
        assert_eq!(
            Message::decode(&attach).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut reply = Message::AttachReply {
            id: 1,
            errno: 16,
            denied: false,
            original_parent: None,
        }
        .encode();
        *reply.last_mut().unwrap() = 2;
        assert_eq!(
            Message::decode(&reply).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn registered_metadata_and_exit_frames_are_exact_and_reject_partial_reports() {
        let reply = Message::AttachReply {
            id: 0x0102,
            errno: 0,
            denied: false,
            original_parent: Some(0x0304),
        };
        let wire = reply.encode();
        assert_eq!(
            wire,
            vec![12, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 0, 0]
        );
        assert_eq!(Message::decode(&wire).unwrap(), reply);
        let mut negative = wire.clone();
        negative[14..].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(Message::decode(&negative).is_err());
        let exit = Message::ExitReport {
            status: 0x2a00,
            uid: 501,
            rusage: [0x31; 144],
            reparented: false,
        };
        let bytes = exit.encode();
        assert_eq!(bytes.len(), 154);
        assert_eq!(&bytes[..9], &[13, 0, 42, 0, 0, 245, 1, 0, 0]);
        assert_eq!(Message::decode(&bytes).unwrap(), exit);
        for length in 0..bytes.len() {
            assert!(Message::decode(&bytes[..length]).is_err());
        }
        let mut stopped = bytes;
        stopped[1..5].copy_from_slice(&0x117fi32.to_le_bytes());
        assert!(Message::decode(&stopped).is_err());
        let ack = Message::ReapAck { id: 9 };
        assert_eq!(Message::decode(&ack.encode()).unwrap(), ack);
        assert!(Message::decode(&[14]).is_err());
        assert!(Message::decode(&[14, 0]).is_err());
    }
    #[test]
    fn signing_metadata_requires_an_exact_current_protocol_frame() {
        for flags in [None, Some(0), Some(u32::MAX)] {
            let packet = Message::CodeFlags { epoch: 7, flags };
            let wire = packet.encode();
            assert_eq!(Message::decode(&wire).unwrap(), packet);
            for len in 0..wire.len() {
                assert!(Message::decode(&wire[..len]).is_err());
            }
        }
        let mut wire = Message::CodeFlags {
            epoch: 7,
            flags: Some(1),
        }
        .encode();
        wire[9] = 0;
        assert!(Message::decode(&wire).is_err());
        wire[9] = 2;
        assert!(Message::decode(&wire).is_err());
        wire[1..9].fill(0);
        assert!(Message::decode(&wire).is_err());
    }
}
