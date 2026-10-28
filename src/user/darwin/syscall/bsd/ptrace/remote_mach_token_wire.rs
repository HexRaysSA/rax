//! Send-once suspension capabilities have independent, one-use identities.

use std::io;

const OFFER: u8 = 0x93;
const DROP: u8 = 0x94;
const CALL: u8 = 0x95;
const RESULT: u8 = 0x96;
const DEAD: u8 = 0x97;
const SEND_CALL: u8 = 0x98;

pub(in super::super::super) fn is_tag(tag: u8) -> bool {
    (OFFER..=SEND_CALL).contains(&tag)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super::super) enum Packet {
    Offer {
        sequence: u64,
        instance: u64,
        token: u64,
    },
    Drop {
        token: u64,
    },
    Call {
        once: bool,
        sequence: u64,
        token: u64,
        id: i32,
        bits: u32,
        reply: bool,
        body: Vec<u8>,
    },
    Result {
        sequence: u64,
        result: i32,
    },
    Dead {
        token: u64,
    },
}

impl Packet {
    pub(in super::super::super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Offer {
                sequence,
                instance,
                token,
            } => {
                bytes.push(OFFER);
                for value in [sequence, instance, token] {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
            Self::Drop { token } | Self::Dead { token } => {
                bytes.push(if matches!(self, Self::Drop { .. }) {
                    DROP
                } else {
                    DEAD
                });
                bytes.extend_from_slice(&token.to_le_bytes());
            }
            Self::Call {
                once,
                sequence,
                token,
                id,
                bits,
                reply,
                body,
            } => {
                bytes.push(if *once { CALL } else { SEND_CALL });
                bytes.extend_from_slice(&sequence.to_le_bytes());
                bytes.extend_from_slice(&token.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&bits.to_le_bytes());
                bytes.push(u8::from(*reply));
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
                bytes.extend_from_slice(body);
            }
            Self::Result { sequence, result } => {
                bytes.push(RESULT);
                bytes.extend_from_slice(&sequence.to_le_bytes());
                bytes.extend_from_slice(&result.to_le_bytes());
            }
        }
        bytes
    }

    pub(in super::super::super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let bad = || io::Error::from(io::ErrorKind::InvalidData);
        let word = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let int = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        Ok(match bytes.first().copied() {
            Some(OFFER) if bytes.len() == 25 && word(9) != 0 && word(17) != 0 => Self::Offer {
                sequence: word(1),
                instance: word(9),
                token: word(17),
            },
            Some(tag @ (DROP | DEAD)) if bytes.len() == 9 && word(1) != 0 => {
                if tag == DROP {
                    Self::Drop { token: word(1) }
                } else {
                    Self::Dead { token: word(1) }
                }
            }
            Some(RESULT) if bytes.len() == 13 => Self::Result {
                sequence: word(1),
                result: int(9) as i32,
            },
            Some(tag @ (CALL | SEND_CALL))
                if bytes.len() >= 30
                    && bytes.len() <= super::super::MAX_FRAME
                    && word(9) != 0
                    && bytes[25] <= 1
                    && int(26) as usize == bytes.len() - 30 =>
            {
                Self::Call {
                    once: tag == CALL,
                    sequence: word(1),
                    token: word(9),
                    id: int(17) as i32,
                    bits: int(21),
                    reply: bytes[25] != 0,
                    body: bytes[30..].to_vec(),
                }
            }
            _ => return Err(bad()),
        })
    }
}
