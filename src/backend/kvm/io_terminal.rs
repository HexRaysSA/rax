//! Terminal-only native I/O ownership; no run mapping or device replay token.
use super::{Input, Output, Pending, State, port_bytes};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

const MAX_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::backend::kvm) struct Image {
    version: u16,
    kind: u8,
    port: u16,
    address: u64,
    size: u8,
    count: u32,
    #[serde(deserialize_with = "payload")]
    data: Vec<u8>,
    acknowledged: u32,
    replied: bool,
}

fn payload<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_BYTES} terminal native I/O bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<u8>, A::Error> {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX_BYTES {
                return Err(A::Error::custom(
                    "terminal native I/O payload exceeds bound",
                ));
            }
            let mut bytes = Vec::with_capacity(hint);
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_BYTES {
                    return Err(A::Error::custom(
                        "terminal native I/O payload exceeds bound",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Bytes)
}

fn invalid(message: &str) -> String {
    format!("terminal native I/O record: {message}")
}

impl Image {
    pub(in crate::backend::kvm) fn restore(&self) -> Result<State, String> {
        if self.version != 1 || self.kind > 3 {
            return Err(invalid("unsupported version or transfer kind"));
        }
        let mmio = self.kind & 1 != 0;
        let output = self.kind >= 2;
        let expected = if mmio {
            if self.port != 0 || self.count != 1 || !(1..=8).contains(&self.size) {
                return Err(invalid("noncanonical MMIO metadata"));
            }
            usize::from(self.size)
        } else {
            if self.address != 0 {
                return Err(invalid("port request has a memory address"));
            }
            port_bytes(self.size, self.count)?
        };
        if expected > MAX_BYTES || self.data.len() > MAX_BYTES {
            return Err(invalid("transfer exceeds its byte bound"));
        }
        let mut state = State::default();
        if output {
            let acknowledged = self.acknowledged as usize;
            if self.replied
                || self.data.len() != expected
                || acknowledged > expected
                || acknowledged % usize::from(self.size) != 0
            {
                return Err(invalid("invalid output payload or acknowledged prefix"));
            }
            let request = if mmio {
                Output::Mmio {
                    address: self.address,
                    bytes: self.data.clone(),
                }
            } else {
                Output::Port {
                    port: self.port,
                    size: self.size,
                    count: self.count,
                    bytes: self.data.clone(),
                }
            };
            state.begin_output(request, expected)?;
            let Some(Pending::Output {
                acknowledged: progress,
                ..
            }) = &mut state.pending
            else {
                return Err(invalid("output construction lost its request"));
            };
            *progress = acknowledged;
        } else {
            if self.acknowledged != 0
                || self.replied && self.data.len() != expected
                || !self.replied && !self.data.is_empty()
            {
                return Err(invalid("invalid input reply metadata"));
            }
            let request = if mmio {
                Input::Mmio {
                    address: self.address,
                    size: self.size,
                }
            } else {
                Input::Port {
                    port: self.port,
                    size: self.size,
                    count: self.count,
                }
            };
            state.begin_input(request, expected)?;
            if self.replied {
                state.complete_input(&self.data);
                state.healthy()?;
            }
        }
        Ok(state)
    }
}

impl State {
    /// The caller retains a permanent VM-wide power-off fence. Restoring this
    /// record alone cannot recreate a kernel completion or its mapped input.
    pub(in crate::backend::kvm) fn capture_terminal(&self) -> Result<Option<Image>, String> {
        self.healthy()?;
        let Some(pending) = &self.pending else {
            return Ok(None);
        };
        let mut image = Image {
            version: 1,
            kind: 0,
            port: 0,
            address: 0,
            size: 0,
            count: 1,
            data: Vec::new(),
            acknowledged: 0,
            replied: false,
        };
        match pending {
            Pending::Input { request, reply } => {
                match request {
                    Input::Port { port, size, count } => {
                        image.port = *port;
                        image.size = *size;
                        image.count = *count;
                    }
                    Input::Mmio { address, size } => {
                        image.kind = 1;
                        image.address = *address;
                        image.size = *size;
                    }
                }
                image.replied = reply.is_some();
                if let Some(reply) = reply {
                    if reply.len() > MAX_BYTES {
                        return Err(invalid("input reply exceeds bound"));
                    }
                    image.data = reply.clone();
                }
            }
            Pending::Output {
                request,
                acknowledged,
            } => {
                image.kind = 2;
                match request {
                    Output::Port {
                        port, size, count, ..
                    } => {
                        image.port = *port;
                        image.size = *size;
                        image.count = *count;
                    }
                    Output::Mmio { address, bytes } => {
                        image.kind = 3;
                        image.address = *address;
                        image.size =
                            u8::try_from(bytes.len()).map_err(|_| invalid("invalid MMIO width"))?;
                    }
                }
                if request.bytes().len() > MAX_BYTES {
                    return Err(invalid("output payload exceeds bound"));
                }
                image.data = request.bytes().to_vec();
                image.acknowledged = u32::try_from(*acknowledged)
                    .map_err(|_| invalid("output prefix exceeds u32"))?;
            }
        }
        image.restore()?;
        Ok(Some(image))
    }
}

#[cfg(test)]
#[path = "io_terminal_tests.rs"]
mod tests;
