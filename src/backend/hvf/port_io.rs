//! Scalar port-I/O qualification, data transfer and deferred completion errors.
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Direction {
    In,
    Out,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ScalarIo {
    pub(crate) port: u16,
    pub(crate) size: u8,
    pub(crate) direction: Direction,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    InvalidSize,
    StringOrRep,
}

/// Undefined qualification bits are ignored. Unsupported forms are explicit;
/// INS/OUTS never become a scalar RAX access.
pub(crate) fn decode(qualification: u64) -> Result<ScalarIo, DecodeError> {
    let size = match qualification & 7 {
        0 => 1,
        1 => 2,
        3 => 4,
        _ => return Err(DecodeError::InvalidSize),
    };
    if qualification & 0x30 != 0 {
        return Err(DecodeError::StringOrRep);
    }
    Ok(ScalarIo {
        port: (qualification >> 16) as u16,
        size,
        direction: if qualification & 8 == 0 {
            Direction::Out
        } else {
            Direction::In
        },
    })
}

pub(crate) fn output_bytes(rax: u64, size: u8) -> Option<Vec<u8>> {
    if !matches!(size, 1 | 2 | 4) {
        return None;
    }
    Some(rax.to_le_bytes()[..usize::from(size)].to_vec())
}

/// IN AL/AX preserves upper RAX; IN EAX zero-extends the32-bit result.
pub(crate) fn input_value(rax: u64, size: u8, data: &[u8]) -> Option<u64> {
    if data.len() != usize::from(size) {
        return None;
    }
    match size {
        1 => Some((rax & !0xff) | u64::from(data[0])),
        2 => Some((rax & !0xffff) | u64::from(u16::from_le_bytes(data.try_into().ok()?))),
        4 => Some(u64::from(u32::from_le_bytes(data.try_into().ok()?))),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct PendingInput {
    pub(crate) io: ScalarIo,
    pub(crate) original_rax: u64,
    pub(crate) length: u64,
}

pub(crate) trait CompletionAccess {
    type Error: Display;
    fn write_rax(&mut self, value: u64) -> Result<(), Self::Error>;
    fn advance_instruction(&mut self, length: u64) -> Result<(), Self::Error>;
}

/// `VCpu::complete_io_in` has no error return. Retain a terminal error so every
/// subsequent run reports it before executing another guest instruction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct InputState {
    pending: Option<PendingInput>,
    failure: Option<String>,
    reply: Option<Vec<u8>>,
}
impl InputState {
    pub(crate) fn hold_failure(&mut self, data: &[u8], failure: String) {
        if self.failure.is_some() {
            return;
        }
        if self
            .pending
            .is_some_and(|pending| data.len() == usize::from(pending.io.size))
        {
            self.reply = Some(data.to_vec());
        }
        self.failure = Some(failure);
    }
    pub(crate) fn descriptor(&self) -> Option<PendingInput> {
        self.pending
    }
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    pub(crate) fn validate_checkpoint(&self) -> Result<(), String> {
        if self
            .failure
            .as_ref()
            .is_some_and(|error| error.len() > 16 * 1024)
        {
            return Err("HVF input error exceeds record limit".into());
        }
        if let Some(pending) = self.pending {
            Self::default().begin(pending).map_err(str::to_owned)?;
        }
        if let Some(reply) = &self.reply {
            let pending = self.pending.ok_or("input reply has no pending request")?;
            if reply.len() != usize::from(pending.io.size) || self.failure.is_none() {
                return Err("invalid retained input reply".into());
            }
        }
        Ok(())
    }
    pub(crate) fn begin(&mut self, pending: PendingInput) -> Result<(), &'static str> {
        if self.pending.is_some() || self.failure.is_some() {
            return Err("HVF input completion is already pending or failed");
        }
        if pending.io.direction != Direction::In
            || !matches!(pending.io.size, 1 | 2 | 4)
            || !(1..=15).contains(&pending.length)
        {
            return Err("invalid HVF scalar input completion");
        }
        self.pending = Some(pending);
        Ok(())
    }
    pub(crate) fn ready(&self) -> Result<(), &str> {
        if let Some(error) = self.failure.as_deref() {
            return Err(error);
        }
        if self.pending.is_some() {
            return Err("HVF input completion is pending");
        }
        Ok(())
    }
    pub(crate) fn complete<T: CompletionAccess>(&mut self, host: &mut T, data: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let Some(pending) = self.pending else {
            self.failure = Some("unexpected HVF input completion without a pending request".into());
            return;
        };
        let Some(value) = input_value(pending.original_rax, pending.io.size, data) else {
            self.failure = Some(format!(
                "HVF input port {:#x}: expected {} bytes, received {}",
                pending.io.port,
                pending.io.size,
                data.len()
            ));
            return;
        };
        self.reply = Some(data.to_vec());
        let result = host
            .write_rax(value)
            .and_then(|()| host.advance_instruction(pending.length));
        if let Err(error) = result {
            self.failure = Some(format!(
                "HVF input port {:#x} completion failed: {error}",
                pending.io.port
            ));
            return;
        }
        self.pending = None;
        self.reply = None;
    }
}
