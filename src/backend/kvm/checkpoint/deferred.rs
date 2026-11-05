//! Owned non-I/O results waiting for delivery after native completion.
use super::bounded;
use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;
use serde::{Deserialize, Deserializer, Serialize};

const MAX_DIAGNOSTIC_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::backend::kvm) enum Image {
    Hlt,
    Shutdown,
    SystemEvent { type_: u32, flags: u64 },
    FailEntry { reason: u64 },
    InternalError,
    Unknown(#[serde(deserialize_with = "diagnostic_bytes")] Vec<u8>),
}

fn diagnostic_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    bounded::sequence::<_, _, MAX_DIAGNOSTIC_BYTES>(deserializer)
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("native deferred result: {message}"))
}

impl Image {
    /// Only settled direct exits have no kernel buffer or device effect left
    /// to complete. Never turn an outstanding I/O request into a replayable exit.
    pub(in crate::backend::kvm) fn capture(exit: Option<&VcpuExit>) -> Result<Option<Self>> {
        let image = match exit {
            None => return Ok(None),
            Some(VcpuExit::Hlt) => Self::Hlt,
            Some(VcpuExit::Shutdown) => Self::Shutdown,
            Some(VcpuExit::SystemEvent { type_, flags }) => Self::SystemEvent {
                type_: *type_,
                flags: *flags,
            },
            Some(VcpuExit::FailEntry { reason }) => Self::FailEntry { reason: *reason },
            Some(VcpuExit::InternalError) => Self::InternalError,
            Some(VcpuExit::Unknown(detail)) => {
                if detail.len() > MAX_DIAGNOSTIC_BYTES {
                    return Err(invalid("diagnostic exceeds its byte bound"));
                }
                Self::Unknown(detail.as_bytes().to_vec())
            }
            Some(_) => return Err(invalid("result is not a settled native direct exit")),
        };
        Ok(Some(image))
    }

    pub(in crate::backend::kvm) fn validate(&self) -> Result<()> {
        if let Self::Unknown(bytes) = self {
            if bytes.len() > MAX_DIAGNOSTIC_BYTES {
                return Err(invalid("diagnostic exceeds its byte bound"));
            }
            std::str::from_utf8(bytes).map_err(|_| invalid("diagnostic is not UTF-8"))?;
        }
        Ok(())
    }

    pub(in crate::backend::kvm) fn restore(&self) -> Result<VcpuExit> {
        self.validate()?;
        Ok(match self {
            Self::Hlt => VcpuExit::Hlt,
            Self::Shutdown => VcpuExit::Shutdown,
            Self::SystemEvent { type_, flags } => VcpuExit::SystemEvent {
                type_: *type_,
                flags: *flags,
            },
            Self::FailEntry { reason } => VcpuExit::FailEntry { reason: *reason },
            Self::InternalError => VcpuExit::InternalError,
            Self::Unknown(bytes) => VcpuExit::Unknown(
                String::from_utf8(bytes.clone()).map_err(|_| invalid("diagnostic is not UTF-8"))?,
            ),
        })
    }
}

#[cfg(test)]
#[path = "deferred_tests.rs"]
mod tests;
