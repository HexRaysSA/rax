//! Stable deferred-exit representation, independent of host/debug build flags.
use crate::devices::bus::{MmioRmwOp, MmioShift};
use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct RmwContext {
    kind: u8,
    a: u64,
    b: u64,
    carry: bool,
}
impl RmwContext {
    fn capture(op: MmioRmwOp) -> Self {
        let (kind, a, b, carry) = match op {
            MmioRmwOp::Exchange(a) => (0, a, 0, false),
            MmioRmwOp::CompareExchange {
                expected,
                replacement,
            } => (1, expected, replacement, false),
            MmioRmwOp::Add { value, carry } => (2, value, 0, carry),
            MmioRmwOp::Subtract { value, borrow } => (3, value, 0, borrow),
            MmioRmwOp::And(a) => (4, a, 0, false),
            MmioRmwOp::Or(a) => (5, a, 0, false),
            MmioRmwOp::Xor(a) => (6, a, 0, false),
            MmioRmwOp::Not => (7, 0, 0, false),
            MmioRmwOp::Negate => (8, 0, 0, false),
            MmioRmwOp::BitSet(a) => (9, a.into(), 0, false),
            MmioRmwOp::BitReset(a) => (10, a.into(), 0, false),
            MmioRmwOp::BitComplement(a) => (11, a.into(), 0, false),
            MmioRmwOp::Shift { kind, count, carry } => {
                let kind = match kind {
                    MmioShift::RotateLeft => 12,
                    MmioShift::RotateRight => 13,
                    MmioShift::RotateCarryLeft => 14,
                    MmioShift::RotateCarryRight => 15,
                    MmioShift::Left => 16,
                    MmioShift::LogicalRight => 17,
                    MmioShift::ArithmeticRight => 18,
                };
                (kind, count.into(), 0, carry)
            }
        };
        Self { kind, a, b, carry }
    }
    fn into_op(self, size: u8) -> Result<MmioRmwOp> {
        let invalid = || Error::Emulator("x86 context: invalid deferred RMW descriptor".into());
        if (self.kind != 1 && self.b != 0)
            || (!matches!(self.kind, 2 | 3 | 14 | 15) && self.carry)
            || (matches!(self.kind, 7 | 8) && self.a != 0)
        {
            return Err(invalid());
        }
        let op = match self.kind {
            0 => MmioRmwOp::Exchange(self.a),
            1 => MmioRmwOp::CompareExchange {
                expected: self.a,
                replacement: self.b,
            },
            2 => MmioRmwOp::Add {
                value: self.a,
                carry: self.carry,
            },
            3 => MmioRmwOp::Subtract {
                value: self.a,
                borrow: self.carry,
            },
            4 => MmioRmwOp::And(self.a),
            5 => MmioRmwOp::Or(self.a),
            6 => MmioRmwOp::Xor(self.a),
            7 => MmioRmwOp::Not,
            8 => MmioRmwOp::Negate,
            9 => MmioRmwOp::BitSet(self.a.try_into().map_err(|_| invalid())?),
            10 => MmioRmwOp::BitReset(self.a.try_into().map_err(|_| invalid())?),
            11 => MmioRmwOp::BitComplement(self.a.try_into().map_err(|_| invalid())?),
            12..=18 => {
                let kind = match self.kind {
                    12 => MmioShift::RotateLeft,
                    13 => MmioShift::RotateRight,
                    14 => MmioShift::RotateCarryLeft,
                    15 => MmioShift::RotateCarryRight,
                    16 => MmioShift::Left,
                    17 => MmioShift::LogicalRight,
                    _ => MmioShift::ArithmeticRight,
                };
                MmioRmwOp::Shift {
                    kind,
                    count: self.a.try_into().map_err(|_| invalid())?,
                    carry: self.carry,
                }
            }
            _ => return Err(invalid()),
        };
        op.validate(size)?;
        Ok(op)
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
pub(super) enum ExitContext {
    Hlt,
    IoIn {
        port: u16,
        size: u8,
    },
    IoInString {
        port: u16,
        size: u8,
        count: u32,
    },
    IoOut {
        port: u16,
        data: Vec<u8>,
    },
    MmioRead {
        addr: u64,
        size: u8,
    },
    MmioWrite {
        addr: u64,
        data: Vec<u8>,
    },
    MmioRmw {
        addr: u64,
        size: u8,
        operation: RmwContext,
    },
    Shutdown,
    SystemEvent {
        type_: u32,
        flags: u64,
    },
    FailEntry {
        reason: u64,
    },
    InternalError,
    Debug,
    Exception(u8),
    SystemCall,
    GdbBreakpoint {
        addr: u64,
    },
    GdbStep,
    Unknown(String),
}
impl ExitContext {
    pub(super) fn capture(exit: &VcpuExit) -> Self {
        match exit {
            VcpuExit::Hlt => Self::Hlt,
            VcpuExit::IoIn { port, size } => Self::IoIn {
                port: *port,
                size: *size,
            },
            VcpuExit::IoInString { port, size, count } => Self::IoInString {
                port: *port,
                size: *size,
                count: *count,
            },
            VcpuExit::IoOut { port, data } => Self::IoOut {
                port: *port,
                data: data.clone(),
            },
            VcpuExit::MmioRead { addr, size } => Self::MmioRead {
                addr: *addr,
                size: *size,
            },
            VcpuExit::MmioWrite { addr, data } => Self::MmioWrite {
                addr: *addr,
                data: data.clone(),
            },
            VcpuExit::MmioRmw {
                addr,
                size,
                operation,
            } => Self::MmioRmw {
                addr: *addr,
                size: *size,
                operation: RmwContext::capture(*operation),
            },
            VcpuExit::Shutdown => Self::Shutdown,
            VcpuExit::SystemEvent { type_, flags } => Self::SystemEvent {
                type_: *type_,
                flags: *flags,
            },
            VcpuExit::FailEntry { reason } => Self::FailEntry { reason: *reason },
            VcpuExit::InternalError => Self::InternalError,
            VcpuExit::Debug => Self::Debug,
            VcpuExit::Exception(vector) => Self::Exception(*vector),
            VcpuExit::SystemCall => Self::SystemCall,
            #[cfg(feature = "debug")]
            VcpuExit::GdbBreakpoint { addr } => Self::GdbBreakpoint { addr: *addr },
            #[cfg(feature = "debug")]
            VcpuExit::GdbStep => Self::GdbStep,
            VcpuExit::Unknown(message) => Self::Unknown(message.clone()),
        }
    }
    pub(super) fn into_exit(self) -> Result<VcpuExit> {
        Ok(match self {
            Self::Hlt => VcpuExit::Hlt,
            Self::IoIn { port, size } => {
                validate_io(size, 1)?;
                VcpuExit::IoIn { port, size }
            }
            Self::IoInString { port, size, count } => {
                validate_io(size, count)?;
                VcpuExit::IoInString { port, size, count }
            }
            Self::IoOut { port, data } => VcpuExit::IoOut { port, data },
            Self::MmioRead { addr, size } => VcpuExit::MmioRead { addr, size },
            Self::MmioWrite { addr, data } => VcpuExit::MmioWrite { addr, data },
            Self::MmioRmw {
                addr,
                size,
                operation,
            } => VcpuExit::MmioRmw {
                addr,
                size,
                operation: operation.into_op(size)?,
            },
            Self::Shutdown => VcpuExit::Shutdown,
            Self::SystemEvent { type_, flags } => VcpuExit::SystemEvent { type_, flags },
            Self::FailEntry { reason } => VcpuExit::FailEntry { reason },
            Self::InternalError => VcpuExit::InternalError,
            Self::Debug => VcpuExit::Debug,
            Self::Exception(vector) => VcpuExit::Exception(vector),
            Self::SystemCall => VcpuExit::SystemCall,
            Self::GdbBreakpoint { addr } => {
                #[cfg(feature = "debug")]
                {
                    VcpuExit::GdbBreakpoint { addr }
                }
                #[cfg(not(feature = "debug"))]
                {
                    let _ = addr;
                    return Err(Error::Emulator(
                        "x86 context requires debugger support".into(),
                    ));
                }
            }
            Self::GdbStep => {
                #[cfg(feature = "debug")]
                {
                    VcpuExit::GdbStep
                }
                #[cfg(not(feature = "debug"))]
                {
                    return Err(Error::Emulator(
                        "x86 context requires debugger support".into(),
                    ));
                }
            }
            Self::Unknown(message) => VcpuExit::Unknown(message),
        })
    }
}

pub(super) fn validate_io(size: u8, count: u32) -> Result<()> {
    if !matches!(size, 1 | 2 | 4) || count == 0 {
        return Err(Error::Emulator(
            "x86 context: invalid pending input width/count".into(),
        ));
    }
    Ok(())
}
