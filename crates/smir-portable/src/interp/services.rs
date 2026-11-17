//! The portable runtime services, as the interpreter performs them.
//!
//! A service validates its scalar arguments and guards every guest buffer
//! before the host does anything. A buffer that fails its guard stops the
//! program with the fault a load or store of the same bytes would raise. A
//! host failure is not a fault: the service returns its error number as the
//! status, and zero as the value.

use crate::Error;
use crate::ir::{Pointer, Service, Value};

use super::host::{Clock, Errno, Host};
use super::memory::Memory;
use super::{Step, internal};

/// Most bytes one read or write transfers. A longer request transfers this
/// many and reports the count.
pub(super) const STREAM_LIMIT: usize = 65536;

/// An integer argument. Undef refines to zero; poison is undefined.
fn scalar(value: Value) -> Result<Result<u64, Step>, Error> {
    match value {
        Value::Int(bits) => Ok(Ok(bits as u64)),
        Value::Undef => Ok(Ok(0)),
        Value::Poison => Ok(Err(Step::LanguageUb("ub_service_argument"))),
        _ => Err(internal("service integer argument")),
    }
}

/// A buffer argument. Undef refines to the null pointer, which has no origin.
fn buffer(value: Value) -> Result<Result<Pointer, Step>, Error> {
    match value {
        Value::DataPtr(pointer) => Ok(Ok(pointer)),
        Value::Undef => Ok(Ok(Pointer::originless(0))),
        Value::Poison => Ok(Err(Step::LanguageUb("ub_service_argument"))),
        _ => Err(internal("service buffer argument")),
    }
}

/// The `(status, value)` results of a call that failed.
fn failed(errno: Errno) -> Vec<Value> {
    vec![Value::Int(u128::from(errno.code())), Value::Int(0)]
}

/// The `(status, value)` results of a transfer.
fn transferred(outcome: Result<usize, Errno>, asked: usize) -> Result<Vec<Value>, Error> {
    match outcome {
        Ok(count) if count <= asked => Ok(vec![Value::Int(0), Value::Int(count as u128)]),
        Ok(_) => Err(internal("host transferred more than it was asked to")),
        Err(errno) => Ok(failed(errno)),
    }
}

/// Perform `service`. `Ok(Ok(results))` continues the program; `Ok(Err(step))`
/// ends this step with a fault or with the end of the program.
pub(super) fn call(
    service: Service,
    arguments: &[Value],
    memory: &mut Memory,
    host: &mut dyn Host,
) -> Result<Result<Vec<Value>, Step>, Error> {
    macro_rules! checked {
        ($operand:expr) => {
            match $operand? {
                Ok(value) => value,
                Err(step) => return Ok(Err(step)),
            }
        };
    }
    macro_rules! guarded {
        ($access:expr) => {
            match $access {
                Ok(value) => value,
                Err(fault) => return Ok(Err(fault.into())),
            }
        };
    }
    match (service, arguments) {
        (Service::FileWrite, [handle, pointer, length]) => {
            let handle = checked!(scalar(*handle));
            let pointer = checked!(buffer(*pointer));
            let length = checked!(scalar(*length));
            // A span of no bytes is not dereferenced.
            let bytes = if length == 0 {
                Vec::new()
            } else {
                guarded!(memory.read_bytes(pointer, length, STREAM_LIMIT))
            };
            transferred(host.write(handle, &bytes), bytes.len()).map(Ok)
        }
        (Service::FileRead, [handle, pointer, length]) => {
            let handle = checked!(scalar(*handle));
            let pointer = checked!(buffer(*pointer));
            let length = checked!(scalar(*length));
            if length != 0 {
                guarded!(memory.writable(pointer, length, 1));
            }
            let mut staged = vec![
                0_u8;
                usize::try_from(length)
                    .map_or(STREAM_LIMIT, |length| length.min(STREAM_LIMIT))
            ];
            let outcome = host.read(handle, &mut staged);
            if let Ok(count) = outcome
                && count != 0
            {
                let read = staged
                    .get(..count)
                    .ok_or_else(|| internal("host transferred more than it was asked to"))?;
                // The span was guarded above, so this cannot fail.
                guarded!(memory.write_bytes(pointer, read));
            }
            transferred(outcome, staged.len()).map(Ok)
        }
        (Service::ProcessExit, [status, mode]) => {
            let status = checked!(scalar(*status));
            let mode = checked!(scalar(*mode));
            // Clean, quick and immediate exit. Only a clean exit runs the
            // module's finalizers; the engine knows of no other cleanup.
            if mode > 2 {
                return Ok(Err(Step::Trap("service_argument")));
            }
            Ok(Err(Step::Exit {
                status: status as u32 as i32,
                clean: mode == 0,
            }))
        }
        (Service::ProcessAbort, []) => Ok(Err(Step::Abort)),
        (Service::ClockNow, [clock]) => {
            let clock = match checked!(scalar(*clock)) {
                0 => Clock::Monotonic,
                1 => Clock::Utc,
                2 => Clock::ProcessCpu,
                3 => Clock::ThreadCpu,
                // No such clock: a status, like any other failure to read one.
                _ => return Ok(Ok(failed(Errno::EINVAL))),
            };
            Ok(Ok(match host.now(clock) {
                Ok(nanoseconds) => vec![Value::Int(0), Value::Int(u128::from(nanoseconds))],
                Err(errno) => failed(errno),
            }))
        }
        _ => Err(internal("service arity")),
    }
}
