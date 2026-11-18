//! The portable runtime services, as the interpreter performs them.
//!
//! A service validates its scalar arguments and guards every guest buffer
//! before the host does anything. A buffer that fails its guard stops the
//! program with the fault a load or store of the same bytes would raise. A
//! host failure is not a fault: the service returns its error number as the
//! status, and zero as the value.

use crate::Error;
use crate::ir::{Pointer, Service, Value};

use super::exec::{Step, internal};
use super::files;
use super::host::{Clock, Errno};
use super::process::{Context, locked};
use super::threads;

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

/// The `(status, pointer)` results of a call that failed.
fn failed_pointer(errno: Errno) -> Vec<Value> {
    vec![
        Value::Int(u128::from(errno.code())),
        Value::DataPtr(Pointer::originless(0)),
    ]
}

/// The `(status, value)` results of a transfer.
fn transferred(outcome: Result<usize, Errno>, asked: usize) -> Result<Vec<Value>, Error> {
    match outcome {
        Ok(count) if count <= asked => Ok(vec![Value::Int(0), Value::Int(count as u128)]),
        Ok(_) => Err(internal("host transferred more than it was asked to")),
        Err(errno) => Ok(failed(errno)),
    }
}

/// Perform `service` for the thread of `context`. `Ok(Ok(results))` continues
/// the program; `Ok(Err(step))` ends this step with a fault, or with the end
/// of the thread or of the program.
///
/// The host is asked for one effect at a time: a thread that waits for input
/// keeps the others from the host until it has it.
pub(super) fn call(
    service: Service,
    arguments: &[Value],
    context: &Context,
) -> Result<Result<Vec<Value>, Step>, Error> {
    let memory = &context.process.memory;
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
            let outcome = locked(&context.process.host).write(handle, &bytes);
            transferred(outcome, bytes.len()).map(Ok)
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
            let outcome = locked(&context.process.host).read(handle, &mut staged);
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
            let reading = locked(&context.process.host).now(clock);
            Ok(Ok(match reading {
                Ok(nanoseconds) => vec![Value::Int(0), Value::Int(u128::from(nanoseconds))],
                Err(errno) => failed(errno),
            }))
        }
        (Service::ThreadSpawn, [entry, argument, stack_bytes]) => {
            if matches!(entry, Value::Poison) {
                return Ok(Err(Step::LanguageUb("ub_service_argument")));
            }
            // The argument is the thread's to interpret; it is passed on as
            // it is, like the argument of a call.
            checked!(scalar(*stack_bytes));
            threads::spawn(context, *entry, *argument)
        }
        (Service::ThreadJoin, [thread]) => threads::join(context, checked!(scalar(*thread))),
        (Service::ThreadDetach, [thread]) => threads::detach(context, checked!(scalar(*thread))),
        (Service::ThreadYield, []) => threads::yield_now(),
        (Service::ThreadId, []) => threads::id(context),
        (Service::ThreadConcurrency, []) => threads::concurrency(context),
        (Service::ThreadExit, [result]) => Ok(Err(Step::ThreadExit(checked!(scalar(*result))))),
        (Service::SyncWait32, [address, expected, timeout]) => {
            let address = checked!(buffer(*address));
            let expected = checked!(scalar(*expected));
            let timeout = checked!(scalar(*timeout));
            threads::wait(context, address, expected as u32, timeout)
        }
        (Service::SyncWake32, [address, count]) => {
            let address = checked!(buffer(*address));
            let count = checked!(scalar(*count));
            threads::wake(context, address, count as u32)
        }
        (Service::MemoryMap, [bytes, alignment, permissions]) => {
            let bytes = checked!(scalar(*bytes));
            let alignment = checked!(scalar(*alignment));
            let permissions = checked!(scalar(*permissions));
            // Nothing to map, no such alignment, or a permission beyond
            // reading and writing: a status, like a refusal for lack of room.
            if bytes == 0 || !alignment.is_power_of_two() || permissions > 3 {
                return Ok(Ok(failed_pointer(Errno::EINVAL)));
            }
            Ok(Ok(
                match memory.map(bytes, alignment, permissions & 1 != 0, permissions & 2 != 0) {
                    Ok(base) => vec![Value::Int(0), Value::DataPtr(base)],
                    Err(_) => failed_pointer(Errno::ENOMEM),
                },
            ))
        }
        (Service::MemoryUnmap, [address, bytes]) => {
            let address = checked!(buffer(*address));
            let bytes = checked!(scalar(*bytes));
            // Only a whole mapping is unmapped.
            Ok(Ok(if memory.unmap(address, bytes) {
                vec![Value::Int(0), Value::Int(0)]
            } else {
                failed(Errno::EINVAL)
            }))
        }
        (Service::MemoryProtect, [address, bytes, permissions]) => {
            let address = checked!(buffer(*address));
            let bytes = checked!(scalar(*bytes));
            let permissions = checked!(scalar(*permissions));
            Ok(Ok(
                if permissions <= 3
                    && memory.protect(address, bytes, permissions & 1 != 0, permissions & 2 != 0)
                {
                    vec![Value::Int(0), Value::Int(0)]
                } else {
                    failed(Errno::EINVAL)
                },
            ))
        }
        (Service::FileOpen, [path, length, flags, mode]) => {
            let path = checked!(buffer(*path));
            let length = checked!(scalar(*length));
            let flags = checked!(scalar(*flags));
            let mode = checked!(scalar(*mode));
            Ok(Ok(guarded!(files::open(
                context, path, length, flags, mode
            ))))
        }
        (Service::FileClose, [handle]) => Ok(Ok(files::close(context, checked!(scalar(*handle))))),
        (Service::FileSeek, [handle, offset, whence]) => {
            let handle = checked!(scalar(*handle));
            let offset = checked!(scalar(*offset));
            let whence = checked!(scalar(*whence));
            Ok(Ok(files::seek(context, handle, offset, whence)))
        }
        (Service::FileUnlink, [path, length]) => {
            let path = checked!(buffer(*path));
            let length = checked!(scalar(*length));
            Ok(Ok(guarded!(files::unlink(context, path, length))))
        }
        (Service::FileRename, [source, source_length, destination, destination_length]) => {
            let source = (checked!(buffer(*source)), checked!(scalar(*source_length)));
            let destination = (
                checked!(buffer(*destination)),
                checked!(scalar(*destination_length)),
            );
            Ok(Ok(guarded!(files::rename(context, source, destination))))
        }
        _ => Err(internal("service arity")),
    }
}
