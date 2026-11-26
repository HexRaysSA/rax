//! Synchronous Win32 one-time initialization and guest callback ownership.

use crate::error::MemoryAccessKind;
use crate::user::windows::{
    hle::{ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow},
    memory::MemFault,
    nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_POSSIBLE_DEADLOCK},
    sync::{OnceCallback, Wait},
};

pub(in crate::user::windows::dll) static ONCE_EXPORTS: &[Export] = &[
    Export::func(
        "InitOnceExecuteOnce",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr],
        execute,
    ),
    Export::func("InitOnceInitialize", Stdcall, &[Ptr], reset),
];

const DONE: u64 = 2;

fn reset(c: &mut Ctx) -> ApiResult {
    let address = c.ptr(0)?;
    if c.p.sync.once_owner(address).is_some() {
        return Err(c.unsupported("reinitializing an active INIT_ONCE"));
    }
    c.write_ptr(address, 0)?;
    Flow::void()
}

fn execute(c: &mut Ctx) -> ApiResult {
    let (address, callback, parameter, output) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?);
    initialize(c, address, callback, parameter, output)
}

fn initialize(c: &mut Ctx, address: u64, callback: u64, parameter: u64, output: u64) -> ApiResult {
    if address == 0 || address % c.psize() != 0 || callback == 0 || output == address {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let state = c.read_ptr(address)?;
    if state & 3 == DONE {
        if output != 0 {
            c.write_ptr(output, state & !3)?;
        }
        return Flow::bool(true);
    }
    if state != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if let Some(owner) = c.p.sync.once_owner(address) {
        if owner == c.t.tid {
            return c.fail(ERROR_POSSIBLE_DEADLOCK, 0);
        }
        return Flow::block(Wait::InitOnce { addr: address }, move |c, _| {
            initialize(c, address, callback, parameter, output)
        });
    }
    probe(c, address)?;
    if output != 0 {
        probe(c, output)?;
    }
    // The dispatcher's cursor is above the outgoing callback frame and below
    // the API's entry stack pointer. Use that reserved space for *Context.
    let scratch = c.cursor;
    c.write_ptr(scratch, 0)?;
    let Some(owner) = c.p.sync.begin_once(address, c.t.tid) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    Flow::call_checked(
        callback,
        vec![address, parameter, scratch],
        move |c, value| {
            if value as u32 == 0 {
                drop(owner);
                return Flow::bool(false);
            }
            let context = c.read_ptr(scratch)?;
            publish(c, address, output, context, owner)
        },
    )
}

fn publish(c: &mut Ctx, address: u64, output: u64, context: u64, owner: OnceCallback) -> ApiResult {
    if context & 3 != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if let Err(fault) = probe(c, address).and_then(|()| {
        if output == 0 {
            Ok(())
        } else {
            probe(c, output)
        }
    }) {
        return Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| publish(c, address, output, context, owner)),
        });
    }
    c.write_ptr(address, context | DONE)?;
    if output != 0 {
        c.write_ptr(output, context)?;
    }
    drop(owner);
    Flow::bool(true)
}

fn probe(c: &Ctx, ptr: u64) -> Result<(), MemFault> {
    c.mem()
        .probe(ptr, c.psize() as usize, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}
