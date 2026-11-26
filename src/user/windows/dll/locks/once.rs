//! Synchronous one-time initialization and guest callback ownership.

use crate::error::MemoryAccessKind;
use crate::user::windows::{
    hle::{ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow},
    memory::MemFault,
    nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_POSSIBLE_DEADLOCK},
    nt::status::{STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
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

pub(in crate::user::windows::dll) static NTDLL_ONCE_EXPORTS: &[Export] = &[Export::func(
    "RtlRunOnceExecuteOnce",
    Stdcall,
    &[Ptr, Ptr, Ptr, Ptr],
    rtl_execute,
)];

const DONE: u64 = 2;

#[derive(Clone, Copy)]
enum OnceApi {
    Win32,
    Rtl,
}

impl OnceApi {
    fn success(self) -> ApiResult {
        match self {
            Self::Win32 => Flow::bool(true),
            Self::Rtl => Flow::ret(STATUS_SUCCESS.into()),
        }
    }

    fn error(self, c: &mut Ctx, error: u32, status: u32) -> ApiResult {
        match self {
            Self::Win32 => c.fail(error, 0),
            Self::Rtl => Flow::ret(status.into()),
        }
    }
}

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
    initialize(c, OnceApi::Win32, address, callback, parameter, output)
}

fn rtl_execute(c: &mut Ctx) -> ApiResult {
    let (address, callback, parameter, output) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?);
    initialize(c, OnceApi::Rtl, address, callback, parameter, output)
}

fn initialize(
    c: &mut Ctx,
    api: OnceApi,
    address: u64,
    callback: u64,
    parameter: u64,
    output: u64,
) -> ApiResult {
    if address == 0 || address % c.psize() != 0 || callback == 0 || output == address {
        return api.error(c, ERROR_INVALID_PARAMETER, STATUS_INVALID_PARAMETER);
    }
    let state = c.read_ptr(address)?;
    if state & 3 == DONE {
        if output != 0 {
            c.write_ptr(output, state & !3)?;
        }
        return api.success();
    }
    if state != 0 {
        return api.error(c, ERROR_INVALID_PARAMETER, STATUS_INVALID_PARAMETER);
    }
    if let Some(owner) = c.p.sync.once_owner(address) {
        if owner == c.t.tid {
            return api.error(c, ERROR_POSSIBLE_DEADLOCK, STATUS_UNSUCCESSFUL);
        }
        return Flow::block(Wait::InitOnce { addr: address }, move |c, _| {
            initialize(c, api, address, callback, parameter, output)
        });
    }
    probe(c, address)?;
    let publish_output = if matches!(api, OnceApi::Win32) {
        output
    } else {
        // The native callback receives the caller's pointer and owns that
        // store. The runtime only reads it when initialization succeeds.
        0
    };
    if publish_output != 0 {
        probe(c, output)?;
    }
    let callback_output = match api {
        OnceApi::Win32 => {
            // The dispatcher's cursor is above the outgoing callback frame
            // and below the API's entry stack pointer.
            c.write_ptr(c.cursor, 0)?;
            c.cursor
        }
        OnceApi::Rtl => output,
    };
    let Some(owner) = c.p.sync.begin_once(address, c.t.tid) else {
        return api.error(c, ERROR_NOT_ENOUGH_MEMORY, STATUS_NO_MEMORY);
    };
    Flow::call_checked(
        callback,
        vec![address, parameter, callback_output],
        move |c, value| {
            if value as u32 == 0 {
                drop(owner);
                return match api {
                    OnceApi::Win32 => Flow::bool(false),
                    OnceApi::Rtl => Flow::ret(STATUS_UNSUCCESSFUL.into()),
                };
            }
            let context = if callback_output == 0 {
                0
            } else {
                c.read_ptr(callback_output)?
            };
            publish(c, api, address, publish_output, context, owner)
        },
    )
}

fn publish(
    c: &mut Ctx,
    api: OnceApi,
    address: u64,
    output: u64,
    context: u64,
    owner: OnceCallback,
) -> ApiResult {
    if context & 3 != 0 {
        return api.error(c, ERROR_INVALID_PARAMETER, STATUS_INVALID_PARAMETER);
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
            retry: Box::new(move |c, _| publish(c, api, address, output, context, owner)),
        });
    }
    c.write_ptr(address, context | DONE)?;
    if output != 0 {
        c.write_ptr(output, context)?;
    }
    drop(owner);
    api.success()
}

fn probe(c: &Ctx, ptr: u64) -> Result<(), MemFault> {
    c.mem()
        .probe(ptr, c.psize() as usize, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}
