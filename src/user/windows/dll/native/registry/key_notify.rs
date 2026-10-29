//! Native notification admission over immutable guest registry snapshots.
use super::*;
use crate::user::windows::objects::RegistryCompletion;
use crate::user::windows::sync::Wait;

const THREAD_AGNOSTIC: u32 = 0x1000_0000;

pub(in super::super) fn notify_key(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match result {
        Ok(flow) => Ok(flow),
        Err(error) => finish(c, Err(error)),
    }
}

fn checked(c: &mut Ctx) -> Checked<Flow> {
    let (handle, event, apc, context, io, filter, _tree, buffer, length, asynchronous) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.u32(5)?,
        c.u32(6)? as u8 != 0,
        c.ptr(7)?,
        c.u32(8)?,
        c.u32(9)? as u8 != 0,
    );
    let agnostic = filter & THREAD_AGNOSTIC != 0;
    if agnostic {
        if !asynchronous || event == 0 || apc != 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
    } else {
        if io % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, io, (c.psize() * 2) as usize)?;
        if length != 0 {
            if buffer % 4 != 0 {
                return status(STATUS_DATATYPE_MISALIGNMENT);
            }
            probe_write(c, buffer, length as usize)?;
        }
        let stores = crate::user::windows::process::registry_notify::io_stores(c.p)
            .map_err(|error| Failure::Api(c.unsupported(error)))?;
        if stores == crate::user::windows::process::registry_notify::IoStores::Status32 {
            c.mem().w32(io, STATUS_PENDING)?;
        } else {
            c.mem().wptr(io, c.psize(), STATUS_PENDING.into())?;
        }
        c.mem().wptr(io + c.psize(), c.psize(), 0)?;
    }
    if filter & !(THREAD_AGNOSTIC | 15) != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    key(c, handle, false)?;
    if c.p.objects.access(handle).unwrap_or(0) & 0x10 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let key = c.p.objects.id(handle).expect("validated key handle");
    let event = if asynchronous && event != 0 {
        if event == c.arch().ptr(u64::MAX) || event == c.arch().ptr(u64::MAX - 1) {
            return status(STATUS_OBJECT_TYPE_MISMATCH);
        }
        match c.p.objects.get(event) {
            None => return status(STATUS_INVALID_HANDLE),
            Some(Object::Event { .. }) => {}
            Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        }
        if c.p.objects.access(event).unwrap_or(0) & 2 == 0 {
            return status(STATUS_ACCESS_DENIED);
        }
        c.p.objects.id(event)
    } else if asynchronous {
        None
    } else {
        Some(
            c.p.objects
                .try_create(Object::Event {
                    manual: false,
                    signaled: 0,
                })
                .ok_or(Failure::Status(STATUS_NO_MEMORY))?,
        )
    };
    let completion = RegistryCompletion {
        owner: (!agnostic).then_some(c.t.tid),
        event,
        io: (!agnostic).then_some(io),
        apc: (asynchronous && apc != 0).then_some((apc, context)),
    };
    if let Err(error) = c.p.objects.register_registry_notification(key, completion) {
        if !asynchronous {
            c.p.objects
                .release(event.expect("private synchronous event"));
        }
        return Err(c.unsupported(error).into());
    }
    if asynchronous {
        Ok(Flow::Ret(crate::user::windows::hle::Value::Int(
            STATUS_PENDING.into(),
        )))
    } else {
        Ok(Flow::Block {
            wait: Wait::NativeObjects {
                objs: vec![event.expect("private synchronous event")],
                all: false,
                deadline: None,
                alertable: false,
            },
            then: Box::new(|_, _| Flow::ret(0x10b)),
        })
    }
}
