//! Publication order is observable with aliasing and a crossing IOSB.
use super::super::named_object::{Checked, Failure};
use super::records::{Publication, Record};
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{Mem, MemFault};

pub(super) fn record(
    c: &mut Ctx,
    io: u64,
    output: u64,
    r: &Record,
    wow: bool,
    caller_length: u32,
) -> Checked<u32> {
    c.mem().wr(output, &r.data)?;
    let information = io.checked_add(c.psize()).ok_or(MemFault {
        addr: u64::MAX,
        write: true,
    })?;
    if wow {
        // Caller data is already observable before either WoW64 IOSB store.
        // Captured Information/output overlap retains the returned data after
        // the Information store. The thunk copies the caller's requested span,
        // including untouched bytes beyond the returned record. A short caller
        // span leaves the rest of the Information store intact.
        let aliased = if output == information {
            Some(c.mem().bytes(information, caller_length.min(4) as usize)?)
        } else {
            None
        };
        c.mem().w32(io, r.status)?;
        c.mem().w32(information, r.information)?;
        if let Some(bytes) = aliased {
            c.mem().wr(information, &bytes)?;
        }
        return Ok(r.status);
    }
    let result: Checked<()> = (|| {
        match r.publication {
            Publication::Full => {
                c.mem().wptr(io, c.psize(), u64::from(r.status))?;
                c.mem()
                    .wptr(information, c.psize(), u64::from(r.information))?;
            }
            Publication::InformationFirst => {
                c.mem()
                    .wptr(information, c.psize(), u64::from(r.information))?;
                c.mem().w32(io, r.status)?;
            }
            Publication::StatusFirst => {
                c.mem().w32(io, r.status)?;
                c.mem()
                    .wptr(information, c.psize(), u64::from(r.information))?;
            }
        }
        Ok(())
    })();
    match result {
        Err(Failure::Api(crate::user::windows::hle::ApiErr::Fault(fault)))
            if r.ignore_late_fault =>
        {
            let _ = super::super::query::write_guard_result(c, Err(fault.into()));
        }
        result => result?,
    }
    Ok(r.status)
}
