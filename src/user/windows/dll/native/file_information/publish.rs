//! Publication order is observable with aliasing and a crossing IOSB.
use super::super::named_object::{Checked, Failure};
use super::records::{Publication, Record};
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::STATUS_SUCCESS;

pub(super) fn record(c: &mut Ctx, io: u64, output: u64, r: &Record, wow: bool) -> Checked<u32> {
    c.mem().wr(output, &r.data)?;
    let information = io.checked_add(c.psize()).ok_or(MemFault {
        addr: u64::MAX,
        write: true,
    })?;
    if wow {
        // Caller data is already observable before either WoW64 IOSB store.
        // Captured Information/output overlap retains the returned data.
        let aliased = if output == information {
            Some(c.mem().bytes(information, 4)?)
        } else {
            None
        };
        c.mem().w32(io, 0)?;
        c.mem().w32(information, r.information)?;
        if let Some(bytes) = aliased {
            c.mem().wr(information, &bytes)?;
        }
        return Ok(STATUS_SUCCESS);
    }
    let result: Checked<()> = (|| {
        match r.publication {
            Publication::Full => {
                c.mem().wptr(io, c.psize(), 0)?;
                c.mem()
                    .wptr(information, c.psize(), u64::from(r.information))?;
            }
            Publication::InformationFirst => {
                c.mem()
                    .wptr(information, c.psize(), u64::from(r.information))?;
                c.mem().w32(io, 0)?;
            }
            Publication::StatusFirst => {
                c.mem().w32(io, 0)?;
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
    Ok(STATUS_SUCCESS)
}
