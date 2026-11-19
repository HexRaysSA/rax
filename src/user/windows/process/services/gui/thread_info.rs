//! GUITHREADINFO for the guest desktop's converted, noninteractive threads.
use super::{Mem, Outcome, Proc, Thread, query_error};
use crate::user::windows::nt::error::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
};
use crate::user::windows::nt::status_to_error;

pub(super) fn query(p: &mut Proc, t: &Thread, [tid, output]: [u64; 2]) -> Result<u64, Outcome> {
    const SIZE: u32 = 72;
    let tid = tid as u32;
    if tid != 0
        && tid != t.tid
        && !p
            .gui
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.initialized)
    {
        return query_error(p, t, ERROR_INVALID_PARAMETER, None);
    }
    if !output.is_multiple_of(4) {
        let status = STATUS_DATATYPE_MISALIGNMENT;
        return query_error(p, t, status_to_error(status), Some(status));
    }
    let result = (|| {
        if p.space.u32(output)? != SIZE {
            return Ok(Some(ERROR_INVALID_PARAMETER));
        }
        if tid == 0 {
            // The message-only desktop has no guest foreground queue.
            return Ok(Some(ERROR_ACCESS_DENIED));
        }
        // These GUI threads own message-only windows. They have no active,
        // focused, captured, menu, sizing, or caret window on the desktop.
        let mut record = [0; SIZE as usize];
        record[..4].copy_from_slice(&SIZE.to_le_bytes());
        p.space.wr(output, &record)?;
        Ok(None)
    })();
    match result {
        Ok(Some(error)) => query_error(p, t, error, None),
        Ok(None) => Ok(1),
        Err(fault) => {
            let fault: crate::user::windows::memory::MemFault = fault;
            let status = if p.vm.take_guard(fault.addr) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            };
            query_error(p, t, status_to_error(status), Some(status))
        }
    }
}
