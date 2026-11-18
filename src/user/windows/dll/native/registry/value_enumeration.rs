//! Value enumeration over ordinal data acquired with the immutable guest key.
use super::*;

pub(in super::super) fn enumerate_value(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    finish(c, result)
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, index, class, output, length, returned) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    if class > 2 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let key = key(c, handle, true)?;
    if length != 0 && output % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, returned, 4)?;
    let values = key
        .ordered_values()
        .ok_or_else(|| c.unsupported("registry value enumeration order is not captured"))?;
    let Some(value) = values.get(index as usize) else {
        return Ok(STATUS_NO_MORE_ENTRIES);
    };
    // Native leaves both destinations untouched for missing ordinals. For a
    // present value it publishes the required length before copying record bytes.
    write_value_record(c, value, class, output, length, returned, None)
}
