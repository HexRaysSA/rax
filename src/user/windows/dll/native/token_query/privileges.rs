//! TOKEN_PRIVILEGES publication from the selected subject's ordered records.

use super::{Ctx, Flow, Mem, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS};
use crate::user::windows::hle::ApiResult;
use crate::user::windows::security::Privilege;
use crate::user::windows::security::token::privileges::{ENTRY_BYTES, HEADER_BYTES, sizes};

pub(super) fn publish(
    c: &Ctx,
    privileges: &[Privilege],
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let (required, _) = sizes(privileges.len())
        .ok_or_else(|| c.unsupported("token privilege count exceeds the capture limit"))?;
    c.mem().w32(returned, required as u32)?;
    if (length as usize) < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    c.mem().w32(output, privileges.len() as u32)?;
    let mut address = output + HEADER_BYTES as u64;
    for privilege in privileges {
        c.mem().w64(address, privilege.luid)?;
        c.mem().w32(address + 8, privilege.attributes)?;
        address += ENTRY_BYTES as u64;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
