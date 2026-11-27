//! Guest thread identity, opening rights and measured native/WoW64 capture order.
use super::client_open;
use super::query::{guard_result, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    if c.arch() == WinArch::X86 {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let request = match client_open::capture(c)? {
        Ok(request) => request,
        Err(status) => return Flow::ret(status.into()),
    };
    if !request.attributes_present {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    let Some((pid, tid)) = request.client.filter(|_| request.name == 0) else {
        return Flow::ret(STATUS_INVALID_PARAMETER_MIX.into());
    };
    if pid != 0 && pid != u64::from(c.p.pid) {
        return Flow::ret(STATUS_INVALID_CID.into());
    }
    // Exited objects remain discoverable while handles/waits retain them. The
    // current thread is absent from p.threads during dispatch, so that map is
    // neither the identity namespace nor the object lifetime authority.
    let Some(id) = c.p.objects.iter().find_map(|(id, object)| {
        matches!(object, Object::Thread { tid: target, .. } if u64::from(*target) == tid & !3)
            .then_some(id)
    }) else {
        return Flow::ret(STATUS_INVALID_CID.into());
    };
    if request.flags & 0xb0 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let access =
        c.p.thread_access
            .as_ref()
            .map_err(|error| c.unsupported(format!("thread opening rights: {error}")))?;
    let grant = match access.grant(request.desired) {
        Ok(grant) => grant,
        Err(status) => return Flow::ret(status.into()),
    };
    client_open::publish(c, request.output, id, request.flags, grant)
}
