//! Temporary pagefile names share the isolated guest object namespace.
use super::super::named_object::{self, Checked, Failure, status};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{Directory, NativeName};
use crate::user::windows::objects::{ObjId, Object};
use std::sync::Arc;

const SE_CREATE_GLOBAL_PRIVILEGE: u64 = 30;
pub(super) const OBJECT_NAME_EXISTS: u32 = 0x4000_0000;

pub(super) fn existing(c: &Ctx, name: &NativeName) -> Checked<Option<ObjId>> {
    let Some(id) = c.p.objects.by_native_name(name) else {
        return Ok(None);
    };
    if !matches!(c.p.objects.obj(id), Some(Object::Mapping { .. })) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    Ok(Some(id))
}

pub(super) fn check_global_creation(c: &Ctx, name: &NativeName) -> Checked<()> {
    if !name.is_global() {
        return Ok(());
    }
    let session = c.p.objects.primary_token_session_id().ok_or_else(|| {
        c.unsupported("NT global pagefile section requires the selected token session")
    })?;
    if session == 0 {
        return Ok(());
    }
    let subject = c.p.objects.primary_token_subject().ok_or_else(|| {
        c.unsupported("NT global pagefile section requires captured token privileges")
    })?;
    if subject.privilege(SE_CREATE_GLOBAL_PRIVILEGE) {
        Ok(())
    } else {
        status(STATUS_PRIVILEGE_NOT_HELD)
    }
}

pub(in super::super) fn open(
    c: &mut Ctx,
    root: Option<Arc<Directory>>,
    units: &[u16],
    flags: u32,
    access: u32,
) -> Checked<Option<u32>> {
    // The installed section resolver owns paths outside the guest-created
    // namespace. Preserve its errors and access checks if no guest name exists.
    let Ok(name) = c.p.object_namespace.named(root, units, flags) else {
        return Ok(None);
    };
    let Some(id) = existing(c, &name)? else {
        return Ok(None);
    };
    if flags & 0x120 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let grant = super::grant(c, access)?;
    c.p.objects
        .open_access(id, flags & 2 != 0, grant)
        .map(Some)
        .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES))
}

pub(super) fn publish(
    c: &mut Ctx,
    out: u64,
    inherit: bool,
    grant: u32,
    id: ObjId,
    already_existed: bool,
) -> ApiResult {
    let Some(handle) = c.p.objects.open_access(id, inherit, grant) else {
        if !already_existed {
            c.p.objects.release(id);
        }
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(
        if already_existed {
            OBJECT_NAME_EXISTS
        } else {
            STATUS_SUCCESS
        }
        .into(),
    )
}

pub(super) fn api_error(error: Failure) -> ApiResult {
    match error {
        Failure::Status(code) => Ok(named_object::nt_return(code)),
        Failure::Api(error) => Err(error),
    }
}
