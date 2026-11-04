//! Construction uses the file grant already checked by the common file path.
use super::super::{Attributes, Request, object_create};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{FileSection, SectionGrantError, file_image};
use crate::user::windows::objects::Object;

pub(super) fn construct(c: &mut Ctx, request: Request, attrs: Attributes, size: u64) -> ApiResult {
    if request.attributes & 0x00680000 != 0 {
        return Err(c.unsupported("based, 64K-page or no-change file-section allocation"));
    }
    let security = c.p.objects.primary_token_subject().map(|subject| {
        if subject
            .privileges
            .iter()
            .any(|p| p.luid == 8 && p.attributes & 2 != 0)
        {
            0
        } else {
            STATUS_PRIVILEGE_NOT_HELD
        }
    });
    let grant = match file_image::grant(request.access, security) {
        Ok(grant) => grant,
        Err(SectionGrantError::Status(status)) => return Flow::ret(status.into()),
        Err(SectionGrantError::Unavailable(reason)) => return Err(c.unsupported(reason)),
    };
    let Some(Object::File(file)) = c.p.objects.get(request.file) else {
        unreachable!("retained file reference");
    };
    let Some(host) = &file.host else {
        return Err(c.unsupported("file section requires a retained host file"));
    };
    if super::file_access(file.access) & 1 == 0 {
        return Err(c.unsupported(
            "file-section byte extraction requires a readable admitted file resource",
        ));
    }
    let section = match FileSection::create(
        host,
        file.lifetime.clone(),
        size,
        request.protection,
        security,
    ) {
        Ok(section) => section,
        Err(file_image::Error::Status(status)) => return Flow::ret(status.into()),
        Err(file_image::Error::Unavailable(reason)) => return Err(c.unsupported(reason)),
    };
    object_create::publish(
        c,
        request.out,
        attrs.flags & 2 != 0,
        grant,
        Object::FileSection(section),
    )
}
