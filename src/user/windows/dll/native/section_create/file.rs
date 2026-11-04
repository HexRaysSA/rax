//! File reference and access validation precede value/attribute construction.
use super::{Attributes, Request, object_create};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{ImageSection, SectionGrantError, file_image};
use crate::user::windows::objects::Object;
mod data;

fn file_access(mut access: u32) -> u32 {
    for (generic, specific) in [
        (0x80000000, 0x120089),
        (0x40000000, 0x120116),
        (0x20000000, 0x1200a0),
        (0x10000000, 0x1f01ff),
        (0x02000000, 0x1f01ff),
    ] {
        if access & generic != 0 {
            access = (access & !generic) | specific;
        }
    }
    access
}

pub(super) fn construct(
    c: &mut Ctx,
    request: Request,
    converted: Option<Attributes>,
    size: u64,
) -> ApiResult {
    let image = request.attributes & 0x01000000 != 0;
    if !image && request.attributes & 0x80000000 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_6.into());
    }
    let file = match c.p.objects.get(request.file) {
        Some(Object::File(file)) => file,
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        None if request.file == c.arch().ptr(u64::MAX)
            || request.file == c.arch().ptr(u64::MAX - 1) =>
        {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    let required = match request.protection {
        2 | 8 => 1,
        4 => 3,
        0x10 => 0x20,
        0x20 | 0x80 => 0x21,
        0x40 => 0x23,
        _ => unreachable!("section protection validated before file reference"),
    };
    let access = file_access(c.p.objects.access(request.file).unwrap_or(0));
    if access & required != required {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    if file.directory {
        return Flow::ret(STATUS_INVALID_FILE_FOR_SECTION.into());
    }
    // Read-only data backing rejects an oversized extent before object
    // capture. The shared-writable path can extend the file and reaches
    // object capture first; the independent negative-maximum rows bind both.
    if (image || !matches!(request.protection, 4 | 0x40)) && (size as i64) < 0 {
        return Flow::ret(STATUS_SECTION_TOO_BIG.into());
    }
    let attrs = match converted {
        Some(attrs) => attrs,
        None => match object_create::capture(c, request.object, "file-backed image section")? {
            Ok(attrs) => attrs,
            Err(status) => return Flow::ret(status.into()),
        },
    };
    if attrs.flags & !0x11ef2 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if attrs.root != 0 && attrs.name == 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    object_create::supported_attributes(c, &attrs, "file-backed image section")?;
    if attrs.flags & 0x10 != 0 {
        return Err(c.unsupported("permanent file-backed image section lifetime"));
    }
    if !image {
        // Shared-writable data sections capture object attributes before
        // rejecting a negative maximum.
        if (size as i64) < 0 {
            return Flow::ret(STATUS_SECTION_TOO_BIG.into());
        }
        return data::construct(c, request, attrs, size);
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
    let file = match c.p.objects.get(request.file) {
        Some(Object::File(file)) => file,
        _ => unreachable!("retained file reference"),
    };
    let Some(host) = file.host.as_ref() else {
        return Err(c.unsupported("file section requires retained image bytes"));
    };
    let backing = match file_image::acquire(
        host,
        size,
        request.protection,
        request.attributes,
        c.p.native.is_some(),
    ) {
        Ok(backing) => backing,
        Err(file_image::Error::Status(status)) => return Flow::ret(status.into()),
        Err(file_image::Error::Unavailable(reason)) => return Err(c.unsupported(reason)),
    };
    let section = ImageSection::created(backing, file.lifetime.clone(), security);
    object_create::publish(
        c,
        request.out,
        attrs.flags & 2 != 0,
        grant,
        Object::ImageSection(section),
    )
}
