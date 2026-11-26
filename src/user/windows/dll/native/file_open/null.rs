//! DOS device opens for a process that starts without an attached console.
use super::super::file_attributes::{attributes, path};
use super::super::named_object::{Checked, status};
use super::Request;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::user::windows::objects::{FileObj, Object};
use std::path::PathBuf;
use std::sync::Arc;

pub(super) fn open(
    c: &mut Ctx,
    request: Request,
    attrs: &attributes::Attributes,
    name: Option<&[u16]>,
) -> Option<Checked<(u64, u64)>> {
    if attrs.root != 0 {
        return None;
    }
    let name = name?;
    let mut selected = None;
    for (prefix, device) in [
        ("\\??\\", "NUL"),
        ("\\DosDevices\\", "NUL"),
        ("\\Device\\", "Null"),
    ] {
        let prefix: Vec<u16> = prefix.encode_utf16().collect();
        if name.len() < prefix.len() || !path::equal(c, &name[..prefix.len()], &prefix) {
            continue;
        }
        let tail = &name[prefix.len()..];
        let component = tail.split(|unit| *unit == u16::from(b'\\')).next()?;
        let expected: Vec<u16> = device.encode_utf16().collect();
        if path::equal(c, component, &expected) {
            // The native null driver accepts a remaining counted child name.
            // It is never interpreted as a host filesystem path.
            selected = Some(());
        } else if device == "NUL" && !component.is_empty() && !component.contains(&u16::from(b':'))
        {
            let text = String::from_utf16_lossy(component);
            let other_device = crate::user::windows::fs::dos_device(&text).filter(|device| {
                let units: Vec<u16> = device.encode_utf16().collect();
                path::equal(c, component, &units)
            });
            return Some(match other_device.as_deref() {
                // Process startup supplies redirected streams without an
                // attached console. The DOS aliases require a console.
                Some("CON" | "CONIN$" | "CONOUT$") if tail.len() == component.len() => {
                    status(STATUS_INVALID_HANDLE)
                }
                Some(_) => Err(c
                    .unsupported("NT DOS device outside the selected null-device profile")
                    .into()),
                None => status(STATUS_OBJECT_NAME_NOT_FOUND),
            });
        }
        break;
    }
    selected?;
    let access = super::mapped_access(request.access);
    if access & 0x0300_0000 != 0 {
        return Some(Err(c
            .unsupported("null-device maximum-access or system-security privilege mapping")
            .into()));
    }
    let file = FileObj {
        host: None,
        host_path: PathBuf::new(),
        path: String::from_utf16_lossy(name),
        access,
        share: request.share,
        lifetime: Arc::new(FileLifetime::new(FileIdentity::Null)),
        null: true,
        append: access & 4 != 0 && access & 2 == 0,
        delete_on_close: false,
        directory: false,
        overlapped: request.options & 0x30 == 0,
    };
    let Some(id) = c.p.objects.try_create(Object::File(file)) else {
        return Some(status(STATUS_INSUFFICIENT_RESOURCES));
    };
    c.p.objects.set_file_mode(id, request.options);
    Some(
        match c.p.objects.open_access(id, attrs.flags & 2 != 0, access) {
            Some(handle) => Ok((u64::from(handle), 0)),
            None => {
                c.p.objects.release(id);
                status(STATUS_INSUFFICIENT_RESOURCES)
            }
        },
    )
}
