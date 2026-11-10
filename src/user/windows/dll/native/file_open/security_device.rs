//! Selected kernel-device opens do not acquire host files or sharing lifetimes.
use super::super::file_attributes::{attributes, path};
use super::super::named_object::{Checked, status};
use super::Request;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::user::windows::object_namespace::security_device::NAME;
use crate::user::windows::objects::Object;

pub(super) fn open(
    c: &mut Ctx,
    request: Request,
    attributes: &attributes::Attributes,
    name: Option<&[u16]>,
    creation: Option<&super::host::Creation>,
) -> Option<Checked<(u64, u64)>> {
    if attributes.root != 0 {
        return matches!(
            c.p.objects.get(attributes.root),
            Some(Object::SecurityFile(_))
        )
        .then(|| {
            Err(c
                .unsupported("relative security-device names are not selected")
                .into())
        });
    }
    let name = name?;
    let expected: Vec<u16> = NAME.encode_utf16().collect();
    if name.len() < expected.len()
        || !path::equal(c, &name[..expected.len()], &expected)
        || name.len() != expected.len() && name[expected.len()] != u16::from(b'\\')
    {
        return None;
    }
    Some(checked(c, request, attributes, creation))
}

fn checked(
    c: &mut Ctx,
    request: Request,
    attributes: &attributes::Attributes,
    creation: Option<&super::host::Creation>,
) -> Checked<(u64, u64)> {
    let device =
        c.p.object_namespace
            .security_device()
            .ok_or_else(|| c.unsupported("kernel security-device identity is not captured"))?;
    if creation.is_some_and(|request| {
        request.disposition != 1
            || request.allocation.is_some()
            || request.attributes != 0
            || !request.ea.is_empty()
    }) {
        return Err(c
            .unsupported("security-device creation options are not selected")
            .into());
    }
    let access = super::mapped_access(request.access);
    if !matches!(access, 1 | 0x80 | 0x100000 | 0x100001 | 0x20000)
        || !matches!(request.share, 0 | 7)
        || !matches!(request.options, 0 | 0x20 | 0x21 | 0x60 | 0x61)
    {
        return Err(c
            .unsupported("security-device access/share/options are not selected")
            .into());
    }
    let Some(id) = c.p.objects.try_create(Object::SecurityFile(device)) else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    c.p.objects.set_file_mode(id, request.options);
    match c
        .p
        .objects
        .open_access(id, attributes.flags & 2 != 0, access)
    {
        Some(handle) => Ok((handle.into(), 0)),
        None => {
            c.p.objects.release(id);
            status(STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}
