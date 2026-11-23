//! Selected kernel-device opens do not acquire host files or sharing lifetimes.
use super::super::file_attributes::{attributes, path};
use super::super::named_object::{Checked, status};
use super::Request;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::user::windows::object_namespace::security_device::{
    CNG_NAME, NAME, SRP_NAME, SecurityDevice, supports_srp_device_absence,
};
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
    if let Some(exact) = device_name(c, name, SRP_NAME) {
        let version = &c.p.cfg.version;
        return Some(
            if exact
                && creation.is_none()
                && attributes.flags == 0x40
                && !attributes.custom_security
                && (request.access, request.share, request.options) == (1, 7, 0)
                && supports_srp_device_absence(
                    (version.major, version.minor, version.build),
                    c.arch(),
                    c.p.object_namespace.native_machine,
                )
                && c.p.object_namespace.srp_device_absent
            {
                status(STATUS_OBJECT_NAME_NOT_FOUND)
            } else {
                Err(c
                    .unsupported("SRP device open is outside the captured absence profile")
                    .into())
            },
        );
    }
    if let Some(exact) = device_name(c, name, CNG_NAME) {
        return Some(open_cng(c, request, attributes, creation, exact));
    }
    let exact = device_name(c, name, NAME)?;
    Some(open_ksecdd(c, request, attributes, creation, exact))
}

fn device_name(c: &mut Ctx, name: &[u16], device: &str) -> Option<bool> {
    let expected: Vec<u16> = device.encode_utf16().collect();
    if name.len() < expected.len()
        || !path::equal(c, &name[..expected.len()], &expected)
        || name.len() != expected.len() && name[expected.len()] != u16::from(b'\\')
    {
        return None;
    }
    Some(name.len() == expected.len())
}

fn open_cng(
    c: &mut Ctx,
    request: Request,
    attributes: &attributes::Attributes,
    creation: Option<&super::host::Creation>,
    exact_name: bool,
) -> Checked<(u64, u64)> {
    let device =
        c.p.object_namespace
            .cng_device()
            .ok_or_else(|| c.unsupported("kernel CNG device identity is not captured"))?;
    let access = super::mapped_access(request.access);
    if c.arch() != WinArch::Arm64
        || !exact_name
        || attributes.flags != 0x40
        || creation.is_some()
        || (access, request.share, request.options) != (0x100001, 7, 0x20)
    {
        return Err(c
            .unsupported("CNG entropy device open parameters are not selected")
            .into());
    }
    open_device(c, device, request, attributes, access)
}

fn open_ksecdd(
    c: &mut Ctx,
    request: Request,
    attributes: &attributes::Attributes,
    creation: Option<&super::host::Creation>,
    exact_name: bool,
) -> Checked<(u64, u64)> {
    let device =
        c.p.object_namespace
            .security_device()
            .ok_or_else(|| c.unsupported("kernel security-device identity is not captured"))?;
    let access = super::mapped_access(request.access);
    if device.server_2022_profile() {
        // Match the installed AMD64 bcrypt open, with a guest-owned handle.
        // The host capture is read-only and has already closed its handle.
        if c.arch() == WinArch::X64
            && !c.p.cfg.host_filesystem
            && exact_name
            && matches!(attributes.flags, 0 | 0x40)
            && !attributes.custom_security
            && creation.is_none()
            && (request.access, request.share, request.options) == (0x100003, 7, 0x20)
        {
            return open_device(c, device, request, attributes, access);
        }
        return Err(c
            .unsupported("Server 2022 security-device open parameters are not selected")
            .into());
    }
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
    let standard_open = matches!(access, 1 | 0x80 | 0x100000 | 0x100001 | 0x20000)
        && matches!(request.share, 0 | 7)
        && matches!(request.options, 0 | 0x20 | 0x21 | 0x60 | 0x61);
    // Installed bcrypt requests this specific file grant on build 29708.
    let bcrypt_open = device.kernel == (10, 0, 29708)
        && exact_name
        && attributes.flags == 0
        && creation.is_none()
        && (access, request.share, request.options) == (0x100003, 7, 0x20);
    if !standard_open && !bcrypt_open {
        return Err(c
            .unsupported("security-device access/share/options are not selected")
            .into());
    }
    open_device(c, device, request, attributes, access)
}

fn open_device(
    c: &mut Ctx,
    device: SecurityDevice,
    request: Request,
    attributes: &attributes::Attributes,
    access: u32,
) -> Checked<(u64, u64)> {
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
