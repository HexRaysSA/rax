//! Current-directory handles for the closed installed namespace.
use super::super::file_attributes::{attributes, path};
use super::super::named_object::{Checked, status};
use super::{Request, host, mapped_access, shared_lifetime};
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object};
use std::path::PathBuf;
use std::sync::Arc;

fn selected(c: &Ctx, name: &[u16]) -> Option<String> {
    let runtime = c.p.native.as_ref()?;
    let dos = path::dos_tail(c, name)?;
    let drive = runtime.guest_root.split_once(':')?.0;
    let root = format!("{drive}:\\");
    if path::equal(c, dos, &root.encode_utf16().collect::<Vec<_>>()) {
        return Some(root);
    }
    let dos = dos.strip_suffix(&[u16::from(b'\\')]).unwrap_or(dos);
    let runtime_dir = runtime.guest_directory.trim_end_matches('\\');
    if path::equal(c, dos, &runtime_dir.encode_utf16().collect::<Vec<_>>()) {
        return Some(runtime_dir.to_owned());
    }
    if c.arch() == WinArch::X86 {
        let system32 = format!(r"{}\System32", runtime.guest_root.trim_end_matches('\\'));
        if path::equal(c, dos, &system32.encode_utf16().collect::<Vec<_>>()) {
            return Some(system32);
        }
    }
    None
}

pub(super) fn open(
    c: &mut Ctx,
    request: Request,
    attrs: &attributes::Attributes,
    name: Option<&[u16]>,
    creation: Option<&host::Creation>,
) -> Option<Checked<(u64, u64)>> {
    if c.p.cfg.host_filesystem || attrs.root != 0 {
        return None;
    }
    let directory = selected(c, name?)?;
    let access = mapped_access(request.access);
    // LIST_DIRECTORY, TRAVERSE, READ_ATTRIBUTES, READ_CONTROL and SYNCHRONIZE.
    const DIRECTORY_READ: u32 = 0x0012_00a1;
    // DIRECTORY_FILE, synchronous nonalertable I/O and OPEN_FOR_BACKUP_INTENT.
    const SUPPORTED_OPTIONS: u32 = 0x4021;
    if access & !DIRECTORY_READ != 0
        || attrs.custom_security
        || creation.is_some_and(|creation| creation.disposition != 1)
    {
        return Some(status(STATUS_ACCESS_DENIED));
    }
    if request.options & 0x40 != 0 {
        return Some(status(STATUS_FILE_IS_A_DIRECTORY));
    }
    if request.options & !SUPPORTED_OPTIONS != 0 || request.options & 1 == 0 {
        return Some(Err(c
            .unsupported("unselected installed directory open options")
            .into()));
    }
    let identity = FileIdentity::GuestDirectory(directory.clone());
    let lifetime = match shared_lifetime(c, &identity, access, request.share) {
        Ok(lifetime) => lifetime.unwrap_or_else(|| Arc::new(FileLifetime::new(identity))),
        Err(error) => return Some(Err(error)),
    };
    let file = FileObj {
        host: None,
        host_path: PathBuf::new(),
        path: directory,
        access,
        share: request.share,
        lifetime,
        null: false,
        append: false,
        delete_on_close: false,
        directory: true,
        overlapped: request.options & 0x30 == 0,
    };
    let Some(id) = c.p.objects.try_create(Object::File(file)) else {
        return Some(status(STATUS_INSUFFICIENT_RESOURCES));
    };
    c.p.objects.set_file_mode(id, request.options);
    Some(
        match c.p.objects.open_access(id, attrs.flags & 2 != 0, access) {
            Some(handle) => Ok((u64::from(handle), 1)),
            None => {
                c.p.objects.release(id);
                status(STATUS_INSUFFICIENT_RESOURCES)
            }
        },
    )
}
