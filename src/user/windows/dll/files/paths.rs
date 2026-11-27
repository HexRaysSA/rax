use super::*;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Flow;
use crate::user::windows::objects::Object;

pub(super) fn final_path_w(c: &mut Ctx) -> ApiResult {
    const VOLUME_NAME_GUID: u32 = 1;
    const VOLUME_NAME_NT: u32 = 2;
    const VOLUME_NAME_NONE: u32 = 4;
    const FILE_NAME_OPENED: u32 = 8;
    let (handle, out, capacity, flags) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.u32(3)?);
    let volume = flags & !FILE_NAME_OPENED;
    if !matches!(
        volume,
        0 | VOLUME_NAME_GUID | VOLUME_NAME_NT | VOLUME_NAME_NONE
    ) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(Object::File(file)) = c.p.objects.get(handle) else {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    };
    let (drive, opened) = match file.path.split_once(':') {
        Some((drive, path)) if path.starts_with('\\') => match drive.as_bytes() {
            [letter @ (b'A'..=b'Z' | b'a'..=b'z')] => (letter.to_ascii_uppercase(), path),
            _ => return c.fail(ERROR_PATH_NOT_FOUND, 0),
        },
        _ => return c.fail(ERROR_PATH_NOT_FOUND, 0),
    };
    let retained =
        c.p.objects
            .file_name_origin(handle)
            .and_then(|origin| origin.as_ref().ok())
            .zip(file.host.as_ref());
    let mut path = Vec::new();
    match volume {
        VOLUME_NAME_NT if c.p.native.is_some() => {
            let native = retained.and_then(|(origin, host)| origin.local_nt_name(host).ok());
            let Some((name, device_units)) = native else {
                return c.fail(ERROR_PATH_NOT_FOUND, 0);
            };
            path.extend_from_slice(&name[..device_units]);
        }
        VOLUME_NAME_NT => {
            // Drive bindings define the portable guest's volume identities.
            let number = drive - b'A' + 1;
            path.extend(format!(r"\Device\HarddiskVolume{number}").encode_utf16());
        }
        VOLUME_NAME_GUID => return c.fail(ERROR_PATH_NOT_FOUND, 0),
        VOLUME_NAME_NONE => {}
        _ => {
            path.extend(r"\\?\".encode_utf16());
            path.extend([u16::from(drive), u16::from(b':')]);
        }
    }
    if flags & FILE_NAME_OPENED != 0 {
        path.extend(opened.encode_utf16());
    } else {
        let name = retained.map(|(origin, host)| origin.name(host, &file.host_path));
        match name {
            Some(Ok(name)) => path.extend(name),
            Some(Err(error)) => return c.fail(host_error(&error, None, ERROR_PATH_NOT_FOUND), 0),
            None => return c.fail(ERROR_PATH_NOT_FOUND, 0),
        }
    }
    if u64::from(capacity) <= path.len() as u64 {
        return Flow::ret(path.len() as u64 + 1);
    }
    c.mem().put_wstr(out, &path)?;
    Flow::ret(path.len() as u64)
}

pub(super) fn attributes_a(c: &mut Ctx) -> ApiResult {
    attributes(c, false)
}

pub(super) fn attributes_w(c: &mut Ctx) -> ApiResult {
    attributes(c, true)
}

fn attributes(c: &mut Ctx, wide: bool) -> ApiResult {
    const INVALID_ATTRIBUTES: u64 = u32::MAX as u64;
    let address = c.ptr(0)?;
    let text = match name(c, address, wide)? {
        Ok(name) => name,
        Err(error) => return bad_name(c, error, INVALID_ATTRIBUTES),
    };
    let (_, host) = match open::resolve(c, &text) {
        Ok(path) => path,
        Err(error) => return bad_name(c, error, INVALID_ATTRIBUTES),
    };
    super::super::native::win32_attributes(c, &host)
}

pub(super) fn delete_w(c: &mut Ctx) -> ApiResult {
    delete(c, true)
}
pub(super) fn delete_a(c: &mut Ctx) -> ApiResult {
    delete(c, false)
}

fn delete(c: &mut Ctx, wide: bool) -> ApiResult {
    let address = c.ptr(0)?;
    preflight_error(c)?;
    let text = match name(c, address, wide)? {
        Ok(n) => n,
        Err(e) => return bad_name(c, e, 0),
    };
    let (_, host) = match open::resolve(c, &text) {
        Ok(v) => v,
        Err(e) => return bad_name(c, e, 0),
    };
    let metadata = match std::fs::symlink_metadata(&host) {
        Ok(m) => m,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), 0),
    };
    if metadata.is_dir() || metadata.permissions().readonly() {
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    if host
        .parent()
        .and_then(|p| std::fs::metadata(p).ok())
        .is_some_and(|m| m.permissions().readonly())
    {
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    // DeleteFile removes a symbolic link, not its target. Target handles do
    // not participate in that distinct object's sharing/deletion lifetime.
    let identity = match FileIdentity::of(&host, &metadata) {
        Ok(i) => i,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), 0),
    };
    let mut lifetime = None;
    let mut open_error = None;
    if !metadata.is_symlink() {
        for (_, object) in c.p.objects.iter() {
            let Object::File(file) = object else {
                continue;
            };
            if file.lifetime.identity != identity {
                continue;
            }
            if file.lifetime.blocks_opens() {
                open_error = Some(ERROR_ACCESS_DENIED);
                break;
            }
            if file.share & SHARE_DELETE == 0 {
                open_error = Some(ERROR_SHARING_VIOLATION);
                break;
            }
            lifetime = Some(file.lifetime.clone());
        }
    }
    if let Some(error) = open_error {
        return c.fail(error, 0);
    }
    if let Some(lifetime) = lifetime {
        let target = match host.canonicalize() {
            Ok(p) => p,
            Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), 0),
        };
        if let Err(e) = lifetime.mark_delete(target, true) {
            return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), 0);
        }
        Flow::bool(true)
    } else {
        match std::fs::remove_file(&host) {
            Ok(()) => Flow::bool(true),
            Err(e) => c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), 0),
        }
    }
}
