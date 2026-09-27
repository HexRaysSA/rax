use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::Flow;
use crate::user::windows::objects::{FileObj, Object};
use std::fs::{Metadata, OpenOptions};
use std::path::PathBuf;
use std::sync::Arc;

pub(super) fn create_w(c: &mut Ctx) -> ApiResult {
    create(c, true)
}
pub(super) fn create_a(c: &mut Ctx) -> ApiResult {
    create(c, false)
}

pub(super) fn resolve(c: &Ctx, path: &str) -> Result<(String, PathBuf), NameError> {
    if path.is_empty() {
        return Err(NameError::Error(ERROR_INVALID_NAME));
    }
    let cwd = String::from_utf16(&c.p.cwd).map_err(|_| NameError::Error(ERROR_INVALID_NAME))?;
    let full = crate::user::windows::fs::full_path(path, &cwd)
        .ok_or(NameError::Unsupported("UNC or device namespace pathname"))?;
    let verbatim = path.starts_with("\\\\?\\");
    if full
        .parts
        .iter()
        .any(|part| (verbatim && matches!(part.as_str(), "." | "..")) || part.contains(':'))
    {
        return Err(NameError::Unsupported(
            "verbatim dot components or alternate data stream",
        ));
    }
    if full
        .parts
        .iter()
        .any(|part| part.chars().any(|ch| ch < ' ' || "<>\"|?*/".contains(ch)))
    {
        return Err(NameError::Error(ERROR_INVALID_NAME));
    }
    if full
        .parts
        .iter()
        .any(|part| crate::user::windows::fs::dos_device(part).is_some())
    {
        return Err(NameError::Unsupported(
            "DOS device component in disk pathname",
        ));
    }
    let host =
        c.p.cfg
            .drives
            .resolve(&full)
            .ok_or(NameError::Error(ERROR_INVALID_DRIVE))?;
    Ok((full.to_string_path(), host))
}

fn inherit(c: &Ctx, at: u64) -> Result<Result<bool, NameError>, MemFault> {
    if at == 0 {
        return Ok(Ok(false));
    }
    let size = if c.arch().is64() { 24 } else { 12 };
    probe(c, at, size, false)?;
    if c.mem().u32(at)? != size as u32 {
        return Ok(Err(NameError::Error(ERROR_INVALID_PARAMETER)));
    }
    let pointer = at.checked_add(c.psize()).ok_or(MemFault {
        addr: u64::MAX,
        write: false,
    })?;
    if c.read_ptr(pointer)? != 0 {
        return Ok(Err(NameError::Unsupported(
            "explicit file security descriptor",
        )));
    }
    let inherit = pointer.checked_add(c.psize()).ok_or(MemFault {
        addr: u64::MAX,
        write: false,
    })?;
    Ok(Ok(c.mem().u32(inherit)? != 0))
}

fn shared_lifetime(
    c: &Ctx,
    identity: &FileIdentity,
    access: u32,
    share: u32,
) -> Result<Option<Arc<FileLifetime>>, u32> {
    let mut lifetime = None;
    for (_, object) in c.p.objects.iter() {
        let Object::File(file) = object else {
            continue;
        };
        if &file.lifetime.identity != identity {
            continue;
        }
        if file.lifetime.blocks_opens() {
            return Err(ERROR_ACCESS_DENIED);
        }
        let existing_access = file.access | if file.delete_on_close { DELETE } else { 0 };
        if share_access(access) & !file.share != 0
            || share_access(existing_access) & !share != 0
            || (file.lifetime.delete_requested() && share & SHARE_DELETE == 0)
        {
            return Err(ERROR_SHARING_VIOLATION);
        }
        lifetime = Some(file.lifetime.clone());
    }
    Ok(lifetime)
}

fn create(c: &mut Ctx, wide: bool) -> ApiResult {
    let (path, access, share, security, disposition, flags, template) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.u32(5)?,
        c.ptr(6)?,
    );
    preflight_error(c)?;
    let text = match name(c, path, wide)? {
        Ok(n) => n,
        Err(e) => return bad_name(c, e, u64::MAX),
    };
    let inherit = match inherit(c, security)? {
        Ok(v) => v,
        Err(e) => return bad_name(c, e, u64::MAX),
    };
    if !(1..=5).contains(&disposition) || share & !7 != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, u64::MAX);
    }
    // Data/append/attribute access, DELETE, READ_CONTROL, and SYNCHRONIZE are
    // modeled. ACL-changing, execution, EA, maximum-allowed and SQOS requests
    // cannot acquire silently fabricated rights.
    const SUPPORTED_ACCESS: u32 =
        GENERIC_READ | GENERIC_WRITE | 7 | 0x180 | DELETE | 0x0002_0000 | 0x0010_0000;
    if access & !SUPPORTED_ACCESS != 0 {
        return Err(c.unsupported("unmodeled file access rights"));
    }
    if flags & !(0x80 | BACKUP_SEMANTICS | DELETE_ON_CLOSE) != 0 {
        return Err(c.unsupported("unmodeled file attributes or flags (including overlapped I/O)"));
    }
    if template != 0 {
        return Err(c.unsupported("file attribute template handle"));
    }
    if let Some(device) = crate::user::windows::fs::dos_device(&text) {
        if device != "NUL" {
            return Err(c.unsupported("opening console/communications DOS devices"));
        }
        if disposition != 3 || flags & !0x80 != 0 {
            return c.fail(ERROR_INVALID_PARAMETER, u64::MAX);
        }
        let object = Object::File(FileObj {
            host: None,
            host_path: PathBuf::new(),
            path: "NUL".into(),
            access,
            share,
            lifetime: Arc::new(FileLifetime::new(FileIdentity::Null)),
            null: true,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        });
        return publish(c, object, inherit, access);
    }
    let (windows, host) = match resolve(c, &text) {
        Ok(v) => v,
        Err(e) => return bad_name(c, e, u64::MAX),
    };
    let metadata = match std::fs::metadata(&host) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
    };
    if metadata
        .as_ref()
        .is_some_and(|m| !m.is_file() && !m.is_dir())
    {
        return Err(c.unsupported("non-regular host filesystem object"));
    }
    if metadata.is_some() && disposition == 1 {
        return c.fail(ERROR_FILE_EXISTS, u64::MAX);
    }
    if metadata.is_none() && matches!(disposition, 3 | 5) {
        return c.fail(
            if host.parent().is_some_and(|p| !p.is_dir()) {
                ERROR_PATH_NOT_FOUND
            } else {
                ERROR_FILE_NOT_FOUND
            },
            u64::MAX,
        );
    }
    if disposition == 5 && access & GENERIC_WRITE == 0 {
        return c.fail(ERROR_ACCESS_DENIED, u64::MAX);
    }
    let directory = metadata.as_ref().is_some_and(Metadata::is_dir);
    if directory
        && (flags & BACKUP_SEMANTICS == 0 || disposition != 3 || flags & DELETE_ON_CLOSE != 0)
    {
        return c.fail(ERROR_ACCESS_DENIED, u64::MAX);
    }
    let deleting = flags & DELETE_ON_CLOSE != 0;
    if deleting && !cfg!(unix) {
        return Err(c.unsupported("replacement-safe deferred deletion on this host"));
    }
    if deleting
        && host
            .parent()
            .and_then(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.permissions().readonly())
    {
        return c.fail(ERROR_ACCESS_DENIED, u64::MAX);
    }
    if metadata
        .as_ref()
        .is_some_and(|m| m.permissions().readonly())
        && (can_write(access) || deleting || access & DELETE != 0 || matches!(disposition, 2 | 5))
    {
        return c.fail(ERROR_ACCESS_DENIED, u64::MAX);
    }
    let identity = metadata
        .as_ref()
        .map(|m| FileIdentity::of(&host, m))
        .transpose();
    let identity = match identity {
        Ok(i) => i,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
    };
    let prior = match &identity {
        Some(identity) => match shared_lifetime(
            c,
            identity,
            access | if deleting { DELETE } else { 0 },
            share,
        ) {
            Ok(v) => v,
            Err(e) => return c.fail(e, u64::MAX),
        },
        None => None,
    };
    // Open without truncation, revalidate identity, then truncate. A sharing
    // conflict or pathname replacement must not destroy existing contents.
    let append = access & APPEND_DATA != 0 && access & (GENERIC_WRITE | WRITE_DATA) == 0;
    let creating = metadata.is_none();
    let mut options = OpenOptions::new();
    options
        .read(can_read(access))
        .write(can_set_end(access) || creating || matches!(disposition, 2 | 5))
        .append(append);
    if creating {
        options.create_new(true);
    }
    let mut file = if directory
        || (!creating && !can_read(access) && !can_write(access) && !matches!(disposition, 2 | 5))
    {
        None
    } else {
        match options.open(&host) {
            Ok(f) => Some(f),
            Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
        }
    };
    let actual_metadata = match file
        .as_ref()
        .map_or_else(|| std::fs::metadata(&host), std::fs::File::metadata)
    {
        Ok(m) => m,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
    };
    let actual_identity = match FileIdentity::of(&host, &actual_metadata) {
        Ok(i) => i,
        Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
    };
    if identity
        .as_ref()
        .is_some_and(|expected| expected != &actual_identity)
    {
        return c.fail(ERROR_SHARING_VIOLATION, u64::MAX);
    }
    if matches!(disposition, 2 | 5) {
        if let Some(file) = file.as_mut() {
            if let Err(e) = file.set_len(0) {
                return c.fail(host_error(&e, Some(&host), ERROR_WRITE_FAULT), u64::MAX);
            }
        }
    }
    let lifetime = prior.unwrap_or_else(|| Arc::new(FileLifetime::new(actual_identity)));
    if deleting {
        let target = match host.canonicalize() {
            Ok(p) => p,
            Err(e) => return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX),
        };
        if let Err(e) = lifetime.mark_delete(target, false) {
            return c.fail(host_error(&e, Some(&host), ERROR_ACCESS_DENIED), u64::MAX);
        }
    }
    let object = Object::File(FileObj {
        host: file,
        host_path: host,
        path: windows,
        access,
        share,
        lifetime,
        null: false,
        append,
        delete_on_close: deleting,
        directory,
        overlapped: false,
    });
    if matches!(disposition, 2 | 4) {
        c.set_last_error(if creating {
            ERROR_SUCCESS
        } else {
            ERROR_ALREADY_EXISTS
        })?;
    }
    publish(c, object, inherit, access)
}

fn publish(c: &mut Ctx, object: Object, inherit: bool, access: u32) -> ApiResult {
    let Some(id) = c.p.objects.try_create(object) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, u64::MAX);
    };
    match c
        .p
        .objects
        .open_access(id, inherit, effective_access(access))
    {
        Some(handle) => Flow::ret(u64::from(handle)),
        None => {
            let object = c.p.objects.release(id);
            // Preserve allocation failure, not a cleanup failure.
            let _ = super::finish_close(object);
            c.fail(ERROR_NOT_ENOUGH_MEMORY, u64::MAX)
        }
    }
}
