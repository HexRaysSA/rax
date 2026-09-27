use super::*;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Flow;
use crate::user::windows::objects::Object;

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
