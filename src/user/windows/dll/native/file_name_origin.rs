//! Open-time guest namespace selection is independent of host path mechanics.
use crate::user::windows::fs::{FileNameOrigin, full_path};
use crate::user::windows::hle::Ctx;
use crate::user::windows::objects::Object;

pub(in crate::user::windows::dll) fn win32(c: &Ctx, path: &str) -> Result<FileNameOrigin, String> {
    absolute(c, &path.encode_utf16().collect::<Vec<_>>(), false)
}

pub(super) fn nt(
    c: &Ctx,
    root: u64,
    name: Option<&[u16]>,
    runtime_library: bool,
) -> Result<FileNameOrigin, String> {
    if root != 0 {
        if let Some(origin) = c.p.objects.file_name_origin(root) {
            return origin.clone();
        }
        return match c.p.objects.get(root) {
            Some(Object::File(file)) => absolute(
                c,
                &file.path.encode_utf16().collect::<Vec<_>>(),
                runtime_library,
            ),
            _ => Err("file name root is not a retained file object".into()),
        };
    }
    absolute(
        c,
        name.ok_or("file name has no captured DOS volume")?,
        runtime_library,
    )
}

fn absolute(c: &Ctx, name: &[u16], runtime_library: bool) -> Result<FileNameOrigin, String> {
    let colon = name
        .iter()
        .position(|u| *u == u16::from(b':'))
        .filter(|i| *i > 0 && name.get(*i + 1) == Some(&u16::from(b'\\')))
        .ok_or("file name has no captured DOS volume")?;
    let unit = name[colon - 1];
    if !matches!(unit, 65..=90 | 97..=122) {
        return Err("invalid file name volume".into());
    }
    let drive = char::from(unit as u8);
    if runtime_library {
        let runtime =
            c.p.native
                .as_ref()
                .ok_or("installed-library namespace is unavailable")?;
        let mapped = full_path(&runtime.guest_directory, "C:\\")
            .and_then(|path| c.p.cfg.drives.resolve(&path))
            .and_then(|path| path.canonicalize().ok());
        if mapped.as_ref() != Some(&runtime.directory) {
            let prefix = runtime
                .guest_directory
                .split_once(':')
                .ok_or("installed-library directory has no DOS volume")?
                .1;
            return FileNameOrigin::capture(&runtime.directory, prefix.encode_utf16().collect())
                .map_err(|e| format!("retained installed-library naming root: {e}"));
        }
    }
    let root =
        c.p.cfg
            .drives
            .root(drive)
            .ok_or("file name volume is not mapped")?;
    FileNameOrigin::capture(root, Vec::new()).map_err(|e| format!("retained naming root: {e}"))
}
