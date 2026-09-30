//! Supplied PE dependencies use guest paths and never probe host paths.
use super::*;

pub(super) fn load(p: &mut Proc, name: &str, explicit: bool) -> Option<Result<usize, LoadError>> {
    let cwd = String::from_utf16_lossy(&p.cwd);
    let app = p
        .cfg
        .guest_image_path
        .as_deref()
        .and_then(|path| path.rsplit_once('\\').map(|(dir, _)| dir.to_owned()))
        .unwrap_or_else(|| cwd.to_string());
    let absolute = name.starts_with(['\\', '/']) || name.as_bytes().get(1) == Some(&b':');
    let candidates = if explicit && absolute {
        vec![name.to_owned()]
    } else {
        vec![format!("{app}\\{name}"), format!("{cwd}\\{name}")]
    };
    for candidate in candidates {
        let Some(path) = super::super::fs::full_path(&candidate, &cwd) else {
            continue;
        };
        let path = path.to_string_path();
        let key = path.to_ascii_lowercase();
        let Some(bytes) = p.cfg.supplied_dlls.get(&key).cloned() else {
            continue;
        };
        if let Some(error) = p.modules.failures.get(&key) {
            return Some(Err(error.clone()));
        }
        if let Some(idx) = loaded_guest_path(p, &path) {
            return Some(Ok(idx));
        }
        // The immutable supplied bytes are copied into the PE parser's ownership;
        // guest mappings are populated by the same loader as filesystem DLLs.
        return Some(load_image(p, bytes.to_vec(), &key, path, None));
    }
    None
}
