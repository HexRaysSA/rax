//! Filesystem lookup for unqualified and explicitly restricted DLL loads.

use super::{
    BuiltinDll, LoadError, Proc, STATUS_DLL_NOT_FOUND, dll, load_builtin, load_native, loaded_path,
    supplied, system_dir,
};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DllSearch {
    #[default]
    Default,
    Application,
    System,
    ApplicationAndSystem,
}

/// Finds a DLL file in the portable default search path.
pub(super) fn native(p: &Proc, name: &str) -> Option<PathBuf> {
    if !p.cfg.host_filesystem {
        return None;
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(parent) = p.cfg.exe_host_path.parent() {
        dirs.push(parent.to_path_buf());
    }
    let app_only = dirs.len();
    dirs.extend(p.cfg.dll_paths.iter().cloned());
    if let Some(cwd) = p
        .cfg
        .drives
        .to_host(&String::from_utf16_lossy(&p.cwd), &p.cwd)
    {
        dirs.push(cwd);
    }
    let lower = name.to_ascii_lowercase();
    for (i, dir) in dirs.iter().enumerate() {
        if p.native.is_none() && i >= app_only && dll::find(&lower).is_some() {
            return None;
        }
        if let Some(found) = super::super::fs::find_case_insensitive(dir, name) {
            return Some(found);
        }
    }
    None
}

fn from_host(p: &mut Proc, path: &Path) -> Result<usize, LoadError> {
    let key = p.cfg.drives.to_windows(path).to_ascii_lowercase();
    if let Some(error) = p.modules.failures.get(&key) {
        return Err(error.clone());
    }
    if let Some(index) = loaded_path(p, path) {
        return Ok(index);
    }
    load_native(p, path, &key)
}

fn from_guest(p: &mut Proc, path: &str) -> Option<Result<usize, LoadError>> {
    if let Some(result) = supplied::load(p, path, true) {
        return Some(result);
    }
    if !p.cfg.host_filesystem {
        return None;
    }
    let file = p.cfg.drives.to_host(path, &p.cwd)?;
    (file.is_file() || loaded_path(p, &file).is_some()).then(|| from_host(p, &file))
}

pub(super) fn restricted(
    p: &mut Proc,
    name: &str,
    builtin: Option<&'static BuiltinDll>,
    known: bool,
) -> Result<usize, LoadError> {
    let search = p.modules.dynamic.search;
    let system = matches!(search, DllSearch::System | DllSearch::ApplicationAndSystem);
    let application = matches!(
        search,
        DllSearch::Application | DllSearch::ApplicationAndSystem
    );
    if application
        && !known
        && let Some((dir, _)) = p.modules.exe().path.rsplit_once('\\')
        && let Some(result) = from_guest(p, &format!("{dir}\\{name}"))
    {
        return result;
    }
    if system || known {
        if let Some(runtime) = p.native.as_ref() {
            let path = runtime.dll(name).map_err(|error| {
                LoadError::new(STATUS_DLL_NOT_FOUND, format!("{name}: {error}"))
            })?;
            if let Some(path) = path {
                return from_host(p, &path);
            }
        } else {
            if let Some(builtin) = builtin {
                return load_builtin(p, builtin);
            }
            let dir = system_dir(p.arch);
            if let Some(result) = from_guest(p, &format!("{dir}\\{name}")) {
                return result;
            }
        }
    }
    Err(LoadError::new(
        STATUS_DLL_NOT_FOUND,
        format!("{name} was not found in the selected DLL search directories"),
    ))
}
