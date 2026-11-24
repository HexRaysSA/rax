//! Synthesize the closed DOS directory hierarchy and search its installed files.
#[cfg(windows)]
mod windows;

use super::super::super::file_attributes::{metadata, path};
use super::super::{Checked, Ctx};
use crate::user::windows::objects::DirectoryEntry;

pub(super) fn collect(c: &Ctx, directory: &str) -> Checked<Vec<DirectoryEntry>> {
    let names = path::guest_directories(c)
        .ok_or_else(|| c.unsupported("closed installed directory tree is unavailable"))?;
    let directory_name: Vec<_> = directory.trim_end_matches('\\').encode_utf16().collect();
    let installed =
        c.p.native
            .as_ref()
            .and_then(|runtime| runtime.directory.to_str())
            .and_then(|name| name.strip_prefix(r"\\?\"));
    let installed_parent =
        installed.and_then(|name| name.rsplit_once('\\').map(|(parent, _)| parent));
    let subdirectories: Vec<_> = names
        .iter()
        .filter_map(|candidate| {
            let (parent, name) = candidate.rsplit_once('\\')?;
            let parent: Vec<_> = parent.encode_utf16().collect();
            if name.is_empty() || !path::equal(c, &directory_name, &parent) {
                return None;
            }
            // The system directory APIs can differ in case from disk. Use the
            // normalized spelling only for the same admitted DOS name.
            let dos_name: Vec<_> = candidate.encode_utf16().collect();
            let spelling = [installed_parent, installed]
                .into_iter()
                .flatten()
                .find(|name| {
                    let installed_name: Vec<_> = name.encode_utf16().collect();
                    path::equal(c, &dos_name, &installed_name)
                });
            Some(
                spelling
                    .and_then(|name| name.rsplit('\\').next())
                    .unwrap_or(name),
            )
        })
        .collect();
    if !subdirectories.is_empty() {
        return Ok(subdirectories
            .into_iter()
            .map(|name| {
                let info = metadata::guest_directory();
                DirectoryEntry {
                    name: name.encode_utf16().collect(),
                    short_name: Vec::new(),
                    times: info.times,
                    allocation: info.allocation,
                    size: info.size,
                    attributes: info.attributes,
                    ea: None,
                    file_id: 0,
                }
            })
            .collect());
    }
    let Some(runtime) = c.p.native.as_ref() else {
        return Err(c
            .unsupported("closed installed runtime is unavailable")
            .into());
    };
    // For WoW64, the DOS System32 alias intentionally uses the selected
    // SysWOW64 view. No guest text is passed to the host directory scan.
    #[cfg(windows)]
    return windows::collect(c, &runtime.directory);
    #[cfg(unix)]
    return super::snapshot::installed(c, &runtime.directory);
    #[cfg(not(any(unix, windows)))]
    return Err(c
        .unsupported("installed directory enumeration adapter is unavailable")
        .into());
}
