//! Enumerate admitted installed images without enumerating a host directory.
use super::super::super::file_attributes::{metadata, path};
use super::super::super::file_open::host;
use super::super::super::named_object::Failure;
use super::super::{Checked, Ctx};
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::native::SELECTED_CHILD_EXECUTABLES;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};
use crate::user::windows::objects::DirectoryEntry;

pub(super) fn collect(c: &Ctx, directory: &str) -> Checked<Vec<DirectoryEntry>> {
    if directory.ends_with(":\\") {
        return Err(c.unsupported("enumeration of the closed drive root").into());
    }
    let mut entries = Vec::with_capacity(SELECTED_CHILD_EXECUTABLES.len());
    for name in SELECTED_CHILD_EXECUTABLES {
        let absolute: Vec<_> = format!(r"{directory}\{name}").encode_utf16().collect();
        let (base, file) = match path::selected(c, &absolute) {
            Ok(Some(entry)) => entry,
            Ok(None)
            | Err(Failure::Status(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND)) => {
                continue;
            }
            Err(failure) => return Err(failure),
        };
        let resolved = path::Resolved {
            host: file,
            base,
            root: None,
            relative: None,
            directory: false,
            runtime_library: true,
        };
        let opened = match host::open(c, &resolved, 0x100080, 7, 0x60, 0x40) {
            Ok(entry) => entry,
            Err(Failure::Status(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND)) => {
                continue;
            }
            Err(failure) => return Err(failure),
        };
        let info = metadata::descriptor(c, &opened.path, &opened.file)?;
        let file_id = match opened.identity {
            FileIdentity::Unix(_, inode) => inode,
            FileIdentity::Windows(_, id) => u64::from_le_bytes(id[..8].try_into().unwrap()),
            _ => {
                return Err(c
                    .unsupported("installed image has no stable file identity")
                    .into());
            }
        };
        entries.push(DirectoryEntry {
            name: name.encode_utf16().collect(),
            short_name: Vec::new(),
            times: info.times,
            allocation: info.allocation,
            size: info.size,
            attributes: info.attributes,
            ea: None,
            file_id,
        });
    }
    Ok(entries)
}
