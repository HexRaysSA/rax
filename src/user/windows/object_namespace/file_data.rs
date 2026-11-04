//! Live file-section identity. Guest handles and views retain the admitted
//! file resource; no pathname is reopened and no guest pointer reaches the host.
use super::SectionGrantError;
use super::file_image::Error;
use crate::user::mm::SharedObject;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::nt::status::*;
use std::fs::File;
use std::sync::Arc;
#[cfg(windows)]
use std::sync::OnceLock;

const MAX_BYTES: u64 = 64 << 20;
#[cfg(windows)]
mod native;

/// A guest-created, file-backed non-image Section with live backing bytes.
#[derive(Debug)]
pub struct FileSection {
    // Metadata views and the native section retire before the backing file
    // and its final deferred-delete owner. Rust drops fields in this order.
    #[cfg(windows)]
    filename: OnceLock<Result<crate::user::windows::mapped_filename::Filename, String>>,
    #[cfg(windows)]
    _native: Arc<std::os::windows::io::OwnedHandle>,
    #[cfg(windows)]
    backing_section: Arc<std::os::windows::io::OwnedHandle>,
    pub(crate) size: u64,
    pub(crate) protection: u32,
    pub(crate) backing: Arc<SharedObject>,
    security: Option<u32>,
    pub(crate) lifetime: Arc<FileLifetime>,
}

impl FileSection {
    /// O(1) host metadata/handle work. Extending a shared-writable section
    /// changes the admitted file length; creating a Section populates no pages.
    pub(crate) fn create(
        file: &File,
        lifetime: Arc<FileLifetime>,
        maximum: u64,
        protection: u32,
        security: Option<u32>,
    ) -> Result<Arc<Self>, Error> {
        let length = file.metadata().map_err(io_error)?.len();
        let size = if maximum == 0 { length } else { maximum };
        if size == 0 {
            return Err(Error::Status(STATUS_MAPPED_FILE_SIZE_ZERO));
        }
        if size > length && !matches!(protection, 4 | 0x40) {
            return Err(Error::Status(STATUS_SECTION_TOO_BIG));
        }
        if size > MAX_BYTES {
            return Err(Error::Unavailable(
                "NtCreateSection exceeds the 64 MiB file-section bound".into(),
            ));
        }
        let writable = matches!(protection, 4 | 0x40);
        #[cfg(not(windows))]
        let backing = Arc::new(
            SharedObject::file_keeping(
                file.try_clone().map_err(io_error)?,
                writable,
                Some(lifetime.clone()),
            )
            .map_err(io_error)?,
        );
        #[cfg(windows)]
        let (native, size) = native::create(file, maximum, protection)?;
        #[cfg(windows)]
        let native = Arc::new(native);
        #[cfg(windows)]
        let backing_section = if protection == 0x10 {
            // Executable-only guest pages still need readable decoder bytes.
            // The admitted resource was already checked readable; this unnamed
            // adapter section adds no file rights and reopens no pathname.
            Arc::new(native::create(file, size, 2)?.0)
        } else {
            native.clone()
        };
        #[cfg(windows)]
        let backing = Arc::new(
            SharedObject::native_file_section(
                backing_section.clone(),
                size,
                writable,
                Some(lifetime.clone()),
            )
            .map_err(io_error)?,
        );
        #[cfg(not(windows))]
        if size > length {
            file.set_len(size).map_err(io_error)?;
        }
        Ok(Arc::new(Self {
            size,
            protection,
            backing,
            security,
            lifetime,
            #[cfg(windows)]
            _native: native,
            #[cfg(windows)]
            backing_section,
            #[cfg(windows)]
            filename: OnceLock::new(),
        }))
    }

    pub(crate) fn grant(&self, access: u32) -> Result<u32, SectionGrantError> {
        super::file_image::grant(access & !0x0200_0000, self.security)
    }

    pub(crate) fn mapped_filename(&self) -> Result<Option<Vec<u16>>, String> {
        #[cfg(windows)]
        {
            let name = self.filename.get_or_init(|| {
                crate::user::windows::mapped_filename::Filename::data_section(&self.backing_section)
                    .map_err(|error| error.to_string())
            });
            match name {
                Ok(name) => name.read().map(Some).map_err(|error| error.to_string()),
                Err(error) => Err(error.clone()),
            }
        }
        #[cfg(not(windows))]
        Ok(None)
    }
}

/// Both open Section objects and views whose handles have closed retain their
/// file identity. O(H + V) for H owned objects and V file views.
pub(crate) fn is_live(p: &crate::user::windows::process::Proc, identity: &FileIdentity) -> bool {
    p.objects.iter().any(|(_, object)| {
        matches!(object, crate::user::windows::objects::Object::FileSection(section)
            if &section.lifetime.identity == identity)
    }) || p.vm.has_file_section(identity)
}

fn io_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Error::Status(STATUS_ACCESS_DENIED)
    } else {
        Error::Unavailable(format!("retained file-section resource: {error}"))
    }
}

/// Native standard PAGE_* compatibility; copy writes need readable bytes,
/// whereas shared writes require shared-writable creation/view protection.
pub(crate) fn allows(initial: u32, requested: u32) -> bool {
    let initial = initial & 0xFF;
    let read = matches!(initial, 2 | 4 | 8 | 0x20 | 0x40 | 0x80);
    let write = matches!(initial, 4 | 0x40);
    let execute = matches!(initial, 0x10 | 0x20 | 0x40 | 0x80);
    match requested & 0xFF {
        1 => true,
        2 | 8 => read,
        4 => write,
        0x10 => execute,
        0x20 | 0x80 => read && execute,
        0x40 => write && execute,
        _ => false,
    }
}
