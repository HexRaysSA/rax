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

/// A file-backed non-image Section with live backing bytes.
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
    lifetime: Option<Arc<FileLifetime>>,
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
        let length = crate::user::windows::fs::retained_len(file).map_err(io_error)?;
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
            lifetime: Some(lifetime),
            #[cfg(windows)]
            _native: native,
            #[cfg(windows)]
            backing_section,
            #[cfg(windows)]
            filename: OnceLock::new(),
        }))
    }

    /// A read/execute file section transferred by the installed cache service.
    /// Its file is owned by that section and has no guest file lifetime.
    #[cfg(windows)]
    pub(crate) fn from_cache(
        handle: std::os::windows::io::OwnedHandle,
        size: u64,
    ) -> std::io::Result<Arc<Self>> {
        if !(1..=MAX_BYTES).contains(&size) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cache section extent",
            ));
        }
        let native = Arc::new(handle);
        let backing = Arc::new(SharedObject::native_file_section(
            native.clone(),
            size,
            false,
            None,
        )?);
        Ok(Arc::new(Self {
            filename: OnceLock::new(),
            _native: native.clone(),
            backing_section: native,
            size,
            protection: 0x20,
            backing,
            security: None,
            lifetime: None,
        }))
    }

    pub(crate) fn file_identity(&self) -> Option<&FileIdentity> {
        self.lifetime.as_ref().map(|lifetime| &lifetime.identity)
    }

    pub(crate) fn is_cache_section(&self) -> bool {
        self.lifetime.is_none()
    }

    pub(crate) fn same_imported_section(&self, other: &Self) -> bool {
        #[cfg(windows)]
        return self.is_cache_section()
            && other.is_cache_section()
            && native::same_object(&self._native, &other._native);
        #[cfg(not(windows))]
        {
            let _ = other;
            false
        }
    }

    pub(crate) fn grant(&self, access: u32) -> Result<u32, SectionGrantError> {
        super::file_image::grant(access & !0x0200_0000, self.security)
    }

    pub(crate) fn mapped_filename(&self) -> Result<Option<Vec<u16>>, String> {
        #[cfg(windows)]
        {
            self.native_filename()?
                .read()
                .map(Some)
                .map_err(|error| error.to_string())
        }
        #[cfg(not(windows))]
        Ok(None)
    }

    #[cfg(windows)]
    pub(crate) fn native_filename(
        &self,
    ) -> Result<&crate::user::windows::mapped_filename::Filename, String> {
        self.filename
            .get_or_init(|| {
                crate::user::windows::mapped_filename::Filename::data_section(&self.backing_section)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

/// Both open Section objects and views whose handles have closed retain their
/// file identity. O(H + V) for H owned objects and V file views.
pub(crate) fn is_live(p: &crate::user::windows::process::Proc, identity: &FileIdentity) -> bool {
    p.objects.iter().any(|(_, object)| {
        matches!(object, crate::user::windows::objects::Object::FileSection(section)
            if section.file_identity() == Some(identity))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::image::pe::hybrid::CodeKind;
    use crate::user::mm::{AddressSpace, SpaceConfig, anonymous_file};
    use crate::user::windows::memory::{FileViewOptions, Mem, VirtualMemory, prot};
    use crate::user::windows::object_namespace::CodeBitmapPlan;
    use std::io::Write;

    #[cfg(windows)]
    #[test]
    fn native_imported_file_section_maps_the_final_partial_page() {
        let mut file = anonymous_file().unwrap();
        let bytes = vec![0x6a; 65537];
        file.write_all(&bytes).unwrap();
        let (handle, size) = native::create(&file, 0, prot::READONLY).unwrap();
        assert_eq!(size, bytes.len() as u64);
        let imported = FileSection::from_cache(handle, size).unwrap();
        drop(file);
        assert!(imported.file_identity().is_none());
        assert!(imported.same_imported_section(&imported));

        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 1 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space, 65536, 1 << 47);
        let base = 0x2000_0000;
        vm.map_file_section(imported, base, 0, 69632, prot::READONLY)
            .unwrap();
        assert_eq!(vm.space().bytes(base, bytes.len()).unwrap(), bytes);
        assert_eq!(vm.space().bytes(base + 65537, 4095).unwrap(), [0; 4095]);
    }

    #[test]
    fn native_extended_cache_view_tags_live_execute_bytes_and_preserves_bits_after_unmap() {
        let mut file = anonymous_file().unwrap();
        file.write_all(&[0x6a; 8193]).unwrap();
        #[cfg(windows)]
        let section = {
            let (handle, size) = native::create(&file, 0, prot::READONLY).unwrap();
            FileSection::from_cache(handle, size).unwrap()
        };
        #[cfg(not(windows))]
        let section = {
            let id =
                FileIdentity::of(std::path::Path::new("."), &file.metadata().unwrap()).unwrap();
            FileSection::create(
                &file,
                Arc::new(FileLifetime::new(id)),
                0,
                prot::EXECUTE_READ,
                None,
            )
            .unwrap()
        };
        drop(file);
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 1 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space, 65536, 1 << 47);
        let bitmap = 0x7df4_51a1_0000;
        vm.publish_ec_image(
            &CodeBitmapPlan {
                base: Some(bitmap),
                ranges: vec![],
            },
            0,
            0,
        )
        .unwrap();
        let base = 0x5000_0000;
        let bit_byte = bitmap + (base >> 15);
        for ec_code in [false, true] {
            let options = FileViewOptions {
                ec_code,
                targets_invalid: true,
            };
            vm.map_file_section_with(section.clone(), base, 0, 12288, prot::EXECUTE_READ, options)
                .unwrap();
            assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
            assert_eq!(
                vm.space().u8(bit_byte).unwrap(),
                if ec_code { 7 } else { 0 }
            );
            assert_eq!(
                vm.dynamic_code_kind(base + 12287).unwrap(),
                ec_code.then_some(CodeKind::Arm64Ec)
            );
            assert!(!vm.valid_call_target(base));
            vm.release(base).unwrap();
            assert_eq!(vm.dynamic_code_kind(base).unwrap(), None);
            assert_eq!(
                vm.space().u8(bit_byte).unwrap(),
                if ec_code { 7 } else { 0 }
            );
        }
    }
}
