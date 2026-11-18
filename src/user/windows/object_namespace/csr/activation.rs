//! Immutable activation data for the selected installed system manifest.
use super::super::DataSection;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::native::NativeRuntime;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct ActivationContext {
    pub(crate) image: PathBuf,
    pub(crate) guest_path: String,
    pub(crate) file_identity: FileIdentity,
    #[cfg(all(windows, target_arch = "aarch64"))]
    _file: std::fs::File,
    pub(crate) manifest_rva: u32,
    pub(crate) manifest: Vec<u8>,
    pub(crate) manifest_time: u64,
    pub(crate) view: Arc<DataSection>,
}

#[cfg(all(windows, target_arch = "aarch64"))]
pub(crate) fn capture(runtime: &NativeRuntime) -> io::Result<Option<ActivationContext>> {
    platform::capture(runtime).map(Some)
}

#[cfg(not(all(windows, target_arch = "aarch64")))]
pub(crate) fn capture(_: &NativeRuntime) -> io::Result<Option<ActivationContext>> {
    Ok(None)
}

#[cfg(all(windows, target_arch = "aarch64"))]
mod platform {
    use super::super::super::data::DataRegion;
    use super::*;
    use crate::user::image::pe::resources::{RT_MANIFEST, ResId, ResourceTree};
    use crate::user::image::pe::{PeImage, dir};
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::memory::ALLOCATION_GRANULARITY;
    use crate::user::windows::native::read_image_file;
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use std::ptr::null;

    const MANIFEST_ID: usize = 2;
    const MAX_DATA: usize = 65536;
    const MAX_MAPPED_IMAGE_BYTES: u32 = 64 << 20;
    const HEADER: usize = 32;

    #[repr(C)]
    struct ActCtx {
        size: u32,
        flags: u32,
        source: *const u16,
        architecture: u16,
        language: u16,
        assembly_directory: *const u16,
        resource: *const u16,
        application: *const u16,
        module: *const c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateActCtxW(context: *const ActCtx) -> *mut c_void;
        fn ReleaseActCtx(context: *mut c_void);
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            output: *mut c_void,
            size: usize,
            copied: *mut usize,
        ) -> i32;
    }

    struct Context(*mut c_void);

    impl Drop for Context {
        fn drop(&mut self) {
            // SAFETY: this is the one reference returned by CreateActCtxW.
            unsafe { ReleaseActCtx(self.0) };
        }
    }

    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported installed activation data",
        )
    }

    fn self_read(address: usize, bytes: &mut [u8]) -> io::Result<()> {
        let mut copied = 0;
        // SAFETY: the source comes from our own live activation context.
        // The OS validates the source, and the initialized destination is
        // writable for its exact length.
        let ok = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                address as *const c_void,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                &mut copied,
            )
        };
        if ok == 0 || copied != bytes.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn activation_data(path: &Path) -> io::Result<Vec<u8>> {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let parameters = ActCtx {
            size: std::mem::size_of::<ActCtx>() as u32,
            flags: 8, // ACTCTX_FLAG_RESOURCE_NAME_VALID
            source: name.as_ptr(),
            architecture: 0,
            language: 0,
            assembly_directory: null(),
            resource: MANIFEST_ID as *const u16,
            application: null(),
            module: null(),
        };
        // SAFETY: the fixed installed path and all ABI inputs outlive the call.
        let handle = unsafe { CreateActCtxW(&parameters) };
        if handle.is_null() || handle == (-1isize) as *mut c_void {
            return Err(io::Error::last_os_error());
        }
        let context = Context(handle);
        // This pointer slot is selected only for Windows ARM64 build 29708.
        let mut raw = [0; 8];
        self_read(
            (context.0 as usize).checked_add(24).ok_or_else(invalid)?,
            &mut raw,
        )?;
        let address = usize::from_le_bytes(raw);
        if address < ALLOCATION_GRANULARITY as usize
            || address % ALLOCATION_GRANULARITY as usize != 0
        {
            return Err(invalid());
        }
        let mut header = [0; HEADER];
        self_read(address, &mut header)?;
        let field = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
        let length = field(12) as usize;
        if &header[..4] != b"Actx"
            || field(4) != HEADER as u32
            || field(8) != 1
            || !(HEADER..=MAX_DATA).contains(&length)
            || [field(16), field(24)]
                .into_iter()
                .any(|offset| offset % 4 != 0 || !(HEADER..length).contains(&(offset as usize)))
            || field(20) != 0
            || field(28) != 0
        {
            return Err(invalid());
        }
        let mut bytes = vec![0; length];
        self_read(address, &mut bytes)?;
        if bytes[..HEADER] != header {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub(super) fn capture(runtime: &NativeRuntime) -> io::Result<ActivationContext> {
        let image = runtime.dll("cryptui.dll")?.ok_or_else(invalid)?;
        let source =
            Path::new(&runtime.guest_directory).join(image.file_name().ok_or_else(invalid)?);
        if source.canonicalize()? != image {
            return Err(invalid());
        }
        let mut file = File::open(&image)?;
        let guest_path = source.to_str().ok_or_else(invalid)?.to_owned();
        let metadata = file.metadata()?;
        let file_identity = FileIdentity::of_open(&image, Some(&file), &metadata)?;
        let manifest_time = metadata.last_write_time();
        let pe = PeImage::parse(read_image_file(&mut file)?).map_err(|_| invalid())?;
        if pe.headers().machine != 0xAA64 || pe.mapped_size() > MAX_MAPPED_IMAGE_BYTES {
            return Err(invalid());
        }
        let tree = ResourceTree::new(pe.headers().directory(dir::RESOURCE)).ok_or_else(invalid)?;
        let mapped = pe.try_memory_image()?;
        let resource = tree
            .find_resource(
                &mapped,
                &ResId::Id(RT_MANIFEST),
                &ResId::Id(MANIFEST_ID as u32),
                None,
            )
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if !(1..=MAX_DATA).contains(&(resource.size as usize)) {
            return Err(invalid());
        }
        let start = resource.rva as usize;
        let end = start
            .checked_add(resource.size as usize)
            .ok_or_else(invalid)?;
        let manifest = mapped.get(start..end).ok_or_else(invalid)?.to_vec();
        let mut bytes = activation_data(&source)?;
        if file.metadata()?.last_write_time() != manifest_time {
            return Err(invalid());
        }
        let size = (bytes.len() as u64).next_multiple_of(PAGE_SIZE);
        bytes.resize(size as usize, 0);
        let view = DataSection::private_readonly(
            size,
            vec![DataRegion {
                offset: 0,
                size,
                bytes: Some(bytes.into()),
            }],
        )?;
        Ok(ActivationContext {
            image,
            guest_path,
            file_identity,
            _file: file,
            manifest_rva: resource.rva,
            manifest,
            manifest_time,
            view,
        })
    }
}
