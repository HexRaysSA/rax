//! Read-only installed Windows runtime selection. No general host filesystem
//! permission is implied, and unavailable native inputs never select HLE DLLs.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::arch::WinArch;
use super::loader::apiset_schema::ApiSetSchema;
use super::process::WinVersion;
use crate::user::image::pe::PeImage;

const MAX_DLL_BYTES: u64 = 64 << 20;

#[derive(Debug)]
pub(crate) struct NativeRuntime {
    pub(crate) directory: PathBuf,
    pub(crate) guest_root: String,
    pub(crate) guest_directory: String,
    pub(crate) version: WinVersion,
    pub(crate) apisets: ApiSetSchema,
    pub(crate) registry: super::registry::Registry,
    pub(crate) nls: Option<super::nls::Nls>,
    pub(crate) startup: Option<super::process::native_start::EntryPoints>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn read_image(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_DLL_BYTES {
        return Err(invalid(
            "selected native DLL must be a regular file at most 64 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_DLL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DLL_BYTES {
        return Err(invalid("selected native DLL exceeded 64 MiB"));
    }
    Ok(bytes)
}

impl NativeRuntime {
    pub(crate) fn select(arch: WinArch) -> io::Result<Self> {
        let (root, directory, schema_directory, version) = platform::select(arch)?;
        let guest_root = root
            .to_str()
            .ok_or_else(|| invalid("native Windows root is not valid Unicode"))?
            .to_owned();
        let guest_directory = directory
            .to_str()
            .ok_or_else(|| invalid("native Windows system directory is not valid Unicode"))?
            .to_owned();
        let directory = directory.canonicalize()?;
        let schema_directory = schema_directory.canonicalize()?;
        let pe = PeImage::parse(read_image(&schema_directory.join("apisetschema.dll"))?)
            .map_err(|e| invalid(format!("installed API-set image: {e}")))?;
        if u64::from(pe.mapped_size()) > MAX_DLL_BYTES {
            return Err(invalid("installed API-set image mapping exceeds 64 MiB"));
        }
        let section = pe
            .sections()
            .iter()
            .find(|s| s.name_str() == ".apiset")
            .ok_or_else(|| invalid("installed API-set image has no .apiset section"))?;
        let memory = pe.memory_image();
        let start = section.virtual_address as usize;
        let end = start
            .checked_add(section.virtual_size as usize)
            .ok_or_else(|| invalid("API-set section overflow"))?;
        let apisets = ApiSetSchema::parse(
            memory
                .get(start..end)
                .ok_or_else(|| invalid("API-set section outside image"))?,
        )?;
        let mut runtime = Self {
            directory,
            guest_root,
            guest_directory,
            version,
            apisets,
            registry: Default::default(),
            nls: None,
            startup: None,
        };
        let ntdll = PeImage::parse(read_image(
            &runtime
                .dll("ntdll.dll")?
                .ok_or_else(|| invalid("installed NTDLL missing"))?,
        )?)
        .map_err(|e| invalid(format!("installed NTDLL: {e}")))?;
        if WinArch::from_machine(ntdll.headers().machine) != Some(arch) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed NTDLL architecture does not match the guest",
            ));
        }
        runtime.registry = super::registry::snapshot()?;
        runtime.nls = Some(super::nls::snapshot(&runtime.registry, &schema_directory)?);
        Ok(runtime)
    }

    pub(crate) fn dll(&self, name: &str) -> io::Result<Option<PathBuf>> {
        if name.is_empty() || name.contains(['\\', '/', ':', '\0']) || name == "." || name == ".." {
            return Err(invalid("native DLL selection requires a basename"));
        }
        let Some(path) = super::fs::find_case_insensitive(&self.directory, name) else {
            return Ok(None);
        };
        let path = path.canonicalize()?;
        if !path.starts_with(&self.directory) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed DLL escapes its selected directory",
            ));
        }
        Ok(Some(path))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub(super) fn select(_: WinArch) -> io::Result<(PathBuf, PathBuf, PathBuf, WinVersion)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Windows libraries require a Windows host",
        ))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[repr(C)]
    struct Version {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
        service_major: u16,
        service_minor: u16,
        suite: u16,
        product: u8,
        reserved: u8,
    }
    const _: [(); 284] = [(); std::mem::size_of::<Version>()];
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetSystemWow64DirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut Version) -> i32;
    }

    fn directory(api: unsafe extern "system" fn(*mut u16, u32) -> u32) -> io::Result<PathBuf> {
        let mut buffer = vec![0u16; 32768];
        // SAFETY: the system-ABI function receives an exclusive initialized
        // UTF-16 buffer of exactly the supplied capacity; it retains no pointer,
        // does not unwind, and its returned length is checked before slicing.
        let length = unsafe { api(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length >= buffer.len() {
            return Err(invalid("Windows directory exceeds 32767 UTF-16 units"));
        }
        if buffer[..length].contains(&0) {
            return Err(invalid("Windows directory API returned an embedded NUL"));
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
    }

    pub(super) fn select(arch: WinArch) -> io::Result<(PathBuf, PathBuf, PathBuf, WinVersion)> {
        let root = directory(GetWindowsDirectoryW)?;
        let system = directory(GetSystemDirectoryW)?;
        let native = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let guest = if arch == native {
            system.clone()
        } else if arch == WinArch::X86 {
            match directory(GetSystemWow64DirectoryW) {
                Ok(path) => path,
                // This Windows ARM64 installation reports a nonzero length
                // but leaves the entire WoW64 buffer zero. Its installed
                // SysWOW64 directory is an independently validated candidate:
                // select() checks the actual NTDLL machine before admission.
                Err(error) if error.kind() == io::ErrorKind::InvalidData => root.join("SysWOW64"),
                Err(error) => return Err(error),
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no matching installed Windows runtime directory for the guest architecture",
            ));
        };
        let mut version = Version {
            size: std::mem::size_of::<Version>() as u32,
            major: 0,
            minor: 0,
            build: 0,
            platform: 0,
            service_pack: [0; 128],
            service_major: 0,
            service_minor: 0,
            suite: 0,
            product: 0,
            reserved: 0,
        };
        // SAFETY: Version is the initialized repr(C) RTL_OSVERSIONINFOEXW
        // layout (284 bytes), naturally aligned and exclusively borrowed for
        // the non-retaining, non-unwinding native system-ABI call.
        let status = unsafe { RtlGetVersion(&mut version) };
        if status < 0 {
            return Err(invalid(format!("RtlGetVersion failed: {status:#010x}")));
        }
        Ok((
            root,
            guest,
            system,
            WinVersion {
                major: version.major,
                minor: version.minor,
                build: version.build,
                product_type: version.product,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_image_reads_are_read_only_and_bounded_before_copying() {
        let dir = std::env::temp_dir().join(format!(
            "rax-native-image-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let path = dir.join("selected.dll");
        std::fs::write(&path, b"selected bytes").unwrap();
        assert_eq!(read_image(&path).unwrap(), b"selected bytes");
        assert_eq!(std::fs::read(&path).unwrap(), b"selected bytes");
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_DLL_BYTES + 1).unwrap();
        drop(file);
        assert_eq!(
            read_image(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(read_image(&dir).is_err());
        assert_eq!(
            read_image(&dir.join("absent.dll")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
    #[cfg(not(windows))]
    #[test]
    fn native_selection_refuses_a_different_host_os() {
        for arch in [WinArch::X86, WinArch::X64, WinArch::Arm64] {
            assert_eq!(
                NativeRuntime::select(arch).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn installed_schema_preserves_hash_identities_and_parent_redirects() {
        let arch = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let runtime = NativeRuntime::select(arch).unwrap();
        assert!(runtime.version.major >= 10);
        assert_eq!(
            runtime
                .apisets
                .host("api-ms-win-crt-runtime-l1-1-0.dll", None),
            Some("ucrtbase.dll")
        );
        assert_eq!(
            runtime
                .apisets
                .host("api-ms-win-core-appinit-l1-1-0", Some("kernel32.dll")),
            Some("kernelbase.dll")
        );
        assert_eq!(
            runtime
                .apisets
                .host("api-ms-win-crt-runtime-l1-65535-0", None),
            None
        );
        assert!(
            runtime
                .dll("NTDLL.DLL")
                .unwrap()
                .unwrap()
                .starts_with(&runtime.directory)
        );
        for name in [
            "..\\ntdll.dll",
            "C:ntdll.dll",
            "ntdll.dll:stream",
            "/ntdll.dll",
        ] {
            assert!(runtime.dll(name).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn installed_numeric_revisions_match_native_windows_loader_resolution() {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
            fn GetModuleFileNameW(module: *mut c_void, path: *mut u16, size: u32) -> u32;
            fn FreeLibrary(module: *mut c_void) -> i32;
        }
        let arch = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let runtime = NativeRuntime::select(arch).unwrap();
        for revision in ["0", "1", "65535"] {
            let name = format!("api-ms-win-core-rtlsupport-l1-1-{revision}.dll");
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            // SAFETY: the UTF-16 name is terminated and retained for this call,
            // the reserved file handle is null, and 0x800 limits search to the
            // system directory. The resulting loader reference is released below.
            let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x800) };
            assert!(!module.is_null(), "native loader refused {name}");
            let mut path = vec![0u16; 32768];
            // SAFETY: module is the live reference obtained above; path contains
            // 32,768 writable initialized UTF-16 units and remains live in the call.
            let count = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) };
            // SAFETY: release precisely the loader reference acquired above;
            // no module pointer is used after this call.
            assert_ne!(unsafe { FreeLibrary(module) }, 0);
            assert!(count != 0 && (count as usize) < path.len());
            let host = String::from_utf16(&path[..count as usize]).unwrap();
            assert_eq!(
                host.rsplit(['\\', '/'])
                    .next()
                    .unwrap()
                    .to_ascii_lowercase(),
                "ntdll.dll"
            );
            assert_eq!(runtime.apisets.host(&name, None), Some("ntdll.dll"));
        }
        for name in [
            "api-ms-win-core-rtlsupport-l1-1-banana.dll",
            "api-ms-win-core-rtlsupport-l65535-65535-0.dll",
        ] {
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            // SAFETY: terminated UTF-16 input and null reserved handle, as above.
            let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x800) };
            // Balance even an unexpected native success before reporting failure.
            if !module.is_null() {
                // SAFETY: this is the live loader reference just acquired.
                unsafe { FreeLibrary(module) };
            }
            assert!(
                module.is_null(),
                "native loader unexpectedly resolved {name}"
            );
            assert_eq!(runtime.apisets.host(name, None), None);
        }
    }
}
