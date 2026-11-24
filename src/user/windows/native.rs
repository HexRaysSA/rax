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

mod code_integrity_policies;
mod code_integrity_policy;
mod image;
pub(crate) mod processor_power;
mod secure_boot_policy;
mod system;
mod wow64_gui;
pub(crate) use image::{SELECTED_CHILD_EXECUTABLES, SelectedImage, selected_child_executable};
pub(crate) use system::{SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES2, SupportedArchitectures};

pub(crate) fn supported_architectures(
    runtime: &NativeRuntime,
    arch: WinArch,
) -> Result<SupportedArchitectures, String> {
    system::capture_supported_architectures(runtime, arch)
}
pub(crate) use secure_boot_policy::{
    SECURE_BOOT_POLICY_BYTES, SYSTEM_SECURE_BOOT_POLICY_INFORMATION,
};

pub(crate) fn flush_information(runtime: &NativeRuntime) -> Result<[u8; 32], String> {
    system::capture_flush(&runtime.version, runtime.object_namespace.native_machine)
}

#[derive(Debug)]
pub(crate) struct NativeRuntime {
    pub(crate) directory: PathBuf,
    pub(crate) guest_root: String,
    pub(crate) guest_directory: String,
    pub(crate) version: WinVersion,
    pub(crate) apisets: ApiSetSchema,
    pub(crate) registry: super::registry::Registry,
    pub(crate) object_namespace: super::object_namespace::Namespace,
    pub(crate) nls: Option<super::nls::Nls>,
    pub(crate) appcompat: super::appcompat::Catalog,
    pub(crate) wnf_catalog: super::wnf::Catalog,
    pub(crate) startup: Option<super::process::native_start::EntryPoints>,
    pub(crate) gui: super::gui::Availability,
    pub(crate) code_integrity: Result<u32, String>,
    pub(crate) code_integrity_policy: Result<[u8; 32], String>,
    pub(crate) code_integrity_policies: Result<std::sync::Arc<[u8]>, String>,
    pub(crate) policy_catalog: Result<std::sync::Arc<super::policy::Catalog>, String>,
    pub(crate) secure_boot_policy: Result<[u8; SECURE_BOOT_POLICY_BYTES], String>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn read_image(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    read_image_file(&mut file)
}

pub(crate) fn read_image_file(file: &mut File) -> io::Result<Vec<u8>> {
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
    pub(crate) fn uses_legacy_gdi_init(&self, arch: WinArch) -> bool {
        arch == WinArch::X64
            && self.object_namespace.native_machine == Some(arch.machine())
            && (self.version.major, self.version.minor, self.version.build) == (10, 0, 20348)
            && self.version.product_type == 3
    }

    pub(crate) fn supports_secure_boot_policy(&self, arch: WinArch) -> bool {
        arch == WinArch::Arm64
            && (self.version.major, self.version.minor, self.version.build) == (10, 0, 29708)
            && self.object_namespace.native_machine == Some(0xAA64)
    }

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
        let memory = pe.try_memory_image()?;
        let start = section.virtual_address as usize;
        let end = start
            .checked_add(section.virtual_size as usize)
            .ok_or_else(|| invalid("API-set section overflow"))?;
        let apisets = ApiSetSchema::parse(
            memory
                .get(start..end)
                .ok_or_else(|| invalid("API-set section outside image"))?,
        )?;
        // These installed Server loaders resolve the recorded identity even
        // when the final component is empty or contains nondigits.
        let apisets = match (
            version.major,
            version.minor,
            version.build,
            version.product_type,
            arch,
        ) {
            (10, 0, 20348 | 26100, 3, WinArch::X64 | WinArch::X86) => {
                apisets.with_legacy_revision_lookup()
            }
            _ => apisets,
        };
        let mut runtime = Self {
            directory,
            guest_root,
            guest_directory,
            version,
            apisets,
            registry: Default::default(),
            object_namespace: Default::default(),
            nls: None,
            appcompat: Default::default(),
            wnf_catalog: Default::default(),
            startup: None,
            gui: Default::default(),
            code_integrity: Err("native code integrity has not been captured".into()),
            policy_catalog: Err("native software policy has not been captured".into()),
            code_integrity_policy: Err("native code integrity policy has not been captured".into()),
            code_integrity_policies: Err(
                "native code integrity policies have not been captured".into()
            ),
            secure_boot_policy: Err("native secure boot policy has not been captured".into()),
        };
        let ntdll_path = runtime
            .dll("ntdll.dll")?
            .ok_or_else(|| invalid("installed NTDLL missing"))?;
        let mut ntdll_file = File::open(&ntdll_path)?;
        let ntdll = PeImage::parse(read_image_file(&mut ntdll_file)?)
            .map_err(|e| invalid(format!("installed NTDLL: {e}")))?;
        let projected_x64 = arch == WinArch::X64 && ntdll.headers().machine == 0xAA64;
        if WinArch::from_machine(ntdll.headers().machine) != Some(arch) && !projected_x64 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed NTDLL architecture does not match the guest",
            ));
        }
        runtime.code_integrity = system::capture();
        runtime.code_integrity_policy = code_integrity_policy::capture();
        runtime.code_integrity_policies = code_integrity_policies::capture();
        runtime.policy_catalog = super::policy::capture();
        runtime.registry = super::registry::snapshot()?;
        runtime.wnf_catalog = super::wnf::snapshot()?;
        let subject = runtime
            .wnf_catalog
            .primary_subject()
            .ok_or_else(|| invalid("native primary-token subject is not captured"))?;
        runtime.registry = super::registry::capture_primary_user(runtime.registry, &subject.user)?;
        let token_session = runtime
            .wnf_catalog
            .primary_token_session_id()
            .ok_or_else(|| invalid("native primary-token session is not captured"))?;
        runtime.object_namespace =
            super::object_namespace::snapshot(runtime.registry.upcase_table(), token_session)?;
        if arch == WinArch::Arm64
            && (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ) == (10, 0, 29708)
            && runtime.object_namespace.native_machine == Some(0xAA64)
        {
            runtime.object_namespace.policy_lookup_names =
                super::object_namespace::policy_lookup::capture(&subject).map(std::sync::Arc::new);
            runtime.object_namespace.privilege_display_names =
                super::security::privilege_names::capture().map(std::sync::Arc::new);
            #[cfg(windows)]
            runtime.object_namespace.capture_lsa_authentication_event();
        }
        if token_session == 1
            && arch == WinArch::Arm64
            && (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ) == (10, 0, 29708)
            && runtime.object_namespace.native_machine == Some(0xAA64)
        {
            runtime.object_namespace.activation_context =
                super::object_namespace::csr::activation::capture(&runtime)
                    .ok()
                    .flatten()
                    .map(std::sync::Arc::new);
        }
        if runtime.supports_secure_boot_policy(arch) {
            runtime.secure_boot_policy = secure_boot_policy::capture();
        }
        runtime.object_namespace.capture_cache_server(
            (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ),
            arch,
        )?;
        runtime.object_namespace.capture_security_device(
            (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ),
            arch,
        )?;
        if arch == WinArch::X86 {
            // SysWOW64 NTDLL and its pinned KnownDlls32 image select Windows'
            // pure x86 process profile. ARM64's default CHPE redirect would mix
            // that RTL with SyChpe32 dependencies requiring hybrid exports/code.
            // Keep the real host machine and WoW64 CPU information unchanged.
            runtime.object_namespace.select_wow_section_root(false)?;
        }
        if projected_x64 {
            let selected = runtime
                .installed_view(arch, &ntdll, &ntdll_path, &ntdll_file)?
                .ok_or_else(|| invalid("installed NTDLL requires an explicit AMD64 kernel view"))?;
            if selected.pe.headers().machine != arch.machine() {
                return Err(invalid(
                    "installed NTDLL projection does not match the guest",
                ));
            }
        }
        runtime.nls = Some(super::nls::snapshot(
            &runtime.registry,
            &schema_directory,
            &runtime.version,
            runtime.object_namespace.native_machine,
            arch,
        )?);
        runtime.appcompat =
            super::appcompat::Catalog::snapshot(&root, runtime.registry.upcase_table())?;
        #[cfg(windows)]
        if matches!(
            (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
                runtime.version.product_type,
                runtime.object_namespace.native_machine,
                arch,
            ),
            (
                10,
                0,
                20348 | 26100,
                3,
                Some(0x8664),
                WinArch::X64 | WinArch::X86
            ) | (10, 0, 26200, 1, Some(0xaa64), WinArch::Arm64 | WinArch::X86)
        ) {
            runtime.appcompat = runtime.appcompat.with_native_lookup(&root)?;
        }
        runtime.gui = runtime.select_gui(arch, token_session, &schema_directory);
        Ok(runtime)
    }

    fn select_gui(
        &self,
        arch: WinArch,
        session: u32,
        native_directory: &Path,
    ) -> super::gui::Availability {
        use super::gui::Availability;
        let (user, win32u) = match (self.dll("user32.dll"), self.dll("win32u.dll")) {
            (Ok(Some(user)), Ok(Some(win32u))) => (user, win32u),
            (Err(error), _) | (_, Err(error)) => {
                return Availability::Unavailable(error.to_string());
            }
            _ => {
                return Availability::Unavailable(
                    "selected USER32/Win32u runtime is absent".into(),
                );
            }
        };
        if self.uses_legacy_gdi_init(arch) {
            let gdi32 = match self.dll("gdi32.dll") {
                Ok(Some(path)) => path,
                Ok(None) => {
                    return Availability::Unavailable("selected GDI32 runtime is absent".into());
                }
                Err(error) => return Availability::Unavailable(error.to_string()),
            };
            return Availability::select(arch, user, win32u, Some(gdi32));
        }
        let Some(profile) = wow64_gui::Profile::select(
            arch,
            self.object_namespace.native_machine,
            &self.version,
            session,
        ) else {
            return Availability::select(arch, user, win32u, None);
        };
        let (user, win32u, legacy_gdi32) = match profile.libraries(&user, &win32u, native_directory)
        {
            Ok(pair) => pair,
            Err(error) => return Availability::Unavailable(error.to_string()),
        };
        let availability = Availability::select(profile.native_arch, user, win32u, legacy_gdi32);
        let Availability::Available(inputs) = availability else {
            return availability;
        };
        match inputs.qualify_wow64_companion(profile.native_arch) {
            Ok(()) => Availability::Wow64Companion(inputs, profile.gdi),
            Err(error) => Availability::Unavailable(error.to_string()),
        }
    }

    pub(crate) fn dll(&self, name: &str) -> io::Result<Option<PathBuf>> {
        Ok(self.dll_paths(name)?.map(|(_, canonical)| canonical))
    }

    /// The original basename spelling and its confined canonical target.
    /// Metadata queries retain the spelling so OBJ_DONT_REPARSE still sees a
    /// filesystem link. Image loading continues to use the canonical target.
    pub(crate) fn dll_paths(&self, name: &str) -> io::Result<Option<(PathBuf, PathBuf)>> {
        if name.is_empty() || name.contains(['\\', '/', ':', '\0']) || name == "." || name == ".." {
            return Err(invalid("native DLL selection requires a basename"));
        }
        let Some(path) = super::fs::find_case_insensitive(&self.directory, name) else {
            return Ok(None);
        };
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&self.directory) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed DLL escapes its selected directory",
            ));
        }
        Ok(Some((path, canonical)))
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
        let guest = if arch == native || native == WinArch::Arm64 && arch == WinArch::X64 {
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
            crate::host::time::system_now()
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
    fn installed_api_set_revisions_match_native_windows_loader_resolution() {
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
        for (name, numeric_control) in [
            ("api-ms-win-core-rtlsupport-l1-1-0.dll", true),
            ("api-ms-win-core-rtlsupport-l1-1-1.dll", true),
            ("api-ms-win-core-rtlsupport-l1-1-65535.dll", true),
            ("api-ms-win-core-rtlsupport-l1-1-4294967296.dll", false),
            ("api-ms-win-core-rtlsupport-l1-1-banana.dll", false),
            ("api-ms-win-core-rtlsupport-l1-1-0abc.dll", false),
            ("api-ms-win-core-rtlsupport-l1-1-_.dll", false),
            ("api-ms-win-core-rtlsupport-l1-1-.dll", false),
            ("api-ms-win-core-rtlsupport-l1-1-0-0.dll", false),
            ("api-ms-win-core-rtlsupport-l65535-65535-0.dll", false),
        ] {
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            // SAFETY: the UTF-16 name is terminated and retained for this call,
            // the reserved file handle is null, and 0x800 limits search to the
            // system directory. The resulting loader reference is released below.
            let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x800) };
            let guest = runtime.apisets.host(name, None);
            if module.is_null() {
                assert_eq!(guest, None, "native loader refused {name}");
                assert!(
                    !numeric_control,
                    "native loader refused the numeric control {name}"
                );
                continue;
            }
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
            assert_eq!(guest, Some("ntdll.dll"), "{name}");
        }
    }
}
