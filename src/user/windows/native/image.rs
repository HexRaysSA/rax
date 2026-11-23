//! One pinned installed image view owns both metadata and mapped bytes.
use super::*;
use crate::user::windows::object_namespace::{ImageSection, ImageTemplate};
#[cfg(windows)]
use crate::user::windows::{
    fs::{FileIdentity, FileLifetime},
    nt::status::STATUS_OBJECT_NAME_NOT_FOUND,
    object_namespace::{LookupError, file_image},
};
use std::sync::Arc;

pub(crate) struct SelectedImage {
    pub(crate) pe: PeImage,
    pub(crate) section: Arc<ImageSection>,
    pub(crate) template: Arc<ImageTemplate>,
}

/// Installed executables admitted by the closed child process profile.
pub(crate) fn selected_child_executable(basename: &str) -> bool {
    ["cmd.exe", "findstr.exe", "sort.exe"]
        .iter()
        .any(|name| basename.eq_ignore_ascii_case(name))
}

impl NativeRuntime {
    /// Find an installed backing file for a main image supplied as bytes.
    /// The exact bytes must match a file in the selected system directory.
    pub(crate) fn matching_executable(&self, guest_path: &str, image: &[u8]) -> Option<File> {
        let (_, mut file) = self.open_executable(guest_path).ok()??;
        same_image_bytes(&mut file, image).ok()?.then_some(file)
    }

    pub(crate) fn open_child_executable(
        &self,
        guest_path: &str,
    ) -> io::Result<Option<(PathBuf, File)>> {
        if !guest_path
            .rsplit_once('\\')
            .is_some_and(|(_, name)| selected_child_executable(name))
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.open_executable(guest_path)
    }

    /// Check the opened file too so a path replacement cannot escape the root.
    fn open_executable(&self, guest_path: &str) -> io::Result<Option<(PathBuf, File)>> {
        let Some((directory, basename)) = guest_path.rsplit_once('\\') else {
            return Ok(None);
        };
        if !directory.eq_ignore_ascii_case(self.guest_directory.trim_end_matches('\\')) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let Some(path) = self.dll(basename)? else {
            return Ok(None);
        };
        let scope = crate::user::windows::fs::FileNameOrigin::capture(&self.directory, Vec::new())?;
        let file = File::open(&path)?;
        scope
            .name(&file, &path)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
        Ok(Some((path, file)))
    }

    pub(crate) fn installed_view(
        &self,
        arch: WinArch,
        pe: &PeImage,
        path: &Path,
        file: &File,
    ) -> io::Result<Option<SelectedImage>> {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Ok(None);
        };
        // Matching-architecture dependencies retain their file placement;
        // NTDLL additionally needs the captured native guard extensions.
        let ntdll = name.eq_ignore_ascii_case("ntdll.dll");
        if !ntdll && WinArch::from_machine(pe.headers().machine) == Some(arch) {
            return Ok(None);
        }
        if self.dll(name)?.as_deref() != Some(path) {
            return Ok(None);
        }
        if arch == WinArch::X86 && self.object_namespace.native_machine.is_none() {
            return Ok(None);
        }
        let directory =
            if arch == WinArch::X86 && self.object_namespace.native_machine != Some(0x14C) {
                "\\KnownDlls32"
            } else {
                "\\KnownDlls"
            };
        let root = format!("{directory}\\{name}");
        #[cfg(not(windows))]
        let _ = file;
        let section = match self.object_namespace.lookup_section(
            None,
            &root.encode_utf16().collect::<Vec<_>>(),
            0x40,
            false,
        ) {
            Ok(section) => section,
            #[cfg(windows)]
            Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND))
                if !ntdll
                    && arch == WinArch::X64
                    && pe.headers().machine == WinArch::Arm64.machine()
                    && self.object_namespace.native_machine == Some(WinArch::Arm64.machine()) =>
            {
                // Windows can project an installed ARM64X DLL with no KnownDlls
                // entry. Use the same open file that supplied the parsed PE.
                installed_file_section(file)
                    .map_err(|error| invalid(format!("selected {name} file section: {error}")))?
            }
            Err(error) => return Err(invalid(format!("selected {name} section: {error:?}"))),
        };
        let template = section.image_for(arch)?;
        selected_view(pe, arch, section, template)
    }
}

fn same_image_bytes(file: &mut File, expected: &[u8]) -> io::Result<bool> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() != expected.len() as u64
        || metadata.len() > MAX_DLL_BYTES
    {
        return Ok(false);
    }
    let mut buffer = [0; 8192];
    for chunk in expected.chunks(buffer.len()) {
        let actual = &mut buffer[..chunk.len()];
        file.read_exact(actual)?;
        if actual != chunk {
            return Ok(false);
        }
    }
    Ok(file.read(&mut buffer[..1])? == 0)
}

#[cfg(windows)]
fn installed_file_section(file: &File) -> io::Result<Arc<ImageSection>> {
    let identity = FileIdentity::retained(file)?;
    let backing = file_image::acquire(file, 0, 2, 0x0100_0000, true)
        .map_err(|error| invalid(format!("{error:?}")))?;
    Ok(ImageSection::created(
        backing,
        Arc::new(FileLifetime::new(identity)),
        None,
    ))
}

fn selected_view(
    file: &PeImage,
    arch: WinArch,
    section: Arc<ImageSection>,
    template: Arc<ImageTemplate>,
) -> io::Result<Option<SelectedImage>> {
    if template.machine == file.headers().machine && template.extensions.iter().all(Option::is_none)
    {
        return Ok(None);
    }
    if WinArch::from_machine(template.machine) != Some(arch) {
        return Err(invalid(
            "selected kernel image view does not match the guest",
        ));
    }
    let source_machine = file.headers().machine;
    if source_machine != template.machine
        && !(source_machine == 0xAA64 && template.machine == 0x8664)
    {
        return Err(invalid(
            "unsupported installed source/view machine transformation",
        ));
    }
    let pe = file
        .with_mapped_view(template.bytes.clone())
        .map_err(|error| invalid(format!("selected installed projected metadata: {error}")))?;
    if section.size != u64::from(pe.mapped_size()) {
        return Err(invalid(
            "selected installed section and file extents disagree",
        ));
    }
    Ok(Some(SelectedImage {
        pe,
        section,
        template,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::object_namespace::ImageRegion;

    fn fixture() -> (PeImage, Arc<ImageTemplate>) {
        let file = PeImage::parse(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ))
            .to_vec(),
        )
        .unwrap();
        let mut bytes = file.memory_image();
        let at = file.headers().nt_offset as usize + 4;
        bytes[at..at + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        let size = bytes.len() as u64;
        let template = ImageTemplate::selected(
            bytes,
            vec![ImageRegion {
                offset: 0,
                size,
                state: mem::COMMIT,
                protection: prot::EXECUTE_READ,
            }],
        )
        .unwrap();
        (file, template)
    }

    #[test]
    fn kernel_projection_selects_metadata_without_relabeling_the_source_file() {
        let (file, template) = fixture();
        let selected = selected_view(
            &file,
            WinArch::X64,
            ImageSection::with_test_image(template.clone()),
            template.clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.pe.headers().machine, 0x8664);
        assert_eq!(file.headers().machine, 0xAA64);
        assert_eq!(selected.pe.bytes(), file.bytes());
        assert_eq!(selected.pe.memory_image(), template.bytes.as_ref());
        assert!(Arc::ptr_eq(&selected.template, &template));
    }

    #[cfg(windows)]
    #[test]
    fn installed_main_image_from_bytes_retains_its_backing_file() {
        use crate::user::windows::{WindowsConfig, WindowsProcess, mapped_filename::Filename};

        let arch = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let runtime = NativeRuntime::select(arch).unwrap();
        let guest = format!("{}\\cmd.exe", runtime.guest_directory);
        let installed = runtime.dll("cmd.exe").unwrap().unwrap();
        let mut image = read_image(&installed).unwrap();
        let expected = Filename::image(&File::open(installed).unwrap())
            .unwrap()
            .unwrap()
            .read()
            .unwrap();
        let mut config = WindowsConfig::embedded(&guest, vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        let process = WindowsProcess::spawn_image(config, image.clone()).unwrap();
        let p = process.state();
        assert_eq!(
            p.vm.mapped_filename(p.modules.exe().base).unwrap(),
            Some(expected)
        );

        for unrelated in ["C:\\app\\cmd.exe", "cmd.exe", "C:\\cmd.exe"] {
            assert!(runtime.matching_executable(unrelated, &image).is_none());
        }
        assert!(
            runtime
                .matching_executable(&format!("{guest}:stream"), &image)
                .is_none()
        );
        assert!(
            runtime
                .matching_executable(&guest, &image[..image.len() - 1])
                .is_none()
        );
        image[0] ^= 1;
        assert!(runtime.matching_executable(&guest, &image).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn installed_known_dependencies_select_the_requested_machine_from_one_file() {
        let host = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let arches = if host == WinArch::Arm64 {
            vec![host, WinArch::X64]
        } else {
            vec![host]
        };
        for arch in arches {
            let runtime = NativeRuntime::select(arch).unwrap();
            for name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
                let path = runtime.dll(name).unwrap().unwrap();
                let mut file = File::open(&path).unwrap();
                let pe = PeImage::parse(read_image_file(&mut file).unwrap()).unwrap();
                let selected = runtime.installed_view(arch, &pe, &path, &file).unwrap();
                let effective = selected.as_ref().map(|view| &view.pe).unwrap_or(&pe);
                assert_eq!(effective.headers().machine, arch.machine(), "{arch} {name}");
                if pe.headers().machine != arch.machine() {
                    let selected = selected.expect("a transformed machine requires a pinned view");
                    assert_eq!(selected.pe.bytes(), pe.bytes());
                    assert_eq!(selected.pe.memory_image(), selected.template.bytes.as_ref());
                }
            }
        }
    }

    #[cfg(all(windows, target_arch = "aarch64"))]
    #[test]
    fn installed_arm64x_vc_runtime_selects_amd64_from_its_retained_file() {
        let runtime = NativeRuntime::select(WinArch::X64).unwrap();
        let Some(path) = runtime.dll("vcruntime140.dll").unwrap() else {
            eprintln!("vcruntime140.dll is absent from the selected installation");
            return;
        };
        let mut file = File::open(&path).unwrap();
        let pe = PeImage::parse(read_image_file(&mut file).unwrap()).unwrap();
        let selected = runtime
            .installed_view(WinArch::X64, &pe, &path, &file)
            .unwrap();
        let effective = selected.as_ref().map(|view| &view.pe).unwrap_or(&pe);
        assert_eq!(effective.headers().machine, WinArch::X64.machine());
        if let Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)) =
            runtime.object_namespace.lookup_section(
                None,
                &"\\KnownDlls\\vcruntime140.dll"
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                0x40,
                false,
            )
            && pe.headers().machine == WinArch::Arm64.machine()
        {
            let selected = selected.expect("an ARM64X file requires an AMD64 kernel view");
            assert_eq!(
                selected.section.file_identity(),
                Some(&FileIdentity::retained(&file).unwrap()),
            );
            assert_eq!(selected.pe.bytes(), pe.bytes());
            assert_eq!(selected.pe.memory_image(), selected.template.bytes.as_ref());
        }
    }

    #[test]
    fn kernel_projection_rejects_wrong_guest_and_changed_file_identity() {
        let (file, template) = fixture();
        assert!(
            selected_view(
                &file,
                WinArch::Arm64,
                ImageSection::with_test_image(template.clone()),
                template.clone()
            )
            .is_err()
        );
        let mut bytes = template.bytes.to_vec();
        bytes[file.headers().nt_offset as usize + 8] ^= 1;
        let changed = ImageTemplate::selected(bytes, template.regions.clone()).unwrap();
        assert!(
            selected_view(
                &file,
                WinArch::X64,
                ImageSection::with_test_image(changed.clone()),
                changed
            )
            .is_err()
        );
    }
}
