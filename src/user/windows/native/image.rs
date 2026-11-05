//! One pinned installed image view owns both metadata and mapped bytes.
use super::*;
use crate::user::windows::object_namespace::{ImageSection, ImageTemplate};
use std::sync::Arc;

pub(crate) struct SelectedImage {
    pub(crate) pe: PeImage,
    pub(crate) section: Arc<ImageSection>,
    pub(crate) template: Arc<ImageTemplate>,
}

impl NativeRuntime {
    pub(crate) fn installed_view(
        &self,
        arch: WinArch,
        file: &PeImage,
        path: &Path,
    ) -> io::Result<Option<SelectedImage>> {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Ok(None);
        };
        // Matching-architecture dependencies retain their file placement;
        // NTDLL additionally needs the captured native guard extensions.
        if !name.eq_ignore_ascii_case("ntdll.dll")
            && WinArch::from_machine(file.headers().machine) == Some(arch)
        {
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
        let section = self
            .object_namespace
            .lookup_section(None, &root.encode_utf16().collect::<Vec<_>>(), 0x40, false)
            .map_err(|error| invalid(format!("selected {name} section: {error:?}")))?;
        let template = section.image_for(arch)?;
        selected_view(file, arch, section, template)
    }
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
                let file = PeImage::parse(read_image(&path).unwrap()).unwrap();
                let selected = runtime.installed_view(arch, &file, &path).unwrap();
                let effective = selected.as_ref().map(|view| &view.pe).unwrap_or(&file);
                assert_eq!(effective.headers().machine, arch.machine(), "{arch} {name}");
                if file.headers().machine != arch.machine() {
                    let selected = selected.expect("a transformed machine requires a pinned view");
                    assert_eq!(selected.pe.bytes(), file.bytes());
                    assert_eq!(selected.pe.memory_image(), selected.template.bytes.as_ref());
                }
            }
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
