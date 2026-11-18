//! Service identity for the native loader's executable SEC_IMAGE view of Win32u.

use std::fs::File;
use std::sync::Arc;

use super::{ServiceTable, stub_number};
use crate::user::image::pe::{PeImage, hybrid::CodeKind};
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::memory::VirtualMemory;
use crate::user::windows::native::{NativeRuntime, read_image_file};
use crate::user::windows::object_namespace::ImageSection;

const MAX_MAPPED_IMAGE_BYTES: u32 = 64 << 20;

pub(crate) struct MappedWin32u {
    known: Option<Arc<ImageSection>>,
    file: Option<SelectedFile>,
    services: ServiceTable,
}

struct SelectedFile {
    _file: File,
    identity: FileIdentity,
}

impl MappedWin32u {
    pub(crate) fn select(runtime: &NativeRuntime, arch: WinArch) -> Option<Self> {
        // The ARM64 SVC is the first instruction in the measured export.
        // The x64 and WoW64 transitions have different entry geometry.
        if arch != WinArch::Arm64 {
            return None;
        }
        let path = runtime.dll("win32u.dll").ok()??;
        let mut file = File::open(&path).ok()?;
        let identity = FileIdentity::of_open(&path, Some(&file), &file.metadata().ok()?).ok()?;
        let pe = PeImage::parse(read_image_file(&mut file).ok()?).ok()?;
        if pe.headers().machine != arch.machine() || pe.mapped_size() > MAX_MAPPED_IMAGE_BYTES {
            return None;
        }
        let services = ServiceTable::from_image(arch, &pe).ok()??;
        let name: Vec<_> = "\\KnownDlls\\win32u.dll".encode_utf16().collect();
        let known = runtime
            .object_namespace
            .lookup_section(None, &name, 0x40, false)
            .ok();
        Some(Self {
            known,
            file: Some(SelectedFile {
                _file: file,
                identity,
            }),
            services,
        })
    }

    /// One lookup each in the selected exports and live image allocations,
    /// followed by an 8-byte instruction fetch.
    pub(crate) fn name(
        &self,
        vm: &VirtualMemory,
        arch: WinArch,
        number: u32,
        pc: u64,
    ) -> Option<&str> {
        if arch != WinArch::Arm64 || pc % 4 != 0 {
            return None;
        }
        let entry = self.services.entries.get(&number)?;
        let view = vm.section_view(pc)?;
        if !self
            .known
            .as_ref()
            .is_some_and(|known| Arc::ptr_eq(known, &view.section))
            && !self
                .file
                .as_ref()
                .is_some_and(|file| view.section.file_identity() == Some(&file.identity))
        {
            return None;
        }
        let within = pc.checked_sub(view.image_base)?;
        if within.checked_add(8)? > view.size
            || view.offset.checked_add(within)? != u64::from(entry.rva)
            || view.code_kind(pc) != Some(CodeKind::Arm64)
        {
            return None;
        }
        let mut bytes = [0; 8];
        vm.space().fetch(pc, &mut bytes).ok()?;
        (stub_number(arch, &bytes) == Some(number)).then_some(entry.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::dll;
    use crate::user::windows::loader::builtin::{self, BuiltinSym};
    use crate::user::windows::memory::{Mem, mem, prot};
    use crate::user::windows::object_namespace::{ImageRegion, ImageTemplate};

    #[test]
    fn mapped_win32u_requires_the_selected_live_executable_view_and_exact_leaf() {
        let arch = WinArch::Arm64;
        let preferred = 0x2000_0000;
        let number = 0x1308;
        let mut image = builtin::build(dll::find("ntdll.dll").unwrap(), arch, preferred, &[]);
        let (_, BuiltinSym::Rva(entry)) = image
            .symbols
            .iter()
            .find(|(name, _)| *name == "NtClose")
            .unwrap()
        else {
            panic!("missing fixture export");
        };
        let entry = *entry as usize;
        let mut stub = [0; 8];
        stub[..4].copy_from_slice(&(0xD400_0001u32 | (number << 5)).to_le_bytes());
        stub[4..].copy_from_slice(&0xD65F_03C0u32.to_le_bytes());
        image.bytes[entry..entry + 8].copy_from_slice(&stub);
        image.bytes[entry + 8..entry + 16].copy_from_slice(&stub);
        let pe = PeImage::parse(image.bytes).unwrap();
        let services = ServiceTable::from_image(arch, &pe).unwrap().unwrap();
        let bytes = pe.memory_image();
        let size = bytes.len() as u64;
        let image = ImageTemplate::selected(
            bytes,
            vec![ImageRegion {
                offset: 0,
                size,
                state: mem::COMMIT,
                protection: prot::EXECUTE_WRITECOPY,
            }],
        )
        .unwrap();
        let selected = ImageSection::with_test_image(image.clone());
        let unrelated = ImageSection::with_test_image(image.clone());
        let binding = MappedWin32u {
            known: Some(selected.clone()),
            file: None,
            services,
        };
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space.clone(), 0x1_0000, 1 << 32);
        let other = preferred + 0x100_0000;
        vm.map_section_image(
            selected.clone(),
            &image,
            preferred,
            preferred,
            size,
            0,
            size,
            false,
            false,
        )
        .unwrap();
        vm.map_section_image(
            unrelated.clone(),
            &image,
            other,
            other,
            size,
            0,
            size,
            false,
            false,
        )
        .unwrap();
        let pc = preferred + entry as u64;
        assert_eq!(binding.name(&vm, arch, number, pc), Some("NtClose"));
        for address in [pc + 4, pc + 8, other + entry as u64, 0x10_0000] {
            assert_eq!(binding.name(&vm, arch, number, address), None);
        }
        assert_eq!(binding.name(&vm, WinArch::X64, number, pc), None);
        assert_eq!(binding.name(&vm, arch, number + 1, pc), None);

        let code_page = pc & !0xfff;
        vm.protect(code_page, 0x1000, prot::EXECUTE).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), Some("NtClose"));
        vm.protect(code_page, 0x1000, prot::READONLY).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), None);
        vm.protect(code_page, 0x1000, prot::EXECUTE_WRITECOPY)
            .unwrap();
        space.w32(pc + 4, 0xD503_201F).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), None);

        vm.release(preferred).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), None);
        vm.map_section_image(
            unrelated, &image, preferred, preferred, size, 0, size, false, false,
        )
        .unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), None);
    }
}
