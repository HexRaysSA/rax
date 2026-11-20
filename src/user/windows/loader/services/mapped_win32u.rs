//! Service identity for the native loader's executable SEC_IMAGE view of Win32u.

use std::fs::File;
use std::sync::Arc;

use super::{MAX_AMD64_LEAF_BYTES, ServiceTable, stub_number};
use crate::user::image::pe::{PeImage, hybrid::CodeKind};
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::memory::{Mem, VirtualMemory};
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
        let known_path = match arch {
            WinArch::Arm64 => "\\KnownDlls\\win32u.dll",
            WinArch::X86 => "\\KnownDlls32\\win32u.dll",
            WinArch::X64 if runtime.object_namespace.native_machine == Some(arch.machine()) => {
                "\\KnownDlls\\win32u.dll"
            }
            WinArch::X64 => return None,
        };
        let path = runtime.dll("win32u.dll").ok()??;
        let mut file = File::open(&path).ok()?;
        let identity = FileIdentity::of_open(&path, Some(&file), &file.metadata().ok()?).ok()?;
        let pe = PeImage::parse(read_image_file(&mut file).ok()?).ok()?;
        if pe.headers().machine != arch.machine() || pe.mapped_size() > MAX_MAPPED_IMAGE_BYTES {
            return None;
        }
        let services = ServiceTable::from_image(arch, &pe).ok()??;
        let name: Vec<_> = known_path.encode_utf16().collect();
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

    /// Match the exact service instruction in an executable view of the
    /// selected image, including the complete AMD64 leaf around SYSCALL.
    pub(crate) fn name(
        &self,
        vm: &VirtualMemory,
        arch: WinArch,
        number: u32,
        pc: u64,
    ) -> Option<&str> {
        if arch != self.services.arch || arch == WinArch::X86 {
            return None;
        }
        let entry = self.services.entries.get(&number)?;
        let view = vm.section_view(pc)?;
        if !self.matches_selected(&view.section) {
            return None;
        }
        let within = u64::from(entry.rva).checked_sub(view.offset)?;
        let start = view.image_base.checked_add(within)?;
        if let Some(leaf) = &entry.amd64 {
            if start.checked_add(leaf.syscall_offset as u64)? != pc
                || within.checked_add(leaf.len as u64)? > view.size
                || view.code_kind(pc) != Some(CodeKind::Amd64)
            {
                return None;
            }
            let mut bytes = [0; MAX_AMD64_LEAF_BYTES];
            vm.space().fetch(start, &mut bytes[..leaf.len]).ok()?;
            return (bytes == leaf.code).then_some(entry.name.as_str());
        }
        if pc != start
            || pc % 4 != 0
            || within.checked_add(8)? > view.size
            || view.code_kind(pc) != Some(CodeKind::Arm64)
        {
            return None;
        }
        let mut bytes = [0; 8];
        vm.space().fetch(pc, &mut bytes).ok()?;
        (stub_number(arch, &bytes) == Some(number)).then_some(entry.name.as_str())
    }

    /// Authenticate a direct WoW64 leaf from the guest loader's SEC_IMAGE view.
    /// The transition PC belongs to the emulator. The stacked return PC identifies
    /// the CALL in the image, including its original selector and return cleanup.
    pub(crate) fn wow64_name(
        &self,
        vm: &VirtualMemory,
        number: u32,
        transition: u64,
        resume: u64,
    ) -> Option<&str> {
        const CALL_END: u64 = 12;

        let entry = self.services.entries.get(&number)?;
        let leaf = entry.direct_wow64.as_ref()?;
        let view = vm.section_view(resume)?;
        if view.offset != 0 || !self.matches_selected(&view.section) {
            return None;
        }
        let within = |rva: u32, len: usize| {
            let rva = u64::from(rva);
            if rva.checked_add(len as u64)? > view.size {
                return None;
            }
            view.image_base.checked_add(rva)
        };
        let stub = within(entry.rva, leaf.len)?;
        if stub.checked_add(CALL_END)? != resume {
            return None;
        }
        let thunk = within(leaf.thunk_rva, 6)?;
        let slot = within(self.services.wow64_slot?, 4)?;
        let mut expected = leaf.code;
        expected[6..10].copy_from_slice(&u32::try_from(thunk).ok()?.to_le_bytes());
        let mut code = [0; 15];
        let mut jump = [0; 6];
        let space = vm.space();
        space.fetch(stub, &mut code[..leaf.len]).ok()?;
        space.fetch(thunk, &mut jump).ok()?;
        (code == expected
            && jump[..2] == [0xff, 0x25]
            && jump[2..] == u32::try_from(slot).ok()?.to_le_bytes()
            && u64::from(space.u32(slot).ok()?) == transition)
            .then_some(entry.name.as_str())
    }

    fn matches_selected(&self, section: &Arc<ImageSection>) -> bool {
        !section.no_execute
            && (self
                .known
                .as_ref()
                .is_some_and(|known| Arc::ptr_eq(known, section))
                || self
                    .file
                    .as_ref()
                    .is_some_and(|file| section.file_identity() == Some(&file.identity)))
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
    fn mapped_wow64_win32u_requires_the_relocated_direct_leaf_and_transition() {
        const NUMBER: u32 = 0x0001_1533;
        const BASE: u64 = 0x2100_0000;
        const OTHER: u64 = 0x2200_0000;
        const TRANSITION: u32 = 0x0015_0000;
        let (services, mut bytes) = super::super::tests::x86_image_table("NtClose", NUMBER);
        bytes.resize(0x1000, 0);
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&WinArch::X86.machine().to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[0x74..0x78].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        bytes[0x90..0x94].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x206..0x20a].copy_from_slice(&(BASE as u32 + 0x240).to_le_bytes());
        bytes[0x242..0x246].copy_from_slice(&(BASE as u32 + 0x300).to_le_bytes());
        bytes[0x300..0x304].copy_from_slice(&TRANSITION.to_le_bytes());
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
        for (section, base) in [(selected, BASE), (unrelated.clone(), OTHER)] {
            vm.map_section_image(section, &image, base, base, size, 0, size, false, false)
                .unwrap();
        }
        let check = |vm: &VirtualMemory, resume| {
            binding.wow64_name(vm, NUMBER, u64::from(TRANSITION), resume)
        };
        assert_eq!(check(&vm, BASE + 0x20c), Some("NtClose"));
        assert_eq!(check(&vm, BASE + 0x20b), None);
        assert_eq!(check(&vm, OTHER + 0x20c), None);
        assert_eq!(
            binding.wow64_name(&vm, NUMBER & 0xffff, u64::from(TRANSITION), BASE + 0x20c),
            None
        );
        assert_eq!(
            binding.wow64_name(&vm, NUMBER, u64::from(TRANSITION + 0x10), BASE + 0x20c),
            None
        );
        for offset in [0x201, 0x206, 0x20a, 0x20d, 0x240, 0x242, 0x300] {
            let original = space.u8(BASE + offset).unwrap();
            space.w8(BASE + offset, original ^ 1).unwrap();
            assert_eq!(check(&vm, BASE + 0x20c), None, "modified byte {offset:#x}");
            space.w8(BASE + offset, original).unwrap();
        }
        vm.protect(BASE, size, prot::READONLY).unwrap();
        assert_eq!(check(&vm, BASE + 0x20c), None);
        vm.release(BASE).unwrap();
        assert_eq!(check(&vm, BASE + 0x20c), None);
        vm.map_section_image(unrelated, &image, BASE, BASE, size, 0, size, false, false)
            .unwrap();
        assert_eq!(check(&vm, BASE + 0x20c), None);
    }

    #[test]
    fn mapped_arm64_win32u_requires_the_selected_executable_leaf() {
        let number = 0x1308u32;
        let mut stub = [0; 8];
        stub[..4].copy_from_slice(&(0xD400_0001u32 | (number << 5)).to_le_bytes());
        stub[4..].copy_from_slice(&0xD65F_03C0u32.to_le_bytes());
        assert_mapped_leaf(WinArch::Arm64, number, &stub, 0);
    }

    #[test]
    fn mapped_amd64_win32u_requires_the_selected_executable_leaf_and_syscall_offset() {
        let number = 0x12e8u32;
        for prefix in [b"".as_slice(), &[0xF3, 0x0F, 0x1E, 0xFA]] {
            for (syscall, tail) in [
                (8, &[0x0F, 0x05, 0xC3][..]),
                (
                    18,
                    &[
                        0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05,
                        0xC3, 0xCD, 0x2E, 0xC3,
                    ][..],
                ),
            ] {
                let stub = [
                    prefix,
                    &[0x4C, 0x8B, 0xD1, 0xB8],
                    &number.to_le_bytes(),
                    tail,
                ]
                .concat();
                assert_mapped_leaf(WinArch::X64, number, &stub, prefix.len() + syscall);
            }
        }
    }

    fn assert_mapped_leaf(arch: WinArch, number: u32, stub: &[u8], syscall: usize) {
        let preferred = 0x2000_0000;
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
        image.bytes[entry..entry + stub.len()].copy_from_slice(stub);
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
        let start = preferred + entry as u64;
        let pc = start + syscall as u64;
        assert_eq!(binding.name(&vm, arch, number, pc), Some("NtClose"));
        for address in [
            pc + 1,
            pc + 2,
            pc + 4,
            other + entry as u64 + syscall as u64,
            0x10_0000,
        ] {
            assert_eq!(binding.name(&vm, arch, number, address), None);
        }
        if syscall != 0 {
            assert_eq!(binding.name(&vm, arch, number, start), None);
        }
        let other_arch = if arch == WinArch::Arm64 {
            WinArch::X64
        } else {
            WinArch::Arm64
        };
        assert_eq!(binding.name(&vm, other_arch, number, pc), None);
        assert_eq!(binding.name(&vm, arch, number + 1, pc), None);

        let code_page = pc & !0xfff;
        vm.protect(code_page, 0x1000, prot::EXECUTE).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), Some("NtClose"));
        vm.protect(code_page, 0x1000, prot::READONLY).unwrap();
        assert_eq!(binding.name(&vm, arch, number, pc), None);
        vm.protect(code_page, 0x1000, prot::EXECUTE_WRITECOPY)
            .unwrap();
        space.w8(start + stub.len() as u64 - 1, 0x90).unwrap();
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
