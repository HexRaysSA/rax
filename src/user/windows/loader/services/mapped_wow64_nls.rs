//! Bind one private WoW64 BASE NLS service to the selected KernelBase view.
use std::fs::File;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::memory::{Mem, VirtualMemory};
use crate::user::windows::native::{NativeRuntime, read_image_file};
use crate::user::windows::object_namespace::ImageSection;
use crate::user::windows::object_namespace::csr::BASE_NLS_BYTES;

const SERVICE: u32 = 0x300b;
const STUB: u64 = 0x1d_f110;
const RESUME: u64 = STUB + 12;
const PARENT: u32 = 0x16_3b9d;
const THUNK: u32 = 0x27_e160;
const OUTPUT: u32 = 0x2a_5eac;
const IMAGE_HASH: [u8; 32] = [
    0xe6, 0xd7, 0xd0, 0x90, 0xb7, 0x7f, 0x64, 0xc9, 0xe3, 0xa4, 0x09, 0xd9, 0x58, 0x51, 0x0c, 0x5b,
    0x80, 0x28, 0x5e, 0x46, 0xd1, 0xa4, 0x2a, 0x89, 0x77, 0x06, 0x93, 0xf2, 0x64, 0x77, 0xe3, 0x7a,
];

pub(crate) struct MappedWow64Nls {
    known: Option<Arc<ImageSection>>,
    file: Option<(File, FileIdentity)>,
}

impl MappedWow64Nls {
    pub(crate) fn select(runtime: &NativeRuntime, arch: WinArch) -> Option<Self> {
        if arch != WinArch::X86
            || (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ) != (10, 0, 29708)
            || runtime.object_namespace.native_machine != Some(0xaa64)
        {
            return None;
        }
        let path = runtime.dll("kernelbase.dll").ok()??;
        let mut file = File::open(&path).ok()?;
        let identity = FileIdentity::of_open(&path, Some(&file), &file.metadata().ok()?).ok()?;
        let bytes = read_image_file(&mut file).ok()?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != IMAGE_HASH {
            return None;
        }
        let name: Vec<_> = "\\KnownDlls32\\kernelbase.dll".encode_utf16().collect();
        let known = runtime
            .object_namespace
            .lookup_section(None, &name, 0x40, false)
            .ok();
        Some(Self {
            known,
            file: Some((file, identity)),
        })
    }

    pub(crate) fn matches(&self, vm: &VirtualMemory, number: u32, resume: u64, sp: u64) -> bool {
        self.admit(vm, number, resume, sp).is_some()
    }

    fn admit(&self, vm: &VirtualMemory, number: u32, resume: u64, sp: u64) -> Option<()> {
        if number != SERVICE {
            return None;
        }
        let view = vm.section_view(resume)?;
        if view.section.no_execute
            || view.offset != 0
            || view.size < u64::from(OUTPUT) + BASE_NLS_BYTES as u64
            || resume.checked_sub(view.image_base)? != RESUME
        {
            return None;
        }
        if !self
            .known
            .as_ref()
            .is_some_and(|known| Arc::ptr_eq(known, &view.section))
            && !self
                .file
                .as_ref()
                .is_some_and(|(_, identity)| view.section.file_identity() == Some(identity))
        {
            return None;
        }
        let base = u32::try_from(view.image_base).ok()?;
        let parent = base.checked_add(PARENT)?;
        let output = base.checked_add(OUTPUT)?;
        let thunk = base.checked_add(THUNK)?;
        let space = vm.space();
        let mut leaf = [0; 15];
        space.fetch(view.image_base + STUB, &mut leaf).ok()?;
        let mut branch = [0; 5];
        space.fetch(u64::from(parent) - 5, &mut branch).ok()?;
        let displacement = (STUB as i32 - PARENT as i32).to_le_bytes();
        if leaf[..6] != [0xb8, 0x0b, 0x30, 0, 0, 0xba]
            || leaf[6..10] != thunk.to_le_bytes()
            || leaf[10..] != [0xff, 0xd2, 0xc2, 8, 0]
            || branch[0] != 0xe8
            || branch[1..] != displacement
            || space.u32(sp).ok()? != parent
            || space.u32(sp.checked_add(4)?).ok()? != output
            || space.u32(sp.checked_add(8)?).ok()? != BASE_NLS_BYTES as u32
        {
            return None;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::object_namespace::{ImageRegion, ImageTemplate};
    use crate::user::windows::{dll, loader::builtin};

    #[test]
    fn wow64_nls_requires_the_selected_image_exact_call_site_and_output() {
        const BASE: u32 = 0x2000_0000;
        const SIZE: u64 = 0x2f_8000;
        let mut image = builtin::build(
            dll::find("ntdll.dll").unwrap(),
            WinArch::X86,
            u64::from(BASE),
            &[],
        )
        .bytes;
        image.resize(SIZE as usize, 0);
        let nt = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
        image[nt + 80..nt + 84].copy_from_slice(&(SIZE as u32).to_le_bytes());
        let stub = &mut image[STUB as usize..STUB as usize + 15];
        stub[..6].copy_from_slice(&[0xb8, 0x0b, 0x30, 0, 0, 0xba]);
        stub[6..10].copy_from_slice(&(BASE + THUNK).to_le_bytes());
        stub[10..].copy_from_slice(&[0xff, 0xd2, 0xc2, 8, 0]);
        let parent = PARENT as usize;
        image[parent - 5] = 0xe8;
        image[parent - 4..parent].copy_from_slice(&(STUB as i32 - PARENT as i32).to_le_bytes());
        let image = ImageTemplate::selected(
            image,
            vec![ImageRegion {
                offset: 0,
                size: SIZE,
                state: mem::COMMIT,
                protection: prot::EXECUTE_WRITECOPY,
            }],
        )
        .unwrap();
        let selected = ImageSection::with_test_image(image.clone());
        let unrelated = ImageSection::with_test_image(image.clone());
        let binding = MappedWow64Nls {
            known: Some(Arc::clone(&selected)),
            file: None,
        };
        let base = u64::from(BASE);
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space.clone(), 0x10000, 1 << 32);
        vm.map_section_image(selected, &image, base, base, SIZE, 0, SIZE, false, false)
            .unwrap();
        let sp = base + SIZE - 12;
        space.w32(sp, BASE + PARENT).unwrap();
        space.w32(sp + 4, BASE + OUTPUT).unwrap();
        space.w32(sp + 8, BASE_NLS_BYTES as u32).unwrap();
        let resume = base + RESUME;
        assert!(binding.matches(&vm, SERVICE, resume, sp));
        assert!(!binding.matches(&vm, SERVICE - 1, resume, sp));
        assert!(!binding.matches(&vm, SERVICE, resume + 1, sp));
        for (offset, bad, correct) in [
            (0, BASE + PARENT + 1, BASE + PARENT),
            (4, BASE + OUTPUT + 1, BASE + OUTPUT),
            (8, BASE_NLS_BYTES as u32 - 1, BASE_NLS_BYTES as u32),
        ] {
            space.w32(sp + offset, bad).unwrap();
            assert!(!binding.matches(&vm, SERVICE, resume, sp));
            space.w32(sp + offset, correct).unwrap();
        }
        space.w8(resume, 0xc3).unwrap();
        assert!(!binding.matches(&vm, SERVICE, resume, sp));
        vm.release(base).unwrap();
        vm.map_section_image(unrelated, &image, base, base, SIZE, 0, SIZE, false, false)
            .unwrap();
        space.w32(sp, BASE + PARENT).unwrap();
        space.w32(sp + 4, BASE + OUTPUT).unwrap();
        space.w32(sp + 8, BASE_NLS_BYTES as u32).unwrap();
        assert!(!binding.matches(&vm, SERVICE, resume, sp));
    }
}
