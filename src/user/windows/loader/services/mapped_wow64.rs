//! Bind measured private WoW64 services to their selected installed image.
use std::fs::File;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::user::windows::arch::WinArch;
use crate::user::windows::dll;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Api;
use crate::user::windows::memory::{Mem, VirtualMemory};
use crate::user::windows::native::{NativeRuntime, read_image_file};
use crate::user::windows::object_namespace::ImageSection;
use crate::user::windows::object_namespace::csr::BASE_NLS_BYTES;

const SERVICE: u32 = 0x300b;
const STUB: u64 = 0x1d_f110;
const PARENT: u32 = 0x16_3b9d;
const CSR_CHILD: u32 = 0x300e;
const CSR_CHILD_STUB: u64 = 0x1d_f140;
const CSR_CHILD_PARENT: u32 = 0x1a_2168;
const THUNK: u32 = 0x27_e160;
const OUTPUT: u32 = 0x2a_5eac;
const IMAGE_HASH: [u8; 32] = [
    0xe6, 0xd7, 0xd0, 0x90, 0xb7, 0x7f, 0x64, 0xc9, 0xe3, 0xa4, 0x09, 0xd9, 0x58, 0x51, 0x0c, 0x5b,
    0x80, 0x28, 0x5e, 0x46, 0xd1, 0xa4, 0x2a, 0x89, 0x77, 0x06, 0x93, 0xf2, 0x64, 0x77, 0xe3, 0x7a,
];

struct PrivateLeaf {
    number: u32,
    stub: u64,
    parent: u32,
    argument_bytes: u8,
    thunk: u32,
}

const NLS_LEAF: PrivateLeaf = PrivateLeaf {
    number: SERVICE,
    stub: STUB,
    parent: PARENT,
    argument_bytes: 8,
    thunk: THUNK,
};
const CHILD_LEAF: PrivateLeaf = PrivateLeaf {
    number: CSR_CHILD,
    stub: CSR_CHILD_STUB,
    parent: CSR_CHILD_PARENT,
    argument_bytes: 4,
    thunk: THUNK,
};

const USER_CONNECT: PrivateLeaf = PrivateLeaf {
    number: 0x2000,
    stub: 0x65_fa0,
    parent: 0x56_b35,
    argument_bytes: 16,
    thunk: 0xd_9b90,
};
const USER_CONNECT_INSIDE: u32 = 0xf_b98c;
const USER32_HASH: [u8; 32] = [
    0x0a, 0x3c, 0x35, 0x25, 0x23, 0x2a, 0x43, 0x09, 0x34, 0x0c, 0x4f, 0x30, 0x12, 0x69, 0x7d, 0x1b,
    0xa5, 0x43, 0x48, 0x4e, 0x66, 0x27, 0x7d, 0xca, 0x9e, 0x55, 0x44, 0xe2, 0xbd, 0xab, 0xc4, 0x43,
];

struct SelectedImage {
    known: Option<Arc<ImageSection>>,
    file: Option<(File, FileIdentity)>,
}

impl SelectedImage {
    fn select(
        runtime: &NativeRuntime,
        arch: WinArch,
        library: &str,
        hash: [u8; 32],
    ) -> Option<Self> {
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
        let path = runtime.dll(library).ok()??;
        let mut file = File::open(&path).ok()?;
        let identity = FileIdentity::of_open(&path, Some(&file), &file.metadata().ok()?).ok()?;
        let bytes = read_image_file(&mut file).ok()?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != hash {
            return None;
        }
        let name: Vec<_> = format!("\\KnownDlls32\\{library}").encode_utf16().collect();
        let known = runtime
            .object_namespace
            .lookup_section(None, &name, 0x40, false)
            .ok();
        Some(Self {
            known,
            file: Some((file, identity)),
        })
    }

    fn verify_leaf(
        &self,
        vm: &VirtualMemory,
        resume: u64,
        sp: u64,
        leaf: &PrivateLeaf,
    ) -> Option<(u32, u64)> {
        let view = vm.section_view(resume)?;
        if view.section.no_execute
            || view.offset != 0
            || resume.checked_sub(view.image_base)? != leaf.stub + 12
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
        let parent = base.checked_add(leaf.parent)?;
        let thunk = base.checked_add(leaf.thunk)?;
        let space = vm.space();
        let mut code = [0; 15];
        space.fetch(view.image_base + leaf.stub, &mut code).ok()?;
        let mut branch = [0; 5];
        space.fetch(u64::from(parent) - 5, &mut branch).ok()?;
        let displacement = (leaf.stub as i32 - leaf.parent as i32).to_le_bytes();
        if code[0] != 0xb8
            || code[1..5] != leaf.number.to_le_bytes()
            || code[5] != 0xba
            || code[6..10] != thunk.to_le_bytes()
            || code[10..] != [0xff, 0xd2, 0xc2, leaf.argument_bytes, 0]
            || branch[0] != 0xe8
            || branch[1..] != displacement
            || space.u32(sp).ok()? != parent
        {
            return None;
        }
        Some((base, view.size))
    }
}

pub(crate) struct MappedWow64KernelBase(SelectedImage);

impl MappedWow64KernelBase {
    pub(crate) fn select(runtime: &NativeRuntime, arch: WinArch) -> Option<Self> {
        SelectedImage::select(runtime, arch, "kernelbase.dll", IMAGE_HASH).map(Self)
    }

    pub(crate) fn api(
        &self,
        vm: &VirtualMemory,
        number: u32,
        resume: u64,
        sp: u64,
    ) -> Option<&'static Api> {
        match number {
            SERVICE => {
                let (base, size) = self.0.verify_leaf(vm, resume, sp, &NLS_LEAF)?;
                if size < u64::from(OUTPUT) + BASE_NLS_BYTES as u64 {
                    return None;
                }
                let output = base.checked_add(OUTPUT)?;
                let space = vm.space();
                (space.u32(sp.checked_add(4)?).ok()? == output
                    && space.u32(sp.checked_add(8)?).ok()? == BASE_NLS_BYTES as u32)
                    .then_some(&dll::WOW64_BASE_NLS)
            }
            CSR_CHILD => {
                self.0.verify_leaf(vm, resume, sp, &CHILD_LEAF)?;
                Some(&dll::WOW64_BASE_CREATE_PROCESS)
            }
            _ => None,
        }
    }
}

pub(crate) struct MappedWow64User32(SelectedImage);

impl MappedWow64User32 {
    pub(crate) fn select(runtime: &NativeRuntime, arch: WinArch) -> Option<Self> {
        SelectedImage::select(runtime, arch, "user32.dll", USER32_HASH).map(Self)
    }

    pub(crate) fn api(
        &self,
        vm: &VirtualMemory,
        number: u32,
        resume: u64,
        sp: u64,
    ) -> Option<&'static Api> {
        if number != USER_CONNECT.number {
            return None;
        }
        let (base, _) = self.0.verify_leaf(vm, resume, sp, &USER_CONNECT)?;
        let inside = base.checked_add(USER_CONNECT_INSIDE)?;
        (vm.space().u32(sp.checked_add(16)?).ok()? == inside).then_some(&dll::WOW64_USER_CONNECT)
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
    fn wow64_user_connect_requires_its_selected_image_caller_and_inside_flag() {
        const BASE: u32 = 0x2000_0000;
        const SIZE: u64 = 0x10_0000;
        let mut bytes = builtin::build(
            dll::find("ntdll.dll").unwrap(),
            WinArch::X86,
            u64::from(BASE),
            &[],
        )
        .bytes;
        bytes.resize(SIZE as usize, 0);
        let nt = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        bytes[nt + 80..nt + 84].copy_from_slice(&(SIZE as u32).to_le_bytes());
        let leaf = &USER_CONNECT;
        let stub = &mut bytes[leaf.stub as usize..leaf.stub as usize + 15];
        stub[..6].copy_from_slice(&[0xb8, 0, 0x20, 0, 0, 0xba]);
        stub[6..10].copy_from_slice(&(BASE + leaf.thunk).to_le_bytes());
        stub[10..].copy_from_slice(&[0xff, 0xd2, 0xc2, 16, 0]);
        let parent = leaf.parent as usize;
        bytes[parent - 5] = 0xe8;
        bytes[parent - 4..parent]
            .copy_from_slice(&(leaf.stub as i32 - leaf.parent as i32).to_le_bytes());
        let image = ImageTemplate::selected(
            bytes,
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
        let binding = MappedWow64User32(SelectedImage {
            known: Some(selected.clone()),
            file: None,
        });
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 8 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space.clone(), 0x10000, 1 << 32);
        let base = u64::from(BASE);
        vm.map_section_image(selected, &image, base, base, SIZE, 0, SIZE, false, false)
            .unwrap();
        let sp = base + SIZE - 24;
        let resume = base + leaf.stub + 12;
        space.w32(sp, BASE + leaf.parent).unwrap();
        space.w32(sp + 16, BASE + USER_CONNECT_INSIDE).unwrap();
        assert_eq!(
            binding.api(&vm, leaf.number, resume, sp).unwrap().name,
            "UserConnectToServer"
        );
        assert!(binding.api(&vm, leaf.number + 1, resume, sp).is_none());
        assert!(binding.api(&vm, leaf.number, resume + 1, sp).is_none());
        space.w32(sp + 16, BASE + USER_CONNECT_INSIDE + 1).unwrap();
        assert!(binding.api(&vm, leaf.number, resume, sp).is_none());
        space.w32(sp + 16, BASE + USER_CONNECT_INSIDE).unwrap();
        space.w32(sp, BASE + leaf.parent + 1).unwrap();
        assert!(binding.api(&vm, leaf.number, resume, sp).is_none());
        vm.release(base).unwrap();
        vm.map_section_image(unrelated, &image, base, base, SIZE, 0, SIZE, false, false)
            .unwrap();
        space.w32(sp, BASE + leaf.parent).unwrap();
        space.w32(sp + 16, BASE + USER_CONNECT_INSIDE).unwrap();
        assert!(binding.api(&vm, leaf.number, resume, sp).is_none());
    }

    #[test]
    fn wow64_kernelbase_requires_the_selected_image_and_exact_measured_call_sites() {
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
        let stub = &mut image[CSR_CHILD_STUB as usize..CSR_CHILD_STUB as usize + 15];
        stub[..6].copy_from_slice(&[0xb8, 0x0e, 0x30, 0, 0, 0xba]);
        stub[6..10].copy_from_slice(&(BASE + THUNK).to_le_bytes());
        stub[10..].copy_from_slice(&[0xff, 0xd2, 0xc2, 4, 0]);
        let parent = CSR_CHILD_PARENT as usize;
        image[parent - 5] = 0xe8;
        image[parent - 4..parent]
            .copy_from_slice(&(CSR_CHILD_STUB as i32 - CSR_CHILD_PARENT as i32).to_le_bytes());
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
        let binding = MappedWow64KernelBase(SelectedImage {
            known: Some(Arc::clone(&selected)),
            file: None,
        });
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
        let resume = base + STUB + 12;
        assert!(binding.api(&vm, SERVICE, resume, sp).is_some());
        assert!(binding.api(&vm, SERVICE - 1, resume, sp).is_none());
        assert!(binding.api(&vm, SERVICE, resume + 1, sp).is_none());
        for (offset, bad, correct) in [
            (0, BASE + PARENT + 1, BASE + PARENT),
            (4, BASE + OUTPUT + 1, BASE + OUTPUT),
            (8, BASE_NLS_BYTES as u32 - 1, BASE_NLS_BYTES as u32),
        ] {
            space.w32(sp + offset, bad).unwrap();
            assert!(binding.api(&vm, SERVICE, resume, sp).is_none());
            space.w32(sp + offset, correct).unwrap();
        }
        let child_resume = base + CSR_CHILD_STUB + 12;
        space.w32(sp, BASE + CSR_CHILD_PARENT).unwrap();
        assert_eq!(
            binding.api(&vm, CSR_CHILD, child_resume, sp).unwrap().name,
            "NtWow64CsrBasepCreateProcess2"
        );
        assert!(binding.api(&vm, SERVICE, child_resume, sp).is_none());
        assert!(binding.api(&vm, CSR_CHILD, resume, sp).is_none());
        space.w8(child_resume + 1, 8).unwrap();
        assert!(binding.api(&vm, CSR_CHILD, child_resume, sp).is_none());
        space.w32(sp, BASE + PARENT).unwrap();
        space.w8(resume, 0xc3).unwrap();
        assert!(binding.api(&vm, SERVICE, resume, sp).is_none());
        vm.release(base).unwrap();
        vm.map_section_image(unrelated, &image, base, base, SIZE, 0, SIZE, false, false)
            .unwrap();
        space.w32(sp, BASE + PARENT).unwrap();
        space.w32(sp + 4, BASE + OUTPUT).unwrap();
        space.w32(sp + 8, BASE_NLS_BYTES as u32).unwrap();
        assert!(binding.api(&vm, SERVICE, resume, sp).is_none());
        space.w32(sp, BASE + CSR_CHILD_PARENT).unwrap();
        assert!(binding.api(&vm, CSR_CHILD, child_resume, sp).is_none());
    }
}
