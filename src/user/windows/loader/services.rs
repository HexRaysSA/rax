//! NT service numbers decoded from the selected NTDLL image, never a build table.
//!
//! Only complete, recognized leaf stubs are admitted. Hooked/forwarded exports
//! and unknown encodings cannot select an unrelated kernel operation.

use std::collections::BTreeMap;

use super::LoadError;
use crate::user::image::pe::exports::{ExportDirectory, ExportTarget};
use crate::user::image::pe::{DataDirectory, PeImage, dir};
use crate::user::windows::arch::WinArch;
use crate::user::windows::nt::status::STATUS_INVALID_IMAGE_FORMAT;

const MAX_EXPORTS: u32 = 1 << 16;
const STUB_BYTES: usize = 64;

#[derive(Debug)]
pub(crate) struct ServiceTable {
    arch: WinArch,
    names: BTreeMap<u32, String>,
    pub(crate) wow64_slot: Option<u32>,
}

impl ServiceTable {
    pub(crate) fn from_image(arch: WinArch, pe: &PeImage) -> Result<Option<Self>, LoadError> {
        let image = pe.memory_image();
        Self::read(
            arch,
            &image,
            pe.headers().directory(dir::EXPORT),
            pe.headers().image_base,
        )
    }

    fn read(
        arch: WinArch,
        image: &[u8],
        range: DataDirectory,
        preferred: u64,
    ) -> Result<Option<Self>, LoadError> {
        let malformed = || {
            LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "malformed NTDLL service exports",
            )
        };
        let Some(exports) = ExportDirectory::read(image, range).map_err(|_| malformed())? else {
            return Ok(None);
        };
        if exports.number_of_names > MAX_EXPORTS || exports.number_of_functions > MAX_EXPORTS {
            return Err(malformed());
        }
        let wow64_slot = if arch == WinArch::X86 {
            match exports
                .by_name(image, b"Wow64Transition", None)
                .map_err(|_| malformed())?
            {
                Some((_, ExportTarget::Rva(rva)))
                    if (rva as usize)
                        .checked_add(4)
                        .is_some_and(|end| end <= image.len()) =>
                {
                    Some(rva)
                }
                _ => None,
            }
        } else {
            None
        };
        let mut names = BTreeMap::new();
        for i in 0..exports.number_of_names {
            let name = exports
                .name_at(image, i)
                .map_err(|_| malformed())?
                .ok_or_else(malformed)?;
            // Nt/Zw aliases share a number. Only the canonical Nt spelling is
            // retained; Rtl userland helpers are never classified as services.
            if !name.starts_with(b"Nt") || !name.get(2).is_some_and(u8::is_ascii_uppercase) {
                continue;
            }
            let index = exports.ordinal_at(image, i).map_err(|_| malformed())?;
            let Some(ExportTarget::Rva(rva)) = exports
                .by_index(image, u32::from(index))
                .map_err(|_| malformed())?
            else {
                continue;
            };
            let start = rva as usize;
            let Some(bytes) = image.get(start..start.saturating_add(STUB_BYTES).min(image.len()))
            else {
                return Err(malformed());
            };
            let Some(number) = stub_number(arch, bytes) else {
                continue;
            };
            if arch == WinArch::X86 {
                let Some(slot) = wow64_slot else { continue };
                let Some(entry) = x86_entry(bytes) else {
                    continue;
                };
                if entry
                    .conditional_base
                    .is_some_and(|base| u64::from(base) != preferred)
                {
                    continue;
                }
                let Some(thunk) = u64::from(entry.thunk)
                    .checked_sub(preferred)
                    .and_then(|rva| usize::try_from(rva).ok())
                else {
                    continue;
                };
                let Some(code) = image.get(thunk..thunk.saturating_add(6)) else {
                    continue;
                };
                if code[..2] != [0xFF, 0x25]
                    || u64::from(u32::from_le_bytes(
                        code[2..6].try_into().map_err(|_| malformed())?,
                    )) != preferred + u64::from(slot)
                {
                    continue;
                }
            }
            let name = String::from_utf8(name).map_err(|_| malformed())?;
            if let Some(previous) = names.insert(number, name.clone())
                && previous != name
            {
                return Err(LoadError::new(
                    STATUS_INVALID_IMAGE_FORMAT,
                    format!(
                        "NTDLL service {number:#x} has conflicting exports {previous} and {name}"
                    ),
                ));
            }
        }
        Ok((!names.is_empty()).then_some(Self {
            arch,
            names,
            wow64_slot,
        }))
    }

    pub(crate) fn name(&self, arch: WinArch, number: u32) -> Option<&str> {
        (self.arch == arch)
            .then(|| self.names.get(&number).map(String::as_str))
            .flatten()
    }
}

fn stub_number(arch: WinArch, bytes: &[u8]) -> Option<u32> {
    match arch {
        WinArch::Arm64 => {
            let svc = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            let ret = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
            (svc & 0xFFE0_001F == 0xD400_0001 && ret == 0xD65F_03C0).then_some((svc >> 5) & 0xFFFF)
        }
        WinArch::X64 => {
            let bytes = bytes
                .strip_prefix(&[0xF3, 0x0F, 0x1E, 0xFA])
                .unwrap_or(bytes);
            if bytes.get(..4)? != [0x4C, 0x8B, 0xD1, 0xB8] {
                return None;
            }
            let number = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
            let tail = bytes.get(8..)?;
            // Direct SYSCALL leaf, or the KUSER_SHARED_DATA test selecting
            // SYSCALL versus INT 2E. No arbitrary branch scanning is used.
            (tail.starts_with(&[0x0F, 0x05, 0xC3])
                || tail.starts_with(&[
                    0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3,
                    0xCD, 0x2E, 0xC3,
                ]))
            .then_some(number)
        }
        WinArch::X86 => {
            if bytes.first()? != &0xB8 || x86_entry(bytes).is_none() {
                return None;
            }
            Some(u32::from_le_bytes(bytes.get(1..5)?.try_into().ok()?))
        }
    }
}

struct X86Entry {
    thunk: u32,
    conditional_base: Option<u32>,
}

fn x86_entry(bytes: &[u8]) -> Option<X86Entry> {
    // Installed WoW64 leaf: MOV EAX, encoded service; MOV EDX, thunk;
    // CALL EDX; RET imm16. High service bits encode WoW64 marshaling and
    // remain part of identity rather than being masked to 16 bits.
    let tail = bytes.get(5..)?;
    if tail.first()? == &0xBA && tail.get(5..8)? == [0xFF, 0xD2, 0xC2] && tail.len() >= 10 {
        return Some(X86Entry {
            thunk: u32::from_le_bytes(tail[1..5].try_into().ok()?),
            conditional_base: None,
        });
    }
    // Installed conditional leaf: CALL $+5; POP EDX; compare the high byte
    // of its relocatable image-base marker; then CALL FS:[0xC0] or the same
    // exported transition thunk. Both branches must have identical RET imm16.
    // No arbitrary branch scan, TEB offset, or alternative transport is admitted.
    let code = bytes.get(..41)?;
    if code[5..14] != [0xE8, 0, 0, 0, 0, 0x5A, 0x80, 0x7A, 0x14]
        || code[15..25] != [0x75, 0x0E, 0x64, 0xFF, 0x15, 0xC0, 0, 0, 0, 0xC2]
        || code[31] != 0xBA
        || code[36..39] != [0xFF, 0xD2, 0xC2]
        || code[25..27] != code[39..41]
        || code[14] != code[30]
    {
        return None;
    }
    Some(X86Entry {
        thunk: u32::from_le_bytes(code[32..36].try_into().ok()?),
        conditional_base: Some(u32::from_le_bytes(code[27..31].try_into().ok()?)),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::user::windows::{dll, loader::builtin};

    pub(crate) fn table(arch: WinArch, name: &str, number: u32) -> ServiceTable {
        if arch == WinArch::X86 {
            return x86_image_table(name, number).0;
        }
        let mut image = builtin::build(dll::find("ntdll.dll").unwrap(), arch, 0x1000_0000, &[]);
        let rva = image
            .symbols
            .iter()
            .find_map(|(n, s)| (*n == name).then_some(s))
            .unwrap();
        let builtin::BuiltinSym::Rva(rva) = *rva else {
            panic!("forwarded service")
        };
        let code = if arch == WinArch::Arm64 {
            [
                (0xD400_0001 | (number << 5)).to_le_bytes(),
                0xD65F_03C0u32.to_le_bytes(),
            ]
            .concat()
        } else {
            [
                vec![0x4C, 0x8B, 0xD1, 0xB8],
                number.to_le_bytes().to_vec(),
                vec![0x0F, 0x05, 0xC3],
            ]
            .concat()
        };
        image.bytes[rva as usize..rva as usize + code.len()].copy_from_slice(&code);
        ServiceTable::read(
            arch,
            &image.bytes,
            DataDirectory {
                rva: image.export_dir.0,
                size: image.export_dir.1,
            },
            0x1000_0000,
        )
        .unwrap()
        .unwrap()
    }

    fn x86_image_table(name: &str, number: u32) -> (ServiceTable, Vec<u8>) {
        let mut image = vec![0u8; 0x400];
        for (offset, value) in [
            (0x110, 1u32),
            (0x114, 2),
            (0x118, 2),
            (0x11c, 0x160),
            (0x120, 0x180),
            (0x124, 0x1a0),
            (0x160, 0x200),
            (0x164, 0x300),
            (0x180, 0x1b0),
            (0x184, 0x1e0),
        ] {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        image[0x1a2..0x1a4].copy_from_slice(&1u16.to_le_bytes());
        image[0x1b0..0x1b0 + name.len()].copy_from_slice(name.as_bytes());
        image[0x1e0..0x1e0 + 15].copy_from_slice(b"Wow64Transition");
        let stub = [
            vec![0xb8],
            number.to_le_bytes().to_vec(),
            vec![0xba],
            0x10000240u32.to_le_bytes().to_vec(),
            vec![0xff, 0xd2, 0xc2, 4, 0],
        ]
        .concat();
        image[0x200..0x200 + stub.len()].copy_from_slice(&stub);
        image[0x240..0x246]
            .copy_from_slice(&[vec![0xff, 0x25], 0x10000300u32.to_le_bytes().to_vec()].concat());
        let table = ServiceTable::read(
            WinArch::X86,
            &image,
            DataDirectory {
                rva: 0x100,
                size: 40,
            },
            0x10000000,
        )
        .unwrap()
        .unwrap();
        (table, image)
    }

    #[test]
    fn wow64_preserves_encoded_numbers_and_requires_the_exported_transition_thunk() {
        let (table, mut image) = x86_image_table("NtClose", 0x0003000f);
        assert_eq!(table.name(WinArch::X86, 0x0003000f), Some("NtClose"));
        assert_eq!(table.name(WinArch::X86, 15), None);
        assert_eq!(table.wow64_slot, Some(0x300));
        for n in 0..15 {
            assert!(stub_number(WinArch::X86, &image[0x200..0x200 + n]).is_none());
        }
        image[0x242..0x246].copy_from_slice(&0x10000304u32.to_le_bytes());
        assert!(
            ServiceTable::read(
                WinArch::X86,
                &image,
                DataDirectory {
                    rva: 0x100,
                    size: 40
                },
                0x10000000
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn conditional_wow64_leaf_requires_complete_matching_branches_marker_and_thunk() {
        let (_, mut image) = x86_image_table("NtQueryInformationProcess", 0x19);
        let code = [
            vec![0xB8],
            0x19u32.to_le_bytes().to_vec(),
            vec![
                0xE8, 0, 0, 0, 0, 0x5A, 0x80, 0x7A, 0x14, 0x10, 0x75, 0x0E, 0x64, 0xFF, 0x15, 0xC0,
                0, 0, 0, 0xC2, 20, 0,
            ],
            0x1000_0000u32.to_le_bytes().to_vec(),
            vec![0xBA],
            0x1000_0240u32.to_le_bytes().to_vec(),
            vec![0xFF, 0xD2, 0xC2, 20, 0],
        ]
        .concat();
        assert_eq!(code.len(), 41);
        image[0x200..0x200 + code.len()].copy_from_slice(&code);
        let read = |image: &[u8], preferred| {
            ServiceTable::read(
                WinArch::X86,
                image,
                DataDirectory {
                    rva: 0x100,
                    size: 40,
                },
                preferred,
            )
            .unwrap()
        };
        let table = read(&image, 0x1000_0000).unwrap();
        assert_eq!(
            table.name(WinArch::X86, 0x19),
            Some("NtQueryInformationProcess")
        );
        assert_eq!(table.wow64_slot, Some(0x300));
        for end in 0..41 {
            assert!(stub_number(WinArch::X86, &code[..end]).is_none());
        }
        for at in [
            0, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            30, 31, 36, 37, 38, 39, 40,
        ] {
            let mut bad = image.clone();
            bad[0x200 + at] ^= 1;
            assert!(
                read(&bad, 0x1000_0000).is_none(),
                "changed instruction/cleanup byte {at}"
            );
        }
        for at in [27, 28, 29] {
            let mut bad = image.clone();
            bad[0x200 + at] ^= 1;
            assert!(
                read(&bad, 0x1000_0000).is_none(),
                "changed image marker byte {at}"
            );
        }
        let mut bad = image.clone();
        bad[0x242..0x246].copy_from_slice(&0x1000_0304u32.to_le_bytes());
        assert!(
            read(&bad, 0x1000_0000).is_none(),
            "fallback must use exported transition slot"
        );
        assert!(
            read(&image, 0x2000_0000).is_none(),
            "marker must name this image base"
        );
    }

    #[test]
    fn derives_export_identity_and_number_from_selected_image() {
        for arch in [WinArch::Arm64, WinArch::X64] {
            for number in [0, 15, 0x37, 0xFFFF] {
                let table = table(arch, "NtClose", number);
                assert_eq!(table.name(arch, number), Some("NtClose"));
                assert_eq!(table.name(arch, number + 1), None);
                assert_eq!(table.name(WinArch::X86, number), None);
            }
        }
    }

    #[test]
    fn refuses_partial_hooked_or_unrecognized_stubs() {
        let a64 = [0xE1, 0x01, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6];
        assert_eq!(stub_number(WinArch::Arm64, &a64), Some(15));
        for n in 0..a64.len() {
            assert_eq!(stub_number(WinArch::Arm64, &a64[..n]), None);
        }
        assert_eq!(
            stub_number(WinArch::Arm64, &[0x01, 0, 0, 0x14, 0xC0, 0x03, 0x5F, 0xD6]),
            None
        );
        assert_eq!(stub_number(WinArch::X64, &[0xE9, 0, 0, 0, 0]), None);
        assert_eq!(stub_number(WinArch::X86, &a64), None);
    }

    #[test]
    fn conflicting_numbers_and_oversized_export_tables_are_rejected() {
        let arch = WinArch::Arm64;
        let mut image = builtin::build(dll::find("ntdll.dll").unwrap(), arch, 0x1000_0000, &[]);
        let range = DataDirectory {
            rva: image.export_dir.0,
            size: image.export_dir.1,
        };
        let stub = [0xD400_01E1u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat();
        for name in ["NtClose", "NtAllocateVirtualMemory"] {
            let rva = image
                .symbols
                .iter()
                .find_map(|(n, s)| (*n == name).then_some(s))
                .unwrap();
            let builtin::BuiltinSym::Rva(rva) = *rva else {
                panic!("forwarded service")
            };
            image.bytes[rva as usize..rva as usize + stub.len()].copy_from_slice(&stub);
        }
        assert!(
            matches!(ServiceTable::read(arch, &image.bytes, range, 0x1000_0000), Err(error) if error.status == STATUS_INVALID_IMAGE_FORMAT && error.message.contains("conflicting exports"))
        );
        let count = range.rva as usize + 24;
        image.bytes[count..count + 4].copy_from_slice(&(MAX_EXPORTS + 1).to_le_bytes());
        assert!(
            matches!(ServiceTable::read(arch, &image.bytes, range, 0x1000_0000), Err(error) if error.status == STATUS_INVALID_IMAGE_FORMAT)
        );
    }

    #[cfg(windows)]
    #[test]
    fn installed_ntdll_exports_define_the_native_service_table() {
        let root =
            std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("Windows SystemRoot"));
        let pe = PeImage::parse(std::fs::read(root.join("System32").join("ntdll.dll")).unwrap())
            .unwrap();
        let arch = WinArch::from_machine(pe.headers().machine).expect("native NTDLL architecture");
        let table = ServiceTable::from_image(arch, &pe)
            .unwrap()
            .expect("installed NTDLL service stubs");
        for name in [
            "NtClose",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtTerminateProcess",
        ] {
            assert!(
                table.names.values().any(|found| found == name),
                "missing installed {name}"
            );
        }
    }
}
