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
const STUB_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) struct ServiceTable {
    arch: WinArch,
    names: BTreeMap<u32, String>,
}

impl ServiceTable {
    pub(crate) fn from_image(arch: WinArch, pe: &PeImage) -> Result<Option<Self>, LoadError> {
        let image = pe.memory_image();
        Self::read(arch, &image, pe.headers().directory(dir::EXPORT))
    }

    fn read(arch: WinArch, image: &[u8], range: DataDirectory) -> Result<Option<Self>, LoadError> {
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
        Ok((!names.is_empty()).then_some(Self { arch, names }))
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
        // WoW64 transitions have a separate argument/transition contract.
        // Until that adapter is established they cannot enter the 64-bit ABI.
        WinArch::X86 => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::user::windows::{dll, loader::builtin};

    pub(crate) fn table(arch: WinArch, name: &str, number: u32) -> ServiceTable {
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
        )
        .unwrap()
        .unwrap()
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
            matches!(ServiceTable::read(arch, &image.bytes, range), Err(error) if error.status == STATUS_INVALID_IMAGE_FORMAT && error.message.contains("conflicting exports"))
        );
        let count = range.rva as usize + 24;
        image.bytes[count..count + 4].copy_from_slice(&(MAX_EXPORTS + 1).to_le_bytes());
        assert!(
            matches!(ServiceTable::read(arch, &image.bytes, range), Err(error) if error.status == STATUS_INVALID_IMAGE_FORMAT)
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
