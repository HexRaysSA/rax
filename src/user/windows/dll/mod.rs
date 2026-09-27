//! Built-in DLL registry. Unimplemented exports are loader errors rather than
//! fabricated successful operations.

pub mod crt;
pub(crate) mod fibers;
mod files;
pub(crate) mod fls;
mod handles;
mod kernel;
pub(crate) mod libraries;
mod locks;
mod native;
mod threading;

use super::hle::Export;

pub(crate) use files::finish_close;

/// A synthetic PE DLL and its export tables.
pub struct BuiltinDll {
    /// Case-folded import name.
    pub name: &'static str,
    /// Loader display name.
    pub display: &'static str,
    /// PE subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI).
    pub subsystem: u16,
    /// Named export tables; the first occurrence of a name takes precedence.
    pub exports: &'static [&'static [Export]],
}

impl std::fmt::Debug for BuiltinDll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltinDll")
            .field("name", &self.name)
            .finish()
    }
}

static NTDLL: BuiltinDll = BuiltinDll {
    name: "ntdll.dll",
    display: "ntdll.dll",
    subsystem: 3,
    exports: &[native::EXPORTS],
};
static KERNEL32: BuiltinDll = BuiltinDll {
    name: "kernel32.dll",
    display: "KERNEL32.DLL",
    subsystem: 3,
    exports: &[
        kernel::EXPORTS,
        libraries::EXPORTS,
        fibers::EXPORTS,
        fls::EXPORTS,
        handles::EXPORTS,
        threading::EXPORTS,
        locks::EXPORTS,
        files::EXPORTS,
    ],
};
static KERNELBASE: BuiltinDll = BuiltinDll {
    name: "kernelbase.dll",
    display: "KERNELBASE.dll",
    subsystem: 3,
    exports: &[
        kernel::EXPORTS,
        libraries::EXPORTS,
        fibers::EXPORTS,
        fls::EXPORTS,
        handles::EXPORTS,
        threading::EXPORTS,
        locks::EXPORTS,
        files::EXPORTS,
    ],
};
static MSVCRT: BuiltinDll = BuiltinDll {
    name: "msvcrt.dll",
    display: "msvcrt.dll",
    subsystem: 3,
    exports: &[
        crt::ALLOCATION_EXPORTS,
        crt::STATE_EXPORTS,
        crt::MEMORY_EXPORTS,
        crt::STRING_EXPORTS,
    ],
};
static UCRTBASE: BuiltinDll = BuiltinDll {
    name: "ucrtbase.dll",
    display: "ucrtbase.dll",
    subsystem: 3,
    exports: &[
        crt::ALLOCATION_EXPORTS,
        crt::STATE_EXPORTS,
        crt::UCRT_STATE_EXPORTS,
        crt::MEMORY_EXPORTS,
        crt::STRING_EXPORTS,
        crt::UCRT_STRING_EXPORTS,
    ],
};
static VCRUNTIME140: BuiltinDll = BuiltinDll {
    name: "vcruntime140.dll",
    display: "VCRUNTIME140.dll",
    subsystem: 3,
    exports: &[crt::VCRUNTIME_MEMORY_EXPORTS, crt::VCRUNTIME_STRING_EXPORTS],
};

/// Initializes data exports. Current built-ins contain only function exports.
pub fn init_data_exports(_: &mut super::process::Proc, _: usize) {}

/// Finds a built-in DLL by case-folded import name.
pub fn find(name: &str) -> Option<&'static BuiltinDll> {
    match name {
        "ntdll.dll" => Some(&NTDLL),
        "kernel32.dll" => Some(&KERNEL32),
        "kernelbase.dll" => Some(&KERNELBASE),
        "msvcrt.dll" => Some(&MSVCRT),
        "ucrtbase.dll" => Some(&UCRTBASE),
        "vcruntime140.dll" => Some(&VCRUNTIME140),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;

    #[test]
    fn builtin_tables_have_no_shadowed_architecture_specific_exports() {
        for dll in [
            &NTDLL,
            &KERNEL32,
            &KERNELBASE,
            &MSVCRT,
            &UCRTBASE,
            &VCRUNTIME140,
        ] {
            for arch in WinArch::ALL {
                let mut names = std::collections::HashSet::new();
                for export in dll.exports.iter().flat_map(|table| table.iter()) {
                    if export.archs.has(arch) {
                        assert!(
                            names.insert(export.name),
                            "{} {:?}: {}",
                            dll.name,
                            arch,
                            export.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn crt_hosts_are_distinct_and_exports_use_cdecl() {
        use crate::user::windows::hle::{Conv, Item};
        assert!(!std::ptr::eq(
            find("msvcrt.dll").unwrap(),
            find("ucrtbase.dll").unwrap()
        ));
        for dll in [&MSVCRT, &UCRTBASE] {
            assert!(dll.exports.iter().map(|t| t.len()).sum::<usize>() > 30);
            for export in dll.exports.iter().flat_map(|table| table.iter()) {
                if let Item::Func(api) = &export.item {
                    assert_eq!(api.conv, Conv::Cdecl, "{} {}", dll.name, export.name);
                }
            }
            assert!(
                !dll.exports
                    .iter()
                    .flat_map(|t| t.iter())
                    .any(|e| e.name == "printf")
            );
        }
        assert!(
            UCRTBASE
                .exports
                .iter()
                .flat_map(|t| t.iter())
                .any(|e| e.name == "_get_errno")
        );
        assert!(
            !MSVCRT
                .exports
                .iter()
                .flat_map(|t| t.iter())
                .any(|e| e.name == "_get_errno")
        );
        for name in ["strnlen", "wcsnlen"] {
            assert!(
                UCRTBASE
                    .exports
                    .iter()
                    .flat_map(|t| t.iter())
                    .any(|e| e.name == name)
            );
            assert!(
                !MSVCRT
                    .exports
                    .iter()
                    .flat_map(|t| t.iter())
                    .any(|e| e.name == name)
            );
        }
        for dll in [&MSVCRT, &UCRTBASE, &VCRUNTIME140] {
            assert!(
                !dll.exports
                    .iter()
                    .flat_map(|t| t.iter())
                    .any(|e| e.name.starts_with("wmem"))
            );
        }
        let names: std::collections::HashSet<_> = VCRUNTIME140
            .exports
            .iter()
            .flat_map(|t| t.iter())
            .map(|e| e.name)
            .collect();
        assert_eq!(names.len(), 11);
        assert!(names.contains("memcpy") && names.contains("wcschr"));
        assert!(!names.contains("__CxxFrameHandler3"));
    }
}
