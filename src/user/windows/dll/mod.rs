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

/// Initializes data exports. Current built-ins contain only function exports.
pub fn init_data_exports(_: &mut super::process::Proc, _: usize) {}

/// Finds a built-in DLL by case-folded import name.
pub fn find(name: &str) -> Option<&'static BuiltinDll> {
    match name {
        "ntdll.dll" => Some(&NTDLL),
        "kernel32.dll" => Some(&KERNEL32),
        "kernelbase.dll" => Some(&KERNELBASE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;

    #[test]
    fn builtin_tables_have_no_shadowed_architecture_specific_exports() {
        for dll in [&NTDLL, &KERNEL32, &KERNELBASE] {
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
}
