//! Built-in DLL registry. Unimplemented exports are loader errors rather than
//! fabricated successful operations.

pub mod crt;
pub(crate) mod fibers;
mod files;
pub(crate) mod fls;
mod function_table;
mod handles;
mod kernel;
pub(crate) mod libraries;
mod locks;
mod native;
mod slist;
mod sysinfo;
mod threading;

use super::hle::Export;

pub(crate) use files::finish_close;
pub(crate) use sysinfo::processor_feature_present;

/// Kernel services share the existing NT implementations, never Rtl helpers.
pub(crate) fn nt_service(
    name: &str,
    arch: super::arch::WinArch,
) -> Option<&'static super::hle::Api> {
    native::EXPORTS.iter().find_map(|export| {
        if export.name == name
            && export.name.starts_with("Nt")
            && export.archs.has(arch)
            && let super::hle::Item::Func(api) = &export.item
        {
            Some(api)
        } else {
            None
        }
    })
}

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
    exports: &[native::EXPORTS, slist::NTDLL_EXPORTS],
};
static KERNEL32: BuiltinDll = BuiltinDll {
    name: "kernel32.dll",
    display: "KERNEL32.DLL",
    subsystem: 3,
    exports: &[
        kernel::EXPORTS,
        function_table::EXPORTS,
        kernel::X86_SEH_EXPORTS,
        libraries::EXPORTS,
        fibers::EXPORTS,
        fls::EXPORTS,
        handles::EXPORTS,
        threading::EXPORTS,
        locks::EXPORTS,
        files::EXPORTS,
        kernel::VCH_EXPORTS,
        slist::KERNEL_FORWARDS,
        sysinfo::EXPORTS,
        sysinfo::KERNEL32_FORWARDS,
    ],
};
static KERNELBASE: BuiltinDll = BuiltinDll {
    name: "kernelbase.dll",
    display: "KERNELBASE.dll",
    subsystem: 3,
    exports: &[
        kernel::EXPORTS,
        function_table::EXPORTS,
        libraries::EXPORTS,
        fibers::EXPORTS,
        fls::EXPORTS,
        handles::EXPORTS,
        threading::EXPORTS,
        locks::EXPORTS,
        files::EXPORTS,
        kernel::VCH_EXPORTS,
        slist::KERNEL_FORWARDS,
        sysinfo::EXPORTS,
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
        crt::INIT_EXPORTS,
        crt::MSVCRT_INIT_EXPORTS,
        crt::MSVCRT_STARTUP_EXPORTS,
        crt::STDIO_EXPORTS,
        crt::MSVCRT_STDIO_EXPORTS,
        crt::NEW_HANDLER_EXPORTS,
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
        crt::INIT_EXPORTS,
        crt::UCRT_INIT_EXPORTS,
        crt::UCRT_STARTUP_EXPORTS,
        crt::UCRT_BOOTSTRAP_EXPORTS,
        crt::UCRT_ONEXIT_EXPORTS,
        crt::UCRT_REGISTRATION_EXPORTS,
        crt::UCRT_EXIT_EXPORTS,
        crt::UCRT_FATAL_EXPORTS,
        crt::UCRT_SIGNAL_EXPORTS,
        crt::STDIO_EXPORTS,
        crt::UCRT_STDIO_EXPORTS,
        crt::UCRT_EXCEPTION_FILTER_EXPORTS,
        crt::NEW_HANDLER_EXPORTS,
    ],
};
static VCRUNTIME140: BuiltinDll = BuiltinDll {
    name: "vcruntime140.dll",
    display: "VCRUNTIME140.dll",
    subsystem: 3,
    exports: &[crt::VCRUNTIME_MEMORY_EXPORTS, crt::VCRUNTIME_STRING_EXPORTS],
};

/// Legacy compatibility hook; it has always performed no initialization.
///
/// Built-in data is now initialized transactionally by the loader before
/// publication. This retained public function does not repeat or bypass that
/// transaction, and calling it after loading leaves guest-owned cells intact.
#[deprecated(note = "built-in data initialization is owned by the loader transaction")]
pub fn init_data_exports(_: &mut super::process::Proc, _: usize) {}

/// Unpublished, loader-local ownership of a built-in's initialized data.
/// Successful CRT storage belongs to the process, not a native importer's
/// dynamic load journal. Failure before publication must abort this receipt.
pub(crate) enum PreparedDataExports {
    None,
    Crt {
        startup: crt::startup::PreparedStartup,
        stdio: crt::stdio::PreparedStdio,
    },
}

impl PreparedDataExports {
    /// Commits only host ownership after all fallible loader links succeed.
    pub(crate) fn commit(self, p: &mut super::process::Proc) {
        match self {
            Self::None => {}
            Self::Crt { startup, stdio } => {
                startup.commit(p);
                stdio.commit(p);
            }
        }
    }

    /// Releases unpublished storage without consulting guest pointer cells.
    pub(crate) fn abort(
        self,
        p: &mut super::process::Proc,
    ) -> Result<(), super::loader::LoadError> {
        match self {
            Self::None => Ok(()),
            Self::Crt { startup, stdio } => {
                // Attempt both releases even if one detects invalid ownership.
                let a = stdio.abort(p);
                let b = startup.abort(p);
                a.and(b)
            }
        }
    }
}

/// Prepares data after image mapping, before module/LDR/trap publication.
/// The CRT preparer owns cleanup of partial work when returning an error.
pub(crate) fn prepare_data_exports(
    p: &mut super::process::Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, super::loader::builtin::BuiltinSym)],
) -> Result<PreparedDataExports, super::loader::LoadError> {
    match dll.name {
        "msvcrt.dll" | "ucrtbase.dll" => {
            let startup = crt::startup::prepare(p, dll, base, symbols)?;
            match crt::stdio::prepare(p, dll, base, symbols) {
                Ok(stdio) => Ok(PreparedDataExports::Crt { startup, stdio }),
                Err(error) => {
                    if let Err(cleanup) = startup.abort(p) {
                        p.fail(format!(
                            "CRT startup rollback: {cleanup:?}; original: {error:?}"
                        ));
                    }
                    Err(error)
                }
            }
        }
        _ => Ok(PreparedDataExports::None),
    }
}

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

    /// Every forwarder names a built-in DLL that exports a function by that
    /// name on each architecture the forwarder exists on.
    #[test]
    fn builtin_forwarders_resolve_to_builtin_functions() {
        use crate::user::windows::hle::Item;
        let mut checked = 0;
        for dll in [
            &NTDLL,
            &KERNEL32,
            &KERNELBASE,
            &MSVCRT,
            &UCRTBASE,
            &VCRUNTIME140,
        ] {
            for export in dll.exports.iter().flat_map(|table| table.iter()) {
                let Item::Forward(to) = export.item else {
                    continue;
                };
                let (module, symbol) = to.split_once('.').expect("MODULE.Symbol");
                let target = find(&format!("{}.dll", module.to_ascii_lowercase()))
                    .unwrap_or_else(|| panic!("{}: {} forwards to a missing DLL", dll.name, to));
                for arch in WinArch::ALL {
                    if !export.archs.has(arch) {
                        continue;
                    }
                    let found = target.exports.iter().flat_map(|t| t.iter()).any(|e| {
                        e.name == symbol && e.archs.has(arch) && matches!(e.item, Item::Func(_))
                    });
                    assert!(
                        found,
                        "{} {arch:?}: {} -> {to} dangles",
                        dll.name, export.name
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 0);
    }

    /// A KERNEL32 forwarder binds to the NTDLL function itself, as
    /// GetProcAddress does on Windows.
    #[test]
    fn kernel32_forwarders_bind_to_the_ntdll_addresses() {
        use crate::user::windows::loader::{self, SymRef};
        use crate::user::windows::process::{WindowsConfig, WindowsProcess};
        let mut config = WindowsConfig::new("forward-test.exe", vec![]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(
            config,
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe").to_vec(),
        )
        .unwrap();
        let p = process.state_mut();
        let kernel32 = loader::load_dll(p, "kernel32.dll").unwrap();
        let ntdll = loader::load_dll(p, "ntdll.dll").unwrap();
        let mut address = |module: usize, name: &str| {
            loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap_or_else(|| panic!("{name} is not exported"))
        };
        for (kernel_name, ntdll_name) in [
            ("RtlCaptureContext", "RtlCaptureContext"),
            ("InitializeSListHead", "RtlInitializeSListHead"),
            ("InterlockedPopEntrySList", "RtlInterlockedPopEntrySList"),
        ] {
            assert_eq!(
                address(kernel32, kernel_name),
                address(ntdll, ntdll_name),
                "{kernel_name}"
            );
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

    #[test]
    fn initializer_admission_distinguishes_legacy_compatibility_from_ucrt_imports() {
        use crate::user::windows::hle::{Arg, Conv, Item};
        for arch in WinArch::ALL {
            for (dll, expected) in [
                (
                    &MSVCRT,
                    if arch == WinArch::Arm64 {
                        &["_initterm", "_initterm_e"][..]
                    } else {
                        &["_initterm"][..]
                    },
                ),
                (&UCRTBASE, &["_initterm", "_initterm_e"][..]),
                (&VCRUNTIME140, &[][..]),
            ] {
                let found: Vec<_> = dll
                    .exports
                    .iter()
                    .flat_map(|table| table.iter())
                    .filter(|export| export.archs.has(arch) && export.name.starts_with("_initterm"))
                    .map(|export| {
                        let Item::Func(api) = &export.item else {
                            panic!("initializer must be callable");
                        };
                        assert_eq!(api.conv, Conv::Cdecl);
                        assert_eq!(api.args, &[Arg::Ptr, Arg::Ptr]);
                        export.name
                    })
                    .collect();
                assert_eq!(found, expected, "{} {arch:?}", dll.name);
            }
        }
    }
}
