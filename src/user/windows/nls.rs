//! Immutable installed NLS section bytes and process-owned guest view lifetime.
//! Host mappings exist only during explicit native runtime acquisition.
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

pub(crate) const MAX_SECTION_BYTES: usize = 8 << 20;
const MAX_TOTAL_BYTES: usize = 64 << 20;
const MAX_SECTIONS: usize = 4102; // At most 4096 registry candidates plus 6 fixed tables.
mod initialize;
mod mui;

/// Finite qualification for initialization and query-only MUI snapshots.
/// Builds 29698, 29704 and 29708 bind the measured ARM64 kernel independently
/// of the guest ABI. Earlier profile admission retains its existing contract.
pub(crate) fn supports_startup_profile(
    version: &super::process::WinVersion,
    native_machine: Option<u16>,
) -> bool {
    version.major == 10
        && version.minor == 0
        && match version.build {
            29683 | 29695 => true,
            29698 | 29704 | 29708 => native_machine == Some(0xAA64),
            _ => false,
        }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MuiProfile {
    PartialClear,
    ProbeDestination,
}

/// Profile selection is shared by guest dispatch and installed acquisition.
pub(crate) fn mui_profile(
    version: &super::process::WinVersion,
    native_machine: Option<u16>,
    arch: super::arch::WinArch,
) -> Option<MuiProfile> {
    use super::arch::WinArch;

    match (
        version.major,
        version.minor,
        version.build,
        native_machine,
        arch,
    ) {
        (10, 0, 20348 | 26100, Some(0x8664), WinArch::X64)
        | (10, 0, 26200, Some(0xAA64), WinArch::Arm64) => Some(MuiProfile::ProbeDestination),
        _ if supports_startup_profile(version, native_machine) => Some(MuiProfile::PartialClear),
        _ => None,
    }
}

/// Initialization has independent controls for the installed AMD64 and ARM64 profiles.
pub(crate) fn supports_initialize_profile(
    version: &super::process::WinVersion,
    native_machine: Option<u16>,
    arch: super::arch::WinArch,
) -> bool {
    use super::arch::WinArch;

    supports_startup_profile(version, native_machine)
        || matches!(
            (
                version.major,
                version.minor,
                version.build,
                native_machine,
                arch
            ),
            (
                10,
                0,
                20348 | 26100,
                Some(0x8664),
                WinArch::X64 | WinArch::X86
            ) | (10, 0, 26200, Some(0xAA64), WinArch::Arm64 | WinArch::X86)
        )
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InstalledUiLanguage {
    pub(crate) id: u16,
    pub(crate) guard_before_write_access: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Nls {
    sections: BTreeMap<(u32, u32), Arc<[u8]>>,
    initialize: Option<initialize::Initialize>,
    mui: Option<Arc<[u8]>>,
    pub(crate) ui_language_commitment: Option<u32>,
    pub(crate) installed_ui_language: Option<InstalledUiLanguage>,
}
impl Nls {
    pub(crate) fn new(sections: Vec<((u32, u32), Vec<u8>)>) -> io::Result<Self> {
        if sections.len() > MAX_SECTIONS {
            return Err(invalid("too many installed NLS sections"));
        }
        let mut result = Self {
            sections: BTreeMap::new(),
            initialize: None,
            mui: None,
            ui_language_commitment: None,
            installed_ui_language: None,
        };
        let mut total = 0usize;
        for ((kind, data), mut bytes) in sections {
            if !matches!(kind, 11 | 12 | 14)
                || kind == 14 && data != 0
                || bytes.is_empty()
                || bytes.len() > MAX_SECTION_BYTES
            {
                return Err(invalid("invalid installed NLS section"));
            }
            let size = (bytes.len() + 4095) & !4095;
            total = total
                .checked_add(size)
                .ok_or_else(|| invalid("NLS size overflow"))?;
            if total > MAX_TOTAL_BYTES || result.sections.contains_key(&(kind, data)) {
                return Err(invalid("oversized or duplicate installed NLS sections"));
            }
            bytes.resize(size, 0);
            result.sections.insert((kind, data), Arc::from(bytes));
        }
        Ok(result)
    }
    pub(crate) fn section(&self, kind: u32, data: u32) -> Option<Arc<[u8]>> {
        self.sections
            .get(&(kind, if kind == 14 { 0 } else { data }))
            .cloned()
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(windows)]
#[path = "nls/installed.rs"]
mod installed;
#[cfg(windows)]
pub(crate) use installed::snapshot;
#[cfg(not(windows))]
pub(crate) fn snapshot(
    _: &super::registry::Registry,
    _: &std::path::Path,
    _: &super::process::WinVersion,
    _: Option<u16>,
    _: super::arch::WinArch,
) -> io::Result<Nls> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed NLS sections require Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amd64_nls_and_mui_profiles_bind_the_kernel_machine_and_process_view() {
        use super::super::arch::WinArch;
        for build in [20347, 20348, 20349, 26099, 26100, 26101] {
            for machine in [None, Some(0x14C), Some(0xAA64), Some(0x8664)] {
                for arch in WinArch::ALL {
                    let mut version = super::super::process::WinVersion {
                        major: 10,
                        minor: 0,
                        build,
                        ..Default::default()
                    };
                    let expected = matches!(build, 20348 | 26100)
                        && machine == Some(0x8664)
                        && arch != WinArch::Arm64;
                    assert_eq!(
                        supports_initialize_profile(&version, machine, arch),
                        expected
                    );
                    assert_eq!(
                        mui_profile(&version, machine, arch),
                        (expected && arch == WinArch::X64).then_some(MuiProfile::ProbeDestination)
                    );
                    assert!(
                        !supports_startup_profile(&version, machine),
                        "MUI admission is independent"
                    );
                    version.minor = 1;
                    assert!(!supports_initialize_profile(&version, machine, arch));
                    assert_eq!(mui_profile(&version, machine, arch), None);
                    version.minor = 0;
                    version.major = 11;
                    assert!(!supports_initialize_profile(&version, machine, arch));
                    assert_eq!(mui_profile(&version, machine, arch), None);
                }
            }
        }
    }

    #[test]
    fn arm64_26200_nls_and_mui_profiles_bind_the_kernel_machine_and_process_view() {
        use super::super::arch::WinArch;
        for (major, minor, build) in [
            (10, 0, 26199),
            (10, 0, 26200),
            (10, 0, 26201),
            (10, 1, 26200),
            (11, 0, 26200),
        ] {
            let version = super::super::process::WinVersion {
                major,
                minor,
                build,
                ..Default::default()
            };
            for machine in [None, Some(0x14C), Some(0x8664), Some(0xAA64)] {
                assert!(!supports_startup_profile(&version, machine));
                for arch in WinArch::ALL {
                    let kernel = (major, minor, build, machine) == (10, 0, 26200, Some(0xAA64));
                    assert_eq!(
                        supports_initialize_profile(&version, machine, arch),
                        kernel && matches!(arch, WinArch::Arm64 | WinArch::X86)
                    );
                    assert_eq!(
                        mui_profile(&version, machine, arch),
                        (kernel && arch == WinArch::Arm64).then_some(MuiProfile::ProbeDestination)
                    );
                }
            }
        }
    }

    #[test]
    fn startup_profile_admission_is_exact_and_independent_of_other_nt_profiles() {
        for (major, minor, build, expected) in [
            (10, 0, 29683, true),
            (10, 0, 29695, true),
            (10, 0, 29698, true),
            (10, 0, 29704, true),
            (10, 0, 29708, true),
            (10, 0, 29682, false),
            (10, 0, 29684, false),
            (10, 0, 29694, false),
            (10, 0, 29696, false),
            (10, 0, 29697, false),
            (10, 0, 29699, false),
            (10, 0, 29703, false),
            (10, 0, 29705, false),
            (10, 0, 29707, false),
            (10, 0, 29709, false),
            (10, 1, 29695, false),
            (11, 0, 29695, false),
            (10, 1, 29698, false),
            (11, 0, 29698, false),
            (10, 1, 29704, false),
            (11, 0, 29704, false),
            (10, 1, 29708, false),
            (11, 0, 29708, false),
        ] {
            let version = super::super::process::WinVersion {
                major,
                minor,
                build,
                ..Default::default()
            };
            for machine in [None, Some(0x14C), Some(0x8664), Some(0xAA64)] {
                let expected = expected
                    && (!matches!(build, 29698 | 29704 | 29708) || machine == Some(0xAA64));
                assert_eq!(supports_startup_profile(&version, machine), expected);
                for arch in super::super::arch::WinArch::ALL {
                    assert_eq!(
                        supports_initialize_profile(&version, machine, arch),
                        expected
                    );
                    assert_eq!(
                        mui_profile(&version, machine, arch),
                        expected.then_some(MuiProfile::PartialClear)
                    );
                }
            }
        }
    }

    #[test]
    fn native_nls_snapshot_bounds_identity_padding_and_shared_bytes() {
        let source = vec![0x53; 4097];
        let nls = Nls::new(vec![((11, 1252), source.clone()), ((14, 0), vec![0x74; 1])]).unwrap();
        let bytes = nls.section(11, 1252).unwrap();
        assert_eq!(bytes.len(), 8192);
        assert_eq!(&bytes[..4097], &source);
        assert!(bytes[4097..].iter().all(|&b| b == 0));
        let clone = nls.clone();
        assert!(Arc::ptr_eq(&bytes, &clone.section(11, 1252).unwrap()));
        assert!(Arc::ptr_eq(
            &nls.section(14, 0).unwrap(),
            &nls.section(14, u32::MAX).unwrap()
        ));
        assert!(nls.section(11, 437).is_none());
        for raw in [
            vec![((10, 0), vec![1])],
            vec![((14, 1), vec![1])],
            vec![((11, 0), Vec::new())],
            vec![((11, 0), vec![0; MAX_SECTION_BYTES + 1])],
            vec![((11, 1), vec![1]), ((11, 1), vec![2])],
        ] {
            assert!(Nls::new(raw).is_err());
        }
        assert!(
            Nls::new(
                (0..9)
                    .map(|n| ((11, n), vec![0; MAX_SECTION_BYTES]))
                    .collect()
            )
            .is_err()
        );
        assert!(
            Nls::new(
                (0..MAX_SECTIONS + 1)
                    .map(|n| ((11, n as u32), vec![0]))
                    .collect()
            )
            .is_err()
        );
    }
}
