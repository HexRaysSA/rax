//! Well-known privilege names and an owned display-language snapshot.

use std::collections::BTreeMap;

// The low LUID components for the privileges in MS-LSAD §3.1.1.2.1.
// These names are ASCII and the high components are all zero.
const PRIVILEGE_NAMES: &[&str] = &[
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
];

pub(crate) fn value(name: &str) -> Option<u32> {
    PRIVILEGE_NAMES
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(name))
        .map(|position| position as u32 + 2)
}

pub(crate) fn name(low: u32, high: u32) -> Option<&'static str> {
    if high != 0 {
        return None;
    }
    let index = low.checked_sub(2)? as usize;
    PRIVILEGE_NAMES.get(index).copied()
}

#[derive(Debug)]
pub(crate) struct DisplayName {
    pub(crate) units: Vec<u16>,
    pub(crate) language: u16,
}

#[derive(Debug)]
pub(crate) struct DisplayCatalog {
    pub(crate) requested: [u16; 2],
    pub(crate) names: BTreeMap<u32, DisplayName>,
}

impl DisplayCatalog {
    pub(crate) fn get(&self, value: u32, requested: [u16; 2]) -> Option<&DisplayName> {
        let name = self.names.get(&value)?;
        // Once the requested language is available, the fallback does not affect the result.
        let matches = requested == self.requested
            || requested[0] == self.requested[0] && requested[0] == name.language;
        matches.then_some(name)
    }
}

#[cfg(windows)]
mod installed {
    use super::{DisplayCatalog, DisplayName, PRIVILEGE_NAMES};

    const MAX_DISPLAY_UNITS: usize = 512;
    const PRIMARY_LANGUAGE_MASK: u16 = 0x03ff;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetThreadUILanguage() -> u16;
        fn GetSystemDefaultUILanguage() -> u16;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn LookupPrivilegeDisplayNameW(
            system: *const u16,
            name: *const u16,
            display: *mut u16,
            count: *mut u32,
            language: *mut u32,
        ) -> i32;
    }

    pub(super) fn capture() -> Option<DisplayCatalog> {
        // SAFETY: These read the current thread and system UI language preferences.
        let (client, system) = unsafe { (GetThreadUILanguage(), GetSystemDefaultUILanguage()) };
        if client == 0 || system == 0 {
            return None;
        }
        let fallback = if client == system {
            system & PRIMARY_LANGUAGE_MASK
        } else {
            system
        };
        let names = PRIVILEGE_NAMES
            .iter()
            .enumerate()
            .filter_map(|(index, name)| {
                capture_name(name).map(|display| (index as u32 + 2, display))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        (!names.is_empty()).then_some(DisplayCatalog {
            requested: [client, fallback],
            names,
        })
    }

    fn capture_name(name: &str) -> Option<DisplayName> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut text = [0; MAX_DISPLAY_UNITS];
        let mut count = text.len() as u32;
        let mut language = 0;
        // SAFETY: The name comes from the fixed table and is NUL-terminated.
        // The bounded text array and both scalar outputs are independent and writable.
        let ok = unsafe {
            LookupPrivilegeDisplayNameW(
                std::ptr::null(),
                name.as_ptr(),
                text.as_mut_ptr(),
                &mut count,
                &mut language,
            )
        };
        let length = count as usize;
        if ok == 0 || length == 0 || length >= text.len() || text[length] != 0 {
            return None;
        }
        let units = &text[..length];
        let language = u16::try_from(language).ok()?;
        if units.contains(&0) || language == 0 {
            return None;
        }
        Some(DisplayName {
            units: units.to_vec(),
            language,
        })
    }
}

pub(crate) fn capture() -> Option<DisplayCatalog> {
    #[cfg(windows)]
    {
        installed::capture()
    }
    #[cfg(not(windows))]
    {
        None
    }
}
