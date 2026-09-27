//! API set names (`api-ms-win-*`, `ext-ms-win-*`) and the DLLs that host
//! them. An API set is a contract name, not a file: the loader redirects
//! an import of one to the DLL implementing it, and API sets never appear
//! in the module list.
//!
//! This is the personality's host-selection profile, not a verified native
//! Windows schema. Exact CRT foundation contracts are named below. The existing
//! family-prefix fallback also redirects other versions/families; redirecting
//! a name does not establish that its exports or that native contract version
//! are implemented. Unknown exports retain explicit failure diagnostics.

/// CRT contracts exercised by the independently compiled foundation fixtures.
const CRT_FOUNDATION: &[&str] = &[
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-string-l1-1-0.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
];

/// Family prefixes and their host DLL; the first match wins.
const FAMILIES: &[(&str, &str)] = &[
    ("api-ms-win-crt-", "ucrtbase.dll"),
    ("api-ms-win-core-rtlsupport-", "ntdll.dll"),
    ("api-ms-win-core-kernel32-legacy-", "kernel32.dll"),
    ("api-ms-win-core-com-", "combase.dll"),
    ("api-ms-win-core-winrt-", "combase.dll"),
    ("api-ms-win-core-", "kernelbase.dll"),
    ("api-ms-win-security-base-", "kernelbase.dll"),
    ("api-ms-win-security-", "advapi32.dll"),
    ("api-ms-win-eventing-", "advapi32.dll"),
    ("api-ms-win-shcore-", "shcore.dll"),
    ("api-ms-win-shell-", "shell32.dll"),
    ("api-ms-win-downlevel-kernel32-", "kernel32.dll"),
    ("api-ms-win-downlevel-advapi32-", "advapi32.dll"),
    ("api-ms-win-downlevel-user32-", "user32.dll"),
    ("api-ms-win-downlevel-ole32-", "ole32.dll"),
    ("api-ms-win-downlevel-shlwapi-", "shlwapi.dll"),
    ("ext-ms-win-", "kernelbase.dll"),
];

/// Whether `name` (lower-case, with extension) is an API set name.
pub fn is_api_set(name: &str) -> bool {
    name.starts_with("api-") || name.starts_with("ext-")
}

/// The host DLL of API set `name` (lower-case), if known.
pub fn host(name: &str) -> Option<&'static str> {
    if !is_api_set(name) {
        return None;
    }
    if CRT_FOUNDATION.contains(&name) {
        return Some("ucrtbase.dll");
    }
    FAMILIES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|&(_, dll)| dll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_resolve_to_their_hosts() {
        assert_eq!(
            host("api-ms-win-crt-runtime-l1-1-0.dll"),
            Some("ucrtbase.dll")
        );
        assert_eq!(
            host("api-ms-win-crt-stdio-l1-1-0.dll"),
            Some("ucrtbase.dll")
        );
        assert_eq!(
            host("api-ms-win-core-synch-l1-2-0.dll"),
            Some("kernelbase.dll")
        );
        assert_eq!(
            host("api-ms-win-core-rtlsupport-l1-1-0.dll"),
            Some("ntdll.dll")
        );
        assert_eq!(host("api-ms-win-core-com-l1-1-0.dll"), Some("combase.dll"));
        assert_eq!(host("kernel32.dll"), None);
        assert!(is_api_set("ext-ms-win-foo-l1-1-0.dll"));
    }

    #[test]
    fn crt_foundation_contracts_share_one_live_builtin_host() {
        for name in CRT_FOUNDATION {
            let dll = host(name).unwrap();
            assert_eq!(
                super::super::super::dll::find(dll).unwrap().name,
                "ucrtbase.dll"
            );
        }
        assert_eq!(
            host("api-ms-win-crt-unknown-l99-99-99.dll"),
            Some("ucrtbase.dll")
        );
        assert_eq!(host("api-ms-win-unknown-l1-1-0.dll"), None);
    }
}
