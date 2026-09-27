//! API set names (`api-ms-win-*`, `ext-ms-win-*`) and the DLLs that host
//! them. An API set is a contract name, not a file: the loader redirects
//! an import of one to the DLL implementing it, and API sets never appear
//! in the module list.
//!
//! The mapping follows the host assignments of Windows 10/11's API set
//! schema for the families this personality implements: the C runtime
//! sets to `ucrtbase.dll`, the core Win32 sets to `kernelbase.dll`, and
//! the rest to the DLLs named below. Matching is by family prefix, so
//! every version of a family (`-l1-1-0`, `-l1-2-0`, ...) resolves alike.

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
}
