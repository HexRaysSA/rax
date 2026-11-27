//! Read-only selection of the macOS host's dyld, caches, on-disk dylibs, and
//! system metadata, including timezone and locale data, the file-type and
//! terminal databases, character-conversion tables, the system firmlink
//! manifest, system TLS defaults, and
//! selected CoreText and AppKit resources, system framework manifests, and
//! framework-bundled XPC service files, system sandbox profiles, and the
//! installed AppleScript component.
//! Installed Perl and Ruby modules,
//! executables, and shebang scripts are available in the same guest namespace.
//! A selected Command Line Tools or Xcode installation supplies its own tools
//! and SDK resources.
//!
//! Selection happens before guest execution. The supplied namespace also
//! contains guest devices and account records. Cache pages are read on demand
//! through retained read-only handles.
use crate::user::supplied_fs::{Device, Files};
use std::io;

#[cfg(any(target_os = "macos", test))]
use crate::user::mm::HostFileSource;
#[cfg(any(target_os = "macos", test))]
use std::sync::Arc;

#[cfg(any(target_os = "macos", test))]
#[path = "runtime_files/dylibs.rs"]
mod dylibs;

#[cfg(any(target_os = "macos", all(test, unix)))]
#[path = "runtime_files/xcode_license.rs"]
mod xcode_license;

#[cfg(any(target_os = "macos", test))]
const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";

#[cfg(any(target_os = "macos", test))]
const FILE_MAGIC_DATABASE: &str = "/usr/share/file/magic.mgc";

#[cfg(any(target_os = "macos", test))]
const FIRMLINK_MANIFEST: &str = "/usr/share/firmlinks";

#[cfg(any(target_os = "macos", test))]
const LAST_RESORT_FONT: &str = "/System/Library/Fonts/LastResort.otf";

#[cfg(any(target_os = "macos", test))]
const APPKIT_APPEARANCE_ROOT: &str =
    "/System/Library/CoreServices/SystemAppearance.bundle/Contents";

#[cfg(any(target_os = "macos", test))]
const OPENSSL_CONFIG: &str = "/private/etc/ssl/openssl.cnf";

#[cfg(any(target_os = "macos", test))]
const OPENSSL_TEMPLATE: &str = "System/Library/Templates/Data/private/etc/ssl/openssl.cnf";

#[cfg(any(target_os = "macos", test))]
const OPENSSL_CA_BUNDLE: &str = "/private/etc/ssl/cert.pem";

#[cfg(any(target_os = "macos", test))]
const OPENSSL_CA_TEMPLATE: &str = "System/Library/Templates/Data/private/etc/ssl/cert.pem";

#[cfg(any(target_os = "macos", test))]
const SHELL_SELECTOR: &str = "/private/var/select/sh";

#[cfg(any(target_os = "macos", test))]
const DEVELOPER_SELECTOR: &str = "/var/db/xcode_select_link";

#[cfg(any(target_os = "macos", test))]
const COMMAND_LINE_TOOLS: &str = "/Library/Developer/CommandLineTools";

#[cfg(any(target_os = "macos", test))]
const XCODE_BUNDLE: &str = "/Applications/Xcode.app";

#[cfg(any(target_os = "macos", test))]
const XCODE_CONTENTS: &str = "/Applications/Xcode.app/Contents";

#[cfg(any(target_os = "macos", test))]
const XCODE_DEVELOPER: &str = "/Applications/Xcode.app/Contents/Developer";

#[cfg(any(target_os = "macos", test))]
const PROGRAM_ROOTS: [&str; 4] = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];

#[cfg(any(target_os = "macos", test))]
const ZONEINFO_PATHS: [&str; 2] = ["/var/db/timezone/zoneinfo", "/usr/share/zoneinfo"];

#[cfg(any(target_os = "macos", test))]
const LOCALE_ROOT: &str = "/usr/share/locale";

#[cfg(any(target_os = "macos", test))]
const TERMINFO_ROOT: &str = "/usr/share/terminfo";

#[cfg(any(target_os = "macos", test))]
const CHARSET_ESDB_ROOT: &str = "/usr/share/i18n/esdb";

#[cfg(any(target_os = "macos", test))]
const CHARSET_MAPPER_ROOT: &str = "/usr/share/i18n/csmapper";

#[cfg(any(target_os = "macos", test))]
const SANDBOX_PROFILE_ROOT: &str = "/System/Library/Sandbox/Profiles";

#[cfg(any(target_os = "macos", test))]
const APPLE_SCRIPT_ROOT: &str = "/System/Library/Components/AppleScript.component/Contents";

#[cfg(any(target_os = "macos", test))]
const DATA_ROOTS: [&str; 6] = [
    APPLE_SCRIPT_ROOT,
    TERMINFO_ROOT,
    CHARSET_ESDB_ROOT,
    CHARSET_MAPPER_ROOT,
    APPKIT_APPEARANCE_ROOT,
    SANDBOX_PROFILE_ROOT,
];

#[cfg(any(target_os = "macos", test))]
const PERL_ROOT: &str = "/System/Library/Perl";

#[cfg(any(target_os = "macos", test))]
const RUBY_VERSIONS: &str = "/System/Library/Frameworks/Ruby.framework/Versions";

const FRAMEWORK_ROOTS: [&str; 6] = [
    "/System/Library/Frameworks",
    "/System/Library/PrivateFrameworks",
    "/System/Cryptexes/OS/System/Library/Frameworks",
    "/System/Cryptexes/OS/System/Library/PrivateFrameworks",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/PrivateFrameworks",
];

/// Derive the XPC service directory for a standard installed framework image.
pub(super) fn framework_service_directory(image: &str) -> Option<String> {
    let relative = FRAMEWORK_ROOTS
        .iter()
        .find_map(|root| image.strip_prefix(root)?.strip_prefix('/'))?;
    let (framework, suffix) = relative.split_once('/')?;
    let name = framework.strip_suffix(".framework")?;
    if name.is_empty()
        || suffix
            .rsplit('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    let (dir, executable) = image.rsplit_once('/')?;
    if executable != name {
        return None;
    }
    let versioned = suffix
        .strip_prefix("Versions/")
        .and_then(|tail| tail.split_once('/'))
        .is_some_and(|(_, executable)| executable == name);
    (suffix == name || versioned).then(|| format!("{dir}/XPCServices"))
}

/// Public kernel version strings collected when selecting the installed runtime.
#[derive(Clone, Debug)]
pub struct NativeKernelInfo {
    pub(crate) release: Vec<u8>,
    pub(crate) version: Vec<u8>,
    pub(crate) apple_silicon: bool,
}

impl NativeKernelInfo {
    pub(crate) fn capture() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                release: native_kernel_string(libc::KERN_OSRELEASE)?,
                version: native_kernel_string(libc::KERN_VERSION)?,
                apple_silicon: native_apple_silicon(),
            })
        }
        #[cfg(not(target_os = "macos"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Darwin kernel information requires a macOS host",
        ))
    }
}

#[cfg(target_os = "macos")]
fn native_apple_silicon() -> bool {
    if cfg!(target_arch = "aarch64") {
        return true;
    }
    // An x86-64 host process may itself be running under Rosetta.
    let mut value = 0i32;
    let mut size = std::mem::size_of_val(&value);
    // SAFETY: the fixed name is NUL-terminated and the output is a writable i32.
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.optional.arm64".as_ptr(),
            (&mut value as *mut i32).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    status == 0 && size == std::mem::size_of_val(&value) && value == 1
}

/// Capture one fixed, public CTL_KERN string before execution.
#[cfg(target_os = "macos")]
fn native_kernel_string(node: libc::c_int) -> io::Result<Vec<u8>> {
    let mut mib = [libc::CTL_KERN, node];
    let mut output = [0u8; 1024];
    let mut size = output.len();
    // SAFETY: mib and output have the respective lengths passed to sysctl.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            output.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = output
        .get(..size)
        .and_then(|bytes| std::ffi::CStr::from_bytes_with_nul(bytes).ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid Darwin kernel string")
        })?;
    Ok(value.to_bytes().to_vec())
}

/// Add the native macOS runtime, preserving explicit supplied-file overrides.
/// A different host cannot supply its own runtime for a Darwin guest.
pub fn native(files: &Files) -> io::Result<Files> {
    native_for_executable(files, None, &[], false)
}

pub(super) fn native_for_executable(
    files: &Files,
    executable: Option<&str>,
    env: &[Vec<u8>],
    guest_accounts: bool,
) -> io::Result<Files> {
    #[cfg(target_os = "macos")]
    {
        let root = std::path::Path::new("/");
        let selected = select_runtime_root(files, root, executable, env)?;
        let selected = select_shell_variant(selected, root, executable)?;
        if guest_accounts {
            select_guest_accounts(selected, executable)
        } else {
            Ok(selected)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (files, executable, env, guest_accounts);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Darwin runtime files require a macOS host",
        ))
    }
}

#[cfg(test)]
fn select_native_root(
    files: &Files,
    root: &std::path::Path,
    executable: Option<&str>,
) -> io::Result<Files> {
    select_runtime_root(files, root, executable, &[])
}

#[cfg(any(target_os = "macos", test))]
fn select_runtime_root(
    files: &Files,
    root: &std::path::Path,
    executable: Option<&str>,
    env: &[Vec<u8>],
) -> io::Result<Files> {
    let files = select(
        files,
        &root.join("usr/lib/dyld"),
        &[
            root.join("System/Library/dyld"),
            // dyld opens the mounted Cryptex path after discovering its root.
            root.join("System/Cryptexes/OS/System/Library/dyld"),
            root.join("System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"),
            root.join("System/Cryptexes/Rosetta/System/Library/dyld"),
            root.join("System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld"),
            root.join("System/Cryptexes/Rosetta/System/x86Support/System/Library/dyld"),
            root.join(
                "System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld",
            ),
        ],
    )?;
    let files = select_system_file(
        files,
        SYSTEM_VERSION_PLIST,
        &root.join(SYSTEM_VERSION_PLIST.trim_start_matches('/')),
    )?;
    let files = select_system_file(
        files,
        FILE_MAGIC_DATABASE,
        &root.join(FILE_MAGIC_DATABASE.trim_start_matches('/')),
    )?;
    // The system volume provides the stock LibreSSL configuration and trust roots.
    let mut files = select_system_file(files, OPENSSL_CONFIG, &root.join(OPENSSL_TEMPLATE))?;
    for (guest, relative) in [
        (OPENSSL_CA_BUNDLE, OPENSSL_CA_TEMPLATE),
        // libfakelink reads this manifest when normalizing FSEvents paths.
        (FIRMLINK_MANIFEST, FIRMLINK_MANIFEST.trim_start_matches('/')),
        (LAST_RESORT_FONT, LAST_RESORT_FONT.trim_start_matches('/')),
    ] {
        if !overlaps_executable(guest, executable) {
            files = select_system_file(files, guest, &root.join(relative))?;
        }
    }
    let files = files
        .with_device(Device::Null)
        .and_then(|files| files.with_device(Device::Zero))
        .and_then(|files| files.with_darwin_descriptor_names())
        .map_err(io::Error::other)?;
    let tools = select_developer_tools(root, executable, env);
    #[cfg(unix)]
    let files = if tools
        .as_ref()
        .is_some_and(|tools| tools.mount == XCODE_CONTENTS)
    {
        xcode_license::select(files, root, executable)?
    } else {
        files
    };
    let selector = tools
        .as_ref()
        .filter(|tools| {
            tools.selected_on_host && !overlaps_executable(DEVELOPER_SELECTOR, executable)
        })
        .map(|tools| tools.developer);
    let roots = [
        "/usr/lib",
        // Perl installs its dylib beside its versioned language runtime.
        PERL_ROOT,
        RUBY_VERSIONS,
        "/System/Cryptexes/OS/usr/lib",
        "/System/Cryptexes/OS/System/Library/Perl",
        "/System/Volumes/Preboot/Cryptexes/OS/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Perl",
        "/System/Cryptexes/Rosetta/usr/lib",
        "/System/Cryptexes/Rosetta/System/Library/Perl",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/Perl",
        "/System/Cryptexes/Rosetta/System/x86Support/usr/lib",
        "/System/Cryptexes/Rosetta/System/x86Support/System/Library/Perl",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/Perl",
    ]
    .into_iter()
    .chain(FRAMEWORK_ROOTS)
    .chain(ZONEINFO_PATHS)
    .chain([LOCALE_ROOT])
    .chain(PROGRAM_ROOTS.into_iter().chain(DATA_ROOTS).filter(|mount| {
        // The main image is inserted after native selection. It can replace
        // a data or program directory or one of its ancestors in the guest namespace.
        !executable.is_some_and(|image| {
            image == *mount
                || mount
                    .strip_prefix(image)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    }))
    .filter_map(|guest| {
        let host = root.join(guest.trim_start_matches('/'));
        let directory = if PROGRAM_ROOTS.contains(&guest) || DATA_ROOTS.contains(&guest) {
            host.symlink_metadata().is_ok_and(|info| info.is_dir())
        } else {
            host.is_dir()
        };
        directory.then(|| (guest.to_owned(), host))
    })
    .chain(tools.map(|tools| (tools.mount.into(), tools.host)))
    .collect();
    let files = files.with_native_library_roots(
        roots,
        Some(accept_runtime_file),
        &[
            LOCALE_ROOT,
            TERMINFO_ROOT,
            CHARSET_ESDB_ROOT,
            CHARSET_MAPPER_ROOT,
            APPKIT_APPEARANCE_ROOT,
            APPLE_SCRIPT_ROOT,
            SANDBOX_PROFILE_ROOT,
            PERL_ROOT,
            RUBY_VERSIONS,
            COMMAND_LINE_TOOLS,
            XCODE_CONTENTS,
            PROGRAM_ROOTS[0],
            PROGRAM_ROOTS[1],
            PROGRAM_ROOTS[2],
            PROGRAM_ROOTS[3],
        ],
        &PROGRAM_ROOTS,
    )?;
    let files = if let Some(developer) = selector {
        files
            .with_native_symlink(DEVELOPER_SELECTOR, developer)
            .map_err(io::Error::other)?
    } else {
        files
    };
    crate::user::supplied_fs::timezone::select_default(files, root)
}

#[cfg(any(target_os = "macos", test))]
fn select_guest_accounts(mut files: Files, executable: Option<&str>) -> io::Result<Files> {
    let (uid, gid) = crate::user::supplied_fs::DARWIN_GUEST_OWNER;
    // Libinfo selects passwd or master.passwd based on effective UID. The
    // virtual user owns the workspace and uses its private /tmp as home.
    // The conventional root and wheel entries carry no host data.
    let accounts = [
        (
            "/etc/passwd",
            format!(
                "root:*:0:0:System Administrator:/var/root:/bin/sh\n\
                 rax:*:{uid}:{gid}:RAX Guest:/tmp:/bin/sh\n"
            ),
        ),
        (
            "/etc/master.passwd",
            format!(
                "root:*:0:0::0:0:System Administrator:/var/root:/bin/sh\n\
                 rax:*:{uid}:{gid}::0:0:RAX Guest:/tmp:/bin/sh\n"
            ),
        ),
        ("/etc/group", format!("wheel:*:0:root\nrax:*:{gid}:rax\n")),
    ];
    for (path, record) in accounts {
        if !overlaps_executable(path, executable)
            && files
                .default_runtime_entry_available(path, None)
                .map_err(io::Error::other)?
        {
            files = files
                .with_file(path.into(), Arc::from(record.into_bytes()))
                .map_err(io::Error::other)?;
        }
    }
    Ok(files)
}

#[cfg(any(target_os = "macos", test))]
struct DeveloperTools {
    mount: &'static str,
    host: std::path::PathBuf,
    developer: &'static str,
    selected_on_host: bool,
}

#[cfg(any(target_os = "macos", test))]
fn select_developer_tools(
    root: &std::path::Path,
    executable: Option<&str>,
    env: &[Vec<u8>],
) -> Option<DeveloperTools> {
    use std::path::Path;

    let override_path = env
        .iter()
        .find_map(|entry| entry.strip_prefix(b"DEVELOPER_DIR="))
        .filter(|value| !value.is_empty());
    let selected_path = match override_path {
        Some(path) => std::path::PathBuf::from(std::str::from_utf8(path).ok()?),
        None => std::fs::read_link(root.join(DEVELOPER_SELECTOR.trim_start_matches('/'))).ok()?,
    };
    let (mount, developer) = if selected_path == Path::new(COMMAND_LINE_TOOLS) {
        (COMMAND_LINE_TOOLS, COMMAND_LINE_TOOLS)
    } else if selected_path == Path::new(XCODE_BUNDLE)
        || selected_path == Path::new(XCODE_DEVELOPER)
    {
        (XCODE_CONTENTS, XCODE_DEVELOPER)
    } else {
        return None;
    };
    // The main image can shadow individual tools. A parent image blocks the mount.
    if executable.is_some_and(|image| {
        image == mount
            || mount
                .strip_prefix(image)
                .is_some_and(|tail| tail.starts_with('/'))
    }) {
        return None;
    }

    // Admit the package at its fixed installation path. Resolving a symlink
    // in that path must never turn an unrelated directory into a toolchain.
    let host = root
        .canonicalize()
        .ok()?
        .join(mount.trim_start_matches('/'));
    if !host.is_dir() || host.canonicalize().ok()? != host {
        return None;
    }
    if mount == XCODE_CONTENTS
        && (!host.join("Developer").symlink_metadata().ok()?.is_dir()
            || !host.join("Info.plist").symlink_metadata().ok()?.is_file())
    {
        return None;
    }
    Some(DeveloperTools {
        mount,
        host,
        developer,
        selected_on_host: override_path.is_none(),
    })
}

#[cfg(any(target_os = "macos", test))]
fn accept_runtime_file(
    guest: &str,
    host: &std::path::Path,
    file: &std::fs::File,
) -> io::Result<bool> {
    use crate::user::image::macho::{MH_BUNDLE, MH_DYLIB, MH_EXECUTE};

    if [COMMAND_LINE_TOOLS, XCODE_CONTENTS]
        .into_iter()
        .any(|root| {
            guest
                .strip_prefix(root)
                .is_some_and(|name| name.starts_with('/'))
        })
    {
        // The confined package includes Mach-O images, SDK data, and scripts.
        return Ok(true);
    }

    if PROGRAM_ROOTS.into_iter().any(|root| {
        guest
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
    }) {
        return Ok(has_execute_permission(file)? && dylibs::accept(file, MH_EXECUTE)?);
    }

    if let Some(module) = guest
        .strip_prefix(PERL_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        if module.ends_with(".pm") {
            return Ok(true);
        }
        if module.ends_with(".bundle") && module.split('/').any(|part| part == "auto") {
            return dylibs::accept(file, MH_BUNDLE);
        }
    }
    if let Some((_, module)) = guest
        .strip_prefix(RUBY_VERSIONS)
        .and_then(|tail| tail.strip_prefix('/'))
        .and_then(|path| path.split_once("/usr/lib/ruby/"))
        .filter(|(version, _)| !version.contains('/'))
    {
        if module.ends_with(".rb") || module.ends_with(".gemspec") {
            return Ok(true);
        }
        if module.ends_with(".bundle") {
            return dylibs::accept(file, MH_BUNDLE);
        }
    }
    if let Some(locale_path) = guest
        .strip_prefix(LOCALE_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        let mut parts = locale_path.split('/');
        let _locale = parts.next();
        let category = parts.next();
        let member = parts.next();
        return Ok(match (category, member) {
            (Some("LC_CTYPE" | "LC_COLLATE" | "LC_MONETARY" | "LC_NUMERIC" | "LC_TIME"), None) => {
                true
            }
            (Some("LC_MESSAGES"), Some("LC_MESSAGES")) => parts.next().is_none(),
            _ => false,
        });
    }
    if let Some(entry) = guest
        .strip_prefix(APPLE_SCRIPT_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        return match entry {
            "MacOS/AppleScript" => dylibs::accept(file, MH_BUNDLE),
            "Info.plist"
            | "version.plist"
            | "Resources/AppleScript.rsrc"
            | "Resources/en.lproj/Localized.rsrc"
            | "Resources/Localizable.loctable"
            | "_CodeSignature/CodeResources" => Ok(true),
            _ => Ok(false),
        };
    }
    if let Some(entry) = guest
        .strip_prefix(APPKIT_APPEARANCE_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        return Ok(entry == "Info.plist"
            || entry
                .strip_prefix("Resources/")
                .is_some_and(|catalog| !catalog.contains('/') && catalog.ends_with(".car")));
    }
    if let Some(entry) = guest
        .strip_prefix(SANDBOX_PROFILE_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        let profile_name = |name: &str| {
            name.strip_suffix(".sb").is_some_and(|stem| {
                !stem.is_empty()
                    && stem.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            })
        };
        return Ok(profile_name(entry)
            && host.parent().is_some_and(|parent| {
                parent.ends_with(SANDBOX_PROFILE_ROOT.trim_start_matches('/'))
            })
            && host
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(profile_name));
    }
    if let Some(entry) = guest
        .strip_prefix(TERMINFO_ROOT)
        .and_then(|tail| tail.strip_prefix('/'))
    {
        return crate::user::supplied_fs::terminfo::accepts(entry, file);
    }
    for root in [CHARSET_ESDB_ROOT, CHARSET_MAPPER_ROOT] {
        if let Some(entry) = guest
            .strip_prefix(root)
            .and_then(|tail| tail.strip_prefix('/'))
        {
            return accept_charset_resource(root, entry, file);
        }
    }
    if let Some((bundle, path, kind)) = framework_file(guest) {
        let same_path = resolved_framework_file(host, bundle) == Some(path);
        match kind {
            FrameworkFile::Manifest => return Ok(same_path),
            FrameworkFile::Executable if same_path && has_execute_permission(file)? => {
                return dylibs::accept_xpc_program_or_dylib(file);
            }
            FrameworkFile::Executable => {}
        }
    }
    if ZONEINFO_PATHS.into_iter().any(|root| {
        guest
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        crate::user::supplied_fs::timezone::has_tzif_header(file)
    } else {
        dylibs::accept(file, MH_DYLIB)
    }
}

#[cfg(any(target_os = "macos", test))]
fn has_execute_permission(file: &std::fs::File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(file.metadata()?.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(true)
    }
}

#[cfg(any(target_os = "macos", test))]
enum FrameworkFile {
    Manifest,
    Executable,
}

#[cfg(any(target_os = "macos", test))]
fn framework_file(guest: &str) -> Option<(&str, &std::path::Path, FrameworkFile)> {
    use std::path::Path;

    let relative = FRAMEWORK_ROOTS.iter().find_map(|root| {
        guest
            .strip_prefix(root)
            .and_then(|suffix| suffix.strip_prefix('/'))
    })?;
    let (bundle, entry) = relative.split_once('/')?;
    if !bundle.ends_with(".framework") {
        return None;
    }
    let path = framework_version_contents(Path::new(entry))?;
    if path == Path::new("Resources/Info.plist") {
        return Some((bundle, path, FrameworkFile::Manifest));
    }
    let mut service = path.strip_prefix("XPCServices").ok()?.components();
    if !service.next()?.as_os_str().to_str()?.ends_with(".xpc") {
        return None;
    }
    let entry = service.as_path();
    if entry == Path::new("Contents/Info.plist") {
        Some((bundle, path, FrameworkFile::Manifest))
    } else if entry
        .strip_prefix("Contents/MacOS")
        .is_ok_and(|name| name.components().count() == 1)
    {
        Some((bundle, path, FrameworkFile::Executable))
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn framework_version_contents(path: &std::path::Path) -> Option<&std::path::Path> {
    if let Ok(version) = path.strip_prefix("Versions") {
        let mut parts = version.components();
        parts.next()?;
        Some(parts.as_path())
    } else {
        Some(path)
    }
}

#[cfg(any(target_os = "macos", test))]
fn resolved_framework_file<'a>(
    host: &'a std::path::Path,
    framework: &str,
) -> Option<&'a std::path::Path> {
    use std::ffi::OsStr;

    // The standard aliases may resolve through Versions/Current and the
    // Cryptex. Retain the framework and within-version path as the identity.
    let bundle = host.ancestors().find(|dir| {
        dir.file_name() == Some(OsStr::new(framework))
            && dir.parent().is_some_and(|root| {
                FRAMEWORK_ROOTS
                    .iter()
                    .any(|known| root.ends_with(known.trim_start_matches('/')))
            })
    })?;
    framework_version_contents(host.strip_prefix(bundle).ok()?)
}

#[cfg(any(target_os = "macos", test))]
fn accept_charset_resource(root: &str, entry: &str, mut file: &std::fs::File) -> io::Result<bool> {
    use std::io::Read;

    let table = entry
        .split_once('/')
        .and_then(|(_, name)| (!name.contains('/')).then_some(name));
    let signature = match (root, entry) {
        (CHARSET_ESDB_ROOT, "esdb.alias" | "esdb.dir")
        | (CHARSET_MAPPER_ROOT, "mapper.dir" | "charset.pivot") => return Ok(true),
        (CHARSET_ESDB_ROOT, "esdb.alias.db" | "esdb.dir.db")
        | (CHARSET_MAPPER_ROOT, "mapper.dir.db") => b"LOOKUP\0\0",
        (CHARSET_MAPPER_ROOT, "charset.pivot.pvdb") => b"CSPIVOT\0",
        (CHARSET_ESDB_ROOT, _) if table.is_some_and(|name| name.ends_with(".esdb")) => {
            b"ESDB\0\0\0\0"
        }
        (CHARSET_MAPPER_ROOT, _) if table.is_some_and(|name| name.ends_with(".mps")) => {
            b"MAPPER\0\0"
        }
        (CHARSET_MAPPER_ROOT, _)
            if entry.starts_with("ISO646/") && table.is_some_and(|name| name.ends_with(".646")) =>
        {
            return Ok(true);
        }
        _ => return Ok(false),
    };
    let mut header = [0; 8];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(&header == signature),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "macos", test))]
fn select_system_file(files: Files, path: &str, host: &std::path::Path) -> io::Result<Files> {
    use crate::user::supplied_fs::Error;

    if !matches!(files.lookup(path), Err(Error::NotFound)) {
        return Ok(files);
    }
    // Keep adjacent files and symlink targets outside the supplied namespace.
    match std::fs::symlink_metadata(host) {
        Ok(metadata) if metadata.is_file() => files.with_host_files_using(
            std::collections::BTreeMap::from([(path.into(), host.to_path_buf())]),
            open_installed_backing,
        ),
        Ok(_) => Ok(files),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(files),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "macos", test))]
fn open_installed_backing(host: &std::path::Path) -> io::Result<Arc<HostFileSource>> {
    Files::open_host_backing(host)
        .map(HostFileSource::for_darwin_installed)
        .map(Arc::new)
}

#[cfg(any(target_os = "macos", test))]
fn overlaps_executable(path: &str, executable: Option<&str>) -> bool {
    let descends = |child: &str, parent: &str| {
        child
            .strip_prefix(parent)
            .is_some_and(|tail| tail.starts_with('/'))
    };
    // The main executable is inserted after native runtime selection.
    executable.is_some_and(|image| image == path || descends(image, path) || descends(path, image))
}

#[cfg(any(target_os = "macos", test))]
fn select_shell_variant(
    files: Files,
    root: &std::path::Path,
    executable: Option<&str>,
) -> io::Result<Files> {
    if overlaps_executable(SHELL_SELECTOR, executable) {
        return Ok(files);
    }
    // The installed /bin/sh wrapper recognizes these guest paths. Retain
    // the link bytes. The destination is resolved inside the guest namespace.
    let host = root.join(SHELL_SELECTOR.trim_start_matches('/'));
    let Ok(target) = std::fs::read_link(host) else {
        return Ok(files);
    };
    match target.to_str() {
        Some(target @ ("/bin/bash" | "/bin/dash" | "/bin/zsh")) => files
            .with_native_symlink(SHELL_SELECTOR, target)
            .map_err(io::Error::other),
        _ => Ok(files),
    }
}

#[cfg(any(target_os = "macos", test))]
fn select(
    files: &Files,
    dyld: &std::path::Path,
    directories: &[std::path::PathBuf],
) -> io::Result<Files> {
    use crate::user::mm::PageSource;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, Weak};

    type Backings = BTreeMap<(u64, u64), Weak<HostFileSource>>;
    static INSTALLED_BACKINGS: Mutex<Backings> = Mutex::new(BTreeMap::new());

    let mut selected = BTreeMap::new();
    if files.lookup("/usr/lib/dyld").is_err() {
        selected.insert("/usr/lib/dyld".to_string(), dyld.to_path_buf());
    }
    let mut count = 0;
    for directory in directories {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with("dyld_shared_cache_")
                || name.ends_with(".map")
                || name.ends_with(".atlas")
            {
                continue;
            }
            if !entry.file_type()?.is_file() {
                continue;
            }
            count += 1;
            if count > 256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native Darwin runtime exceeds 256 cache files",
                ));
            }
            let host = entry.path();
            // dyld probes the system directory as well as the Cryptex path.
            // Aliases retain one file handle and have distinct guest inode keys.
            let mut paths = vec![format!("/System/Library/dyld/{name}")];
            // A native Windows path has no meaning in the POSIX guest namespace.
            // The generic selection fixture still uses the explicit guest alias.
            if let Some(guest) = host.to_str().filter(|path| path.starts_with('/')) {
                paths.push(guest.to_owned());
            }
            for path in paths {
                if files.lookup(&path).is_err() {
                    selected.insert(path, host.clone());
                }
            }
        }
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no native Darwin shared cache files found",
        ));
    }
    let mut backings = INSTALLED_BACKINGS
        .lock()
        .map_err(|_| io::Error::other("Darwin runtime backing table is poisoned"))?;
    backings.retain(|_, source| source.strong_count() != 0);
    files.with_host_files_using(selected, |host| {
        // Open through this selection's path before sharing. A replaced file
        // gets its own backing, and a weak entry never keeps a descriptor open.
        let source = open_installed_backing(host)?;
        let identity = source.identity();
        let entry = backings.entry((identity.dev, identity.ino)).or_default();
        if let Some(existing) = entry.upgrade() {
            return Ok(existing);
        }
        *entry = Arc::downgrade(&source);
        Ok(source)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::supplied_fs::{Kind, test_backing::TestFile};
    use std::sync::Arc;

    #[test]
    fn selected_runtime_keeps_overrides_and_maps_large_cache_files_lazily() {
        let fixture = TestFile::new(b"dyld", 4);
        let cache = fixture.dir.join("dyld_shared_cache_arm64e.01.dylddata");
        std::fs::File::create(&cache)
            .unwrap()
            .set_len((64 << 20) + 1)
            .unwrap();
        std::fs::write(fixture.dir.join("unrelated"), b"not-runtime").unwrap();
        std::fs::write(
            fixture.dir.join("dyld_shared_cache_arm64e.map"),
            b"metadata",
        )
        .unwrap();
        let files = Files::default()
            .with_file("/usr/lib/dyld".into(), Arc::from(&b"override"[..]))
            .unwrap();
        let selected = select(&files, &fixture.path, &[fixture.dir.clone()]).unwrap();
        assert_eq!(&*selected.read("/usr/lib/dyld").unwrap(), b"override");
        let alias = "/System/Library/dyld/dyld_shared_cache_arm64e.01.dylddata";
        let entry = selected.lookup(alias).unwrap().1;
        assert!(matches!(entry.kind, Kind::Backed(_)));
        assert_eq!(entry.len(), (64 << 20) + 1);
        assert!(entry.bytes().is_err());
        assert!(selected.lookup("/System/Library/dyld/unrelated").is_err());
        assert!(
            selected
                .lookup("/System/Library/dyld/dyld_shared_cache_arm64e.map")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_runtime_shares_live_backings_and_observes_replacement() {
        let fixture = TestFile::new(b"dyld", 4);
        let name = "dyld_shared_cache_arm64e";
        let cache = fixture.dir.join(name);
        let replacement = fixture.dir.join("replacement");
        std::fs::write(&cache, b"old cache").unwrap();
        let files = Files::default();
        let directories = std::slice::from_ref(&fixture.dir);
        let select_backing = || {
            let runtime = select(&files, &fixture.path, directories).unwrap();
            let entry = runtime
                .lookup(&format!("/System/Library/dyld/{name}"))
                .unwrap()
                .1;
            let Kind::Backed(source) = entry.kind else {
                panic!("installed cache must have retained backing");
            };
            source
        };

        let first = select_backing();
        let second = select_backing();
        assert!(Arc::ptr_eq(&first, &second));

        std::fs::write(&replacement, b"new cache").unwrap();
        std::fs::rename(&replacement, &cache).unwrap();
        let third = select_backing();
        assert!(!Arc::ptr_eq(&first, &third));
        use crate::user::mm::PageSource as _;
        for (source, expected) in [(&first, b"old cache"), (&third, b"new cache")] {
            let mut bytes = [0; 9];
            assert_eq!(source.read_at(0, &mut bytes).unwrap(), expected.len());
            assert_eq!(&bytes, expected);
        }

        let retired = Arc::downgrade(&first);
        drop(first);
        drop(second);
        assert!(retired.upgrade().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn shell_selector_admits_only_stock_link_metadata_and_preserves_overrides() {
        use crate::user::supplied_fs::Error;

        let fixture = TestFile::new(b"host bytes", 10);
        let selector = fixture.dir.join(SHELL_SELECTOR.trim_start_matches('/'));
        std::fs::create_dir_all(selector.parent().unwrap()).unwrap();
        let link = |target: &str| std::os::unix::fs::symlink(target, &selector).unwrap();
        link("/bin/dash");
        for executable in ["/private", SHELL_SELECTOR, "/private/var/select/sh/tool"] {
            let files = select_shell_variant(Files::default(), &fixture.dir, Some(executable))
                .unwrap()
                .with_file(executable.into(), Arc::from(b"entry image".as_slice()))
                .unwrap();
            assert_eq!(&*files.read(executable).unwrap(), b"entry image");
        }
        let selected = select_shell_variant(Files::default(), &fixture.dir, None).unwrap();
        let metadata = selected
            .lookup_with_follow(SHELL_SELECTOR, false)
            .unwrap()
            .1;
        assert_eq!(metadata.link_target(), Some(b"/bin/dash".as_slice()));
        assert!(matches!(
            selected.lookup(SHELL_SELECTOR),
            Err(Error::NotFound)
        ));
        let supplied = selected
            .with_file("/bin/dash".into(), Arc::from(b"guest image".as_slice()))
            .unwrap();
        assert_eq!(&*supplied.read(SHELL_SELECTOR).unwrap(), b"guest image");

        let override_file = Files::default()
            .with_file(SHELL_SELECTOR.into(), Arc::from(b"override".as_slice()))
            .unwrap();
        let selected = select_shell_variant(override_file, &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(SHELL_SELECTOR).unwrap(), b"override");

        let mount = TestFile::new(b"mount", 5);
        let mounted = Files::default()
            .with_host_roots(std::collections::BTreeMap::from([(
                "/private/var".into(),
                mount.dir.clone(),
            )]))
            .unwrap();
        let selected = select_shell_variant(mounted, &fixture.dir, None).unwrap();
        assert!(matches!(
            selected.lookup_with_follow(SHELL_SELECTOR, false),
            Err(Error::NotFound)
        ));

        let blocked = Files::default()
            .with_file("/private/var".into(), Arc::from(b"regular".as_slice()))
            .unwrap();
        let selected = select_shell_variant(blocked, &fixture.dir, None).unwrap();
        assert!(matches!(
            selected.lookup(SHELL_SELECTOR),
            Err(Error::NotDirectory)
        ));

        std::fs::remove_file(&selector).unwrap();
        for rejected in ["/bin/cat", "../bin/bash", "/bin/./bash"] {
            link(rejected);
            let selected = select_shell_variant(Files::default(), &fixture.dir, None).unwrap();
            assert!(matches!(
                selected.lookup_with_follow(SHELL_SELECTOR, false),
                Err(Error::NotFound)
            ));
            std::fs::remove_file(&selector).unwrap();
        }
        std::fs::write(selector, b"/bin/bash").unwrap();
        let selected = select_shell_variant(Files::default(), &fixture.dir, None).unwrap();
        assert!(matches!(
            selected.lookup_with_follow(SHELL_SELECTOR, false),
            Err(Error::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installed_child_programs_select_mach_os_and_scripts_and_preserve_main_image_precedence() {
        use crate::user::image::macho::{CPU_TYPE_X86_64, MH_DYLIB, MH_EXECUTE, MH_MAGIC_64};
        use crate::user::supplied_fs::Error;
        use std::{
            fs::{self, Permissions},
            os::unix::fs::{PermissionsExt, symlink},
        };

        let fixture = TestFile::new(b"unused", 8);
        let root = &fixture.dir;
        for directory in [
            "usr/lib",
            "System/Library/dyld",
            "usr/bin",
            "bin",
            "usr/local/bin",
            "sbin",
            "usr/sbin",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        let mut executable = [0u8; 32];
        executable[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        executable[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        executable[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        for path in [
            "bin/sh",
            "usr/bin/child",
            "usr/lib/outside",
            "usr/local/bin/child",
            "sbin/legacy-tool",
            "usr/sbin/system-tool",
        ] {
            let host = root.join(path);
            fs::write(&host, executable).unwrap();
            fs::set_permissions(&host, Permissions::from_mode(0o755)).unwrap();
        }
        symlink("child", root.join("usr/bin/alias")).unwrap();
        symlink("../lib/outside", root.join("usr/bin/escape")).unwrap();
        symlink("../lib/outside", root.join("usr/sbin/escape")).unwrap();
        fs::write(root.join("usr/bin/no-execute"), executable).unwrap();
        fs::set_permissions(
            root.join("usr/bin/no-execute"),
            Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut dylib = executable;
        dylib[12..16].copy_from_slice(&MH_DYLIB.to_le_bytes());
        fs::write(root.join("usr/bin/library"), dylib).unwrap();
        fs::set_permissions(root.join("usr/bin/library"), Permissions::from_mode(0o755)).unwrap();
        let script = b"#!/bin/sh\nprintf 'installed script\\n'\n";
        for (name, contents, mode) in [
            ("script", script.as_slice(), 0o755),
            ("script-no-execute", script.as_slice(), 0o644),
            ("script-no-interpreter", b"#!  \n".as_slice(), 0o755),
            ("script-no-line-end", b"#!/bin/sh".as_slice(), 0o755),
        ] {
            let host = root.join("usr/bin").join(name);
            fs::write(&host, contents).unwrap();
            fs::set_permissions(host, Permissions::from_mode(mode)).unwrap();
        }

        let original = Files::default();
        let files = select_native_root(&original, root, Some("/usr/bin/child")).unwrap();
        for path in [
            "/usr/bin/child",
            "/usr/bin/alias",
            "/bin/sh",
            "/sbin/legacy-tool",
            "/usr/sbin/system-tool",
        ] {
            assert_eq!(&*files.read(path).unwrap(), &executable, "{path}");
        }
        assert_eq!(&*files.read("/usr/bin/script").unwrap(), script);
        for path in [
            "/usr/bin/CHILD",
            "/usr/bin/escape",
            "/usr/bin/no-execute",
            "/usr/bin/library",
            "/usr/bin/script-no-execute",
            "/usr/bin/script-no-interpreter",
            "/usr/bin/script-no-line-end",
            "/usr/local/bin/child",
            "/sbin/system-tool",
            "/usr/sbin/escape",
        ] {
            assert!(matches!(files.read(path), Err(Error::NotFound)), "{path}");
        }
        let files = files
            .with_file("/usr/bin/child".into(), Arc::from(&b"guest main"[..]))
            .unwrap();
        assert_eq!(&*files.read("/usr/bin/child").unwrap(), b"guest main");

        let supplied = original
            .with_file("/bin/sh".into(), Arc::from(&b"caller shell"[..]))
            .unwrap();
        let files = select_native_root(&supplied, root, Some("/usr/bin/child")).unwrap();
        assert_eq!(&*files.read("/bin/sh").unwrap(), b"caller shell");

        for path in ["/bin", "/sbin", "/usr/sbin"] {
            let files = select_native_root(&original, root, Some(path)).unwrap();
            assert!(matches!(files.lookup(path), Err(Error::NotFound)));
            let files = files
                .with_file(path.into(), Arc::from(&b"guest main"[..]))
                .unwrap();
            assert_eq!(&*files.read(path).unwrap(), b"guest main");
        }
    }

    #[cfg(unix)]
    #[test]
    fn selected_command_line_tools_stay_in_the_installed_package() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"outside file", 12);
        let root = &fixture.dir;
        let developer = root.join(COMMAND_LINE_TOOLS.trim_start_matches('/'));
        let selector = root.join(DEVELOPER_SELECTOR.trim_start_matches('/'));
        for path in ["usr/lib", "System/Library/dyld", "usr/share/locale"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        fs::create_dir_all(developer.join("SDKs")).unwrap();
        fs::create_dir_all(selector.parent().unwrap()).unwrap();
        fs::write(developer.join("SDKs/SDKSettings.json"), b"SDK resource").unwrap();
        fs::create_dir_all(root.join("usr/share/locale/CC")).unwrap();
        fs::write(root.join("usr/share/locale/CC/LC_CTYPE"), b"locale").unwrap();
        symlink("SDKSettings.json", developer.join("SDKs/alias")).unwrap();
        symlink(
            root.join("usr/share/locale/CC/LC_CTYPE"),
            developer.join("SDKs/escape"),
        )
        .unwrap();
        let filename = format!("{COMMAND_LINE_TOOLS}/SDKs/SDKSettings.json");
        let alias = format!("{COMMAND_LINE_TOOLS}/SDKs/alias");
        let escape = format!("{COMMAND_LINE_TOOLS}/SDKs/escape");
        let files = Files::default();
        let env = vec![format!("DEVELOPER_DIR={COMMAND_LINE_TOOLS}/").into_bytes()];
        let selected = select_runtime_root(&files, root, None, &env).unwrap();
        for name in [&filename, &alias] {
            assert_eq!(&*selected.read(name).unwrap(), b"SDK resource");
        }
        assert!(matches!(selected.read(&escape), Err(Error::NotFound)));
        assert_eq!(
            &*selected.read("/usr/share/locale/CC/LC_CTYPE").unwrap(),
            b"locale"
        );
        assert!(matches!(
            selected.lookup(DEVELOPER_SELECTOR),
            Err(Error::NotFound)
        ));

        let overridden = files
            .with_file(filename.clone(), Arc::from(b"guest SDK".as_slice()))
            .unwrap();
        let selected = select_runtime_root(&overridden, root, None, &env).unwrap();
        assert_eq!(&*selected.read(&filename).unwrap(), b"guest SDK");
        let selected = select_runtime_root(&files, root, Some(&filename), &env)
            .unwrap()
            .with_file(filename.clone(), Arc::from(b"entry image".as_slice()))
            .unwrap();
        assert_eq!(&*selected.read(&filename).unwrap(), b"entry image");
        let selected = select_runtime_root(&files, root, Some("/Library/Developer"), &env)
            .unwrap()
            .with_file(
                "/Library/Developer".into(),
                Arc::from(b"entry image".as_slice()),
            )
            .unwrap();
        assert!(matches!(selected.read(&filename), Err(Error::NotDirectory)));

        symlink(COMMAND_LINE_TOOLS, &selector).unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert_eq!(&*selected.read(&filename).unwrap(), b"SDK resource");
        let (_, entry) = selected
            .lookup_with_follow(DEVELOPER_SELECTOR, false)
            .unwrap();
        assert_eq!(entry.link_target(), Some(COMMAND_LINE_TOOLS.as_bytes()));

        let other_developer = vec![b"DEVELOPER_DIR=/Applications/Xcode.app".to_vec()];
        let selected = select_runtime_root(&files, root, None, &other_developer).unwrap();
        assert!(matches!(selected.lookup(&filename), Err(Error::NotFound)));
        assert!(matches!(
            selected.lookup(DEVELOPER_SELECTOR),
            Err(Error::NotFound)
        ));

        fs::rename(&developer, developer.with_extension("relocated")).unwrap();
        symlink(developer.with_extension("relocated"), developer).unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(selected.lookup(&filename), Err(Error::NotFound)));
        assert!(matches!(
            selected.lookup(DEVELOPER_SELECTOR),
            Err(Error::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn selected_xcode_stays_in_the_installed_bundle() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"outside file", 12);
        let root = &fixture.dir;
        let contents = root.join(XCODE_CONTENTS.trim_start_matches('/'));
        let selector = root.join(DEVELOPER_SELECTOR.trim_start_matches('/'));
        for path in ["usr/lib", "System/Library/dyld", "usr/share/locale/CC"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        let locale = root.join("usr/share/locale/CC/LC_CTYPE");
        fs::write(&locale, b"locale").unwrap();
        fs::create_dir_all(contents.join("Developer/usr/bin")).unwrap();
        fs::create_dir_all(contents.join("SharedFrameworks")).unwrap();
        fs::create_dir_all(selector.parent().unwrap()).unwrap();
        fs::write(contents.join("Info.plist"), b"Xcode bundle metadata").unwrap();
        fs::write(contents.join("SharedFrameworks/runtime"), b"runtime").unwrap();
        symlink(
            "../../../SharedFrameworks/runtime",
            contents.join("Developer/usr/bin/tool"),
        )
        .unwrap();
        symlink(locale, contents.join("Developer/usr/bin/escape")).unwrap();
        symlink(XCODE_DEVELOPER, &selector).unwrap();

        let files = Files::default();
        let tool = format!("{XCODE_DEVELOPER}/usr/bin/tool");
        let escape = format!("{XCODE_DEVELOPER}/usr/bin/escape");
        for location in [None, Some(XCODE_BUNDLE), Some(XCODE_DEVELOPER)] {
            let env: Vec<_> = location
                .map(|path| format!("DEVELOPER_DIR={path}").into_bytes())
                .into_iter()
                .collect();
            let selected = select_runtime_root(&files, root, None, &env).unwrap();
            assert_eq!(&*selected.read(&tool).unwrap(), b"runtime");
            assert!(matches!(selected.read(&escape), Err(Error::NotFound)));
            assert_eq!(
                &*selected.read("/usr/share/locale/CC/LC_CTYPE").unwrap(),
                b"locale"
            );
            match selected.lookup_with_follow(DEVELOPER_SELECTOR, false) {
                Ok((_, entry)) if location.is_none() => {
                    assert_eq!(entry.link_target(), Some(XCODE_DEVELOPER.as_bytes()));
                }
                Err(Error::NotFound) if location.is_some() => {}
                result => panic!("unexpected developer selector: {result:?}"),
            }
        }

        let override_files = files
            .with_file(tool.clone(), Arc::from(b"caller tool".as_slice()))
            .unwrap();
        let selected = select_native_root(&override_files, root, None).unwrap();
        assert_eq!(&*selected.read(&tool).unwrap(), b"caller tool");
        let selected = select_native_root(&files, root, Some(XCODE_BUNDLE)).unwrap();
        assert!(matches!(selected.lookup(&tool), Err(Error::NotFound)));

        fs::rename(&contents, contents.with_extension("relocated")).unwrap();
        symlink(contents.with_extension("relocated"), contents).unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(selected.lookup(&tool), Err(Error::NotFound)));
        assert!(matches!(
            selected.lookup(DEVELOPER_SELECTOR),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn fixed_system_files_are_selected_without_neighboring_files() {
        let fixture = TestFile::new(b"dyld", 4);
        let dyld = fixture.dir.join("usr/lib/dyld");
        let cache_dir = fixture.dir.join("System/Library/dyld");
        let version = fixture
            .dir
            .join(SYSTEM_VERSION_PLIST.trim_start_matches('/'));
        let magic = fixture
            .dir
            .join(FILE_MAGIC_DATABASE.trim_start_matches('/'));
        std::fs::create_dir_all(dyld.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::create_dir_all(version.parent().unwrap()).unwrap();
        std::fs::write(dyld, b"dyld").unwrap();
        std::fs::write(cache_dir.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        std::fs::write(&version, b"installed").unwrap();
        std::fs::write(version.with_file_name("Unselected.plist"), b"other").unwrap();
        std::fs::create_dir_all(magic.with_file_name("magic")).unwrap();
        std::fs::write(&magic, b"compiled magic database").unwrap();
        std::fs::write(magic.with_file_name("magic").join("source"), b"other").unwrap();
        let selected = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"installed");
        assert_eq!(
            &*selected.read(FILE_MAGIC_DATABASE).unwrap(),
            b"compiled magic database"
        );
        assert!(selected.lookup("/usr/share/file/magic").is_err());
        assert!(
            selected
                .lookup("/System/Library/CoreServices/Unselected.plist")
                .is_err()
        );

        let supplied = Files::default()
            .with_file(SYSTEM_VERSION_PLIST.into(), Arc::from(&b"supplied"[..]))
            .unwrap()
            .with_file(
                FILE_MAGIC_DATABASE.into(),
                Arc::from(&b"supplied magic"[..]),
            )
            .unwrap();
        let selected = select_native_root(&supplied, &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"supplied");
        assert_eq!(
            &*selected.read(FILE_MAGIC_DATABASE).unwrap(),
            b"supplied magic"
        );

        let caller = TestFile::new(b"caller", 6);
        std::fs::write(caller.dir.join("SystemVersion.plist"), b"mounted").unwrap();
        let mounted = Files::default()
            .with_host_roots(std::collections::BTreeMap::from([(
                "/System/Library/CoreServices".into(),
                caller.dir.clone(),
            )]))
            .unwrap();
        let selected = select_native_root(&mounted, &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"mounted");

        let blocked = Files::default()
            .with_file(
                "/System/Library/CoreServices".into(),
                Arc::from(&b"file"[..]),
            )
            .unwrap();
        let selected = select_native_root(&blocked, &fixture.dir, None).unwrap();
        assert_eq!(
            &*selected.read("/System/Library/CoreServices").unwrap(),
            b"file"
        );
        assert!(selected.lookup(SYSTEM_VERSION_PLIST).is_err());

        #[cfg(unix)]
        {
            std::fs::remove_file(&version).unwrap();
            std::os::unix::fs::symlink(&fixture.path, &version).unwrap();
            let selected = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
            assert!(selected.lookup(SYSTEM_VERSION_PLIST).is_err());
        }
    }

    #[test]
    fn guest_accounts_use_guest_credentials_and_preserve_caller_paths() {
        use crate::user::supplied_fs::Error;
        use std::collections::BTreeMap;

        let fixture = TestFile::new(b"dyld", 4);
        let dyld = fixture.dir.join("usr/lib/dyld");
        let cache = fixture
            .dir
            .join("System/Library/dyld/dyld_shared_cache_arm64e");
        let host_etc = fixture.dir.join("etc");
        std::fs::create_dir_all(dyld.parent().unwrap()).unwrap();
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(dyld, b"dyld").unwrap();
        std::fs::write(cache, b"cache").unwrap();
        std::fs::create_dir(&host_etc).unwrap();
        std::fs::write(host_etc.join("master.passwd"), b"host account").unwrap();

        let empty = Files::default();
        let native = select_native_root(&empty, &fixture.dir, None).unwrap();
        assert!(matches!(
            native.lookup("/etc/master.passwd"),
            Err(Error::NotFound)
        ));
        let select = |files: &Files, executable: Option<&str>| {
            let selected = select_native_root(files, &fixture.dir, executable).unwrap();
            select_guest_accounts(selected, executable).unwrap()
        };
        let selected = select(&empty, None);
        let (uid, gid) = crate::user::supplied_fs::DARWIN_GUEST_OWNER;
        let passwd = selected.read("/etc/passwd").unwrap();
        let master = selected.read("/etc/master.passwd").unwrap();
        let group = selected.read("/etc/group").unwrap();
        let records = |bytes: &[u8]| {
            let content = std::str::from_utf8(bytes).unwrap();
            content.lines().map(str::to_owned).collect::<Vec<_>>()
        };
        assert_eq!(
            records(&passwd),
            [
                "root:*:0:0:System Administrator:/var/root:/bin/sh".to_owned(),
                format!("rax:*:{uid}:{gid}:RAX Guest:/tmp:/bin/sh"),
            ]
        );
        assert_eq!(
            records(&master),
            [
                "root:*:0:0::0:0:System Administrator:/var/root:/bin/sh".to_owned(),
                format!("rax:*:{uid}:{gid}::0:0:RAX Guest:/tmp:/bin/sh"),
            ]
        );
        assert_eq!(
            records(&group),
            ["wheel:*:0:root".to_owned(), format!("rax:*:{gid}:rax")]
        );

        let supplied = empty
            .with_file("/etc/passwd".into(), Arc::from(&b"caller account"[..]))
            .unwrap();
        let selected = select(&supplied, None);
        assert_eq!(&*selected.read("/etc/passwd").unwrap(), b"caller account");

        let mounted = empty
            .with_host_roots(BTreeMap::from([("/etc".into(), host_etc)]))
            .unwrap();
        let selected = select(&mounted, None);
        assert_eq!(
            &*selected.read("/etc/master.passwd").unwrap(),
            b"host account"
        );
        assert!(matches!(
            selected.lookup("/etc/passwd"),
            Err(Error::NotFound)
        ));

        for image in ["/etc", "/etc/passwd", "/etc/passwd/program"] {
            let selected = select(&empty, Some(image));
            assert!(matches!(
                selected.lookup("/etc/passwd"),
                Err(Error::NotFound)
            ));
        }
    }

    #[test]
    fn openssl_defaults_come_from_the_system_templates() {
        use crate::user::supplied_fs::Error;

        let fixture = TestFile::new(b"dyld", 4);
        let dyld = fixture.dir.join("usr/lib/dyld");
        let cache_dir = fixture.dir.join("System/Library/dyld");
        let template = fixture.dir.join(OPENSSL_TEMPLATE);
        let ca_template = fixture.dir.join(OPENSSL_CA_TEMPLATE);
        let local = fixture.dir.join(OPENSSL_CONFIG.trim_start_matches('/'));
        let local_ca = fixture.dir.join(OPENSSL_CA_BUNDLE.trim_start_matches('/'));
        std::fs::create_dir_all(dyld.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::create_dir_all(template.parent().unwrap()).unwrap();
        std::fs::create_dir_all(local.parent().unwrap()).unwrap();
        std::fs::write(dyld, b"dyld").unwrap();
        std::fs::write(cache_dir.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        std::fs::write(local, b"local config").unwrap();
        std::fs::write(local_ca, b"local bundle").unwrap();
        std::fs::write(template.with_file_name("local-key.pem"), b"neighbor").unwrap();

        let absent = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
        assert!(matches!(
            absent.lookup(OPENSSL_CONFIG),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            absent.lookup(OPENSSL_CA_BUNDLE),
            Err(Error::NotFound)
        ));

        std::fs::write(&template, b"system config").unwrap();
        std::fs::write(&ca_template, b"system bundle").unwrap();
        let selected = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(OPENSSL_CONFIG).unwrap(), b"system config");
        assert_eq!(
            &*selected.read(OPENSSL_CA_BUNDLE).unwrap(),
            b"system bundle"
        );
        assert!(matches!(
            selected.lookup("/private/etc/ssl/local-key.pem"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            selected.lookup(&format!("/{OPENSSL_TEMPLATE}")),
            Err(Error::NotFound)
        ));

        let supplied = Files::default()
            .with_file(OPENSSL_CONFIG.into(), Arc::from(&b"guest config"[..]))
            .unwrap()
            .with_file(OPENSSL_CA_BUNDLE.into(), Arc::from(&b"guest bundle"[..]))
            .unwrap();
        let selected = select_native_root(&supplied, &fixture.dir, None).unwrap();
        assert_eq!(&*selected.read(OPENSSL_CONFIG).unwrap(), b"guest config");
        assert_eq!(&*selected.read(OPENSSL_CA_BUNDLE).unwrap(), b"guest bundle");

        let executable =
            select_native_root(&Files::default(), &fixture.dir, Some(OPENSSL_CA_BUNDLE)).unwrap();
        assert!(matches!(
            executable.lookup(OPENSSL_CA_BUNDLE),
            Err(Error::NotFound)
        ));

        #[cfg(unix)]
        {
            std::fs::remove_file(&ca_template).unwrap();
            std::os::unix::fs::symlink(&fixture.path, &ca_template).unwrap();
            let selected = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
            assert!(matches!(
                selected.lookup(OPENSSL_CA_BUNDLE),
                Err(Error::NotFound)
            ));
        }
    }

    #[test]
    fn native_selection_discovers_rosetta_primary_and_split_caches() {
        for rosetta in [
            "System/Cryptexes/Rosetta/System/Library/dyld",
            "System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld",
            "System/Cryptexes/Rosetta/System/x86Support/System/Library/dyld",
            "System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld",
        ] {
            let fixture = TestFile::new(b"root", 4);
            let dyld = fixture.dir.join("usr/lib/dyld");
            std::fs::create_dir_all(dyld.parent().unwrap()).unwrap();
            std::fs::write(&dyld, b"host-dyld").unwrap();
            let os = if rosetta.starts_with("System/Volumes/Preboot/") {
                "System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"
            } else {
                "System/Cryptexes/OS/System/Library/dyld"
            };
            let os = fixture.dir.join(os);
            std::fs::create_dir_all(&os).unwrap();
            std::fs::write(os.join("dyld_shared_cache_arm64e"), b"arm-cache").unwrap();
            let rosetta = fixture.dir.join(rosetta);
            std::fs::create_dir_all(&rosetta).unwrap();
            for (name, data) in [
                ("dyld_shared_cache_x86_64", &b"x64-cache"[..]),
                ("dyld_shared_cache_x86_64.01", &b"x64-split"[..]),
                ("dyld_shared_cache_x86_64.map", &b"metadata"[..]),
                ("aot_shared_cache.0", &b"translation"[..]),
            ] {
                std::fs::write(rosetta.join(name), data).unwrap();
            }
            let selected = select_native_root(&Files::default(), &fixture.dir, None).unwrap();
            assert_eq!(&*selected.read("/usr/lib/dyld").unwrap(), b"host-dyld");
            for (directory, name, bytes) in [
                (&os, "dyld_shared_cache_arm64e", &b"arm-cache"[..]),
                (&rosetta, "dyld_shared_cache_x86_64", &b"x64-cache"[..]),
                (&rosetta, "dyld_shared_cache_x86_64.01", &b"x64-split"[..]),
            ] {
                assert_eq!(
                    &*selected
                        .read(&format!("/System/Library/dyld/{name}"))
                        .unwrap(),
                    bytes
                );
                if let Some(path) = directory
                    .join(name)
                    .to_str()
                    .filter(|path| path.starts_with('/'))
                {
                    assert_eq!(&*selected.read(path).unwrap(), bytes);
                }
            }
            assert!(
                selected
                    .lookup("/System/Library/dyld/aot_shared_cache.0")
                    .is_err()
            );
            assert!(
                selected
                    .lookup("/System/Library/dyld/dyld_shared_cache_x86_64.map")
                    .is_err()
            );
            let supplied = Files::default()
                .with_file("/usr/lib/dyld".into(), Arc::from(&b"supplied-dyld"[..]))
                .unwrap()
                .with_file(
                    "/System/Library/dyld/dyld_shared_cache_x86_64".into(),
                    Arc::from(&b"supplied-cache"[..]),
                )
                .unwrap();
            let selected = select_native_root(&supplied, &fixture.dir, None).unwrap();
            assert_eq!(&*selected.read("/usr/lib/dyld").unwrap(), b"supplied-dyld");
            assert_eq!(
                &*selected
                    .read("/System/Library/dyld/dyld_shared_cache_x86_64")
                    .unwrap(),
                b"supplied-cache"
            );
        }
    }

    #[test]
    fn native_selection_rejects_roots_without_shared_caches() {
        let fixture = TestFile::new(b"root", 4);
        assert_eq!(
            select_native_root(&Files::default(), &fixture.dir, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn installed_timezone_paths_only_expose_selected_tzif_data() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let zones = root.join("var/db/timezone/zoneinfo");
        for dir in [
            lib.clone(),
            cache.clone(),
            zones.join("America"),
            root.join("usr/share"),
            root.join("etc"),
        ] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        symlink(
            "../../var/db/timezone/zoneinfo",
            root.join("usr/share/zoneinfo"),
        )
        .unwrap();
        symlink(
            "../var/db/timezone/zoneinfo/America/New_York",
            root.join("etc/localtime"),
        )
        .unwrap();

        let mut header = [0; 44];
        header[..5].copy_from_slice(b"TZif3");
        fs::write(zones.join("America/New_York"), header).unwrap();
        fs::write(zones.join("zone.tab"), b"text index").unwrap();
        fs::write(zones.join("../unselected"), header).unwrap();
        symlink("../unselected", zones.join("escape")).unwrap();
        fs::write(lib.join("timezone"), header).unwrap();

        let selected = select_native_root(&Files::default(), root, None).unwrap();
        for path in [
            "/var/db/timezone/zoneinfo/America/New_York",
            "/usr/share/zoneinfo/America/New_York",
            "/etc/localtime",
        ] {
            assert_eq!(&*selected.read(path).unwrap(), &header, "{path}");
        }
        for path in [
            "/var/db/timezone/zoneinfo/zone.tab",
            "/usr/share/zoneinfo/escape",
            "/var/db/timezone/unselected",
            "/usr/lib/timezone",
        ] {
            assert!(
                matches!(selected.read(path), Err(Error::NotFound)),
                "{path}"
            );
        }

        let override_path = "/var/db/timezone/zoneinfo/America/New_York";
        let explicit = Files::default()
            .with_file(override_path.into(), Arc::from(&b"supplied"[..]))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(&*selected.read(override_path).unwrap(), b"supplied");
    }

    #[cfg(unix)]
    #[test]
    fn installed_terminfo_mount_accepts_compiled_entries_and_confines_aliases() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unused", 8);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let terminfo = root.join(TERMINFO_ROOT.trim_start_matches('/'));
        for dir in [
            &lib,
            &cache,
            &terminfo.join("78"),
            &terminfo.join("v"),
            &terminfo.join("xx"),
        ] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        let terminfo_entry = |magic: u16| {
            let mut entry = [0; 12];
            entry[..2].copy_from_slice(&magic.to_le_bytes());
            entry
        };
        let legacy = terminfo_entry(0o432);
        let extended = terminfo_entry(0o1036);
        fs::write(terminfo.join("78/xterm"), legacy).unwrap();
        fs::write(terminfo.join("v/vt100"), extended).unwrap();
        fs::write(terminfo.join("78/xtruncated"), &legacy[..2]).unwrap();
        fs::write(terminfo.join("78/xtext"), b"not terminfo").unwrap();
        fs::write(terminfo.join("xx/xmisplaced"), legacy).unwrap();
        fs::write(lib.join("outside"), legacy).unwrap();
        symlink("xterm", terminfo.join("78/xalias")).unwrap();
        symlink(lib.join("outside"), terminfo.join("78/xescape")).unwrap();

        let files = select_native_root(&Files::default(), root, None).unwrap();
        for (path, data) in [
            ("/usr/share/terminfo/78/xterm", legacy),
            ("/usr/share/terminfo/78/xalias", legacy),
            ("/usr/share/terminfo/v/vt100", extended),
        ] {
            assert_eq!(&*files.read(path).unwrap(), &data);
        }
        for path in [
            "/usr/share/terminfo/78/xtruncated",
            "/usr/share/terminfo/78/xtext",
            "/usr/share/terminfo/xx/xmisplaced",
            "/usr/share/terminfo/78/xescape",
        ] {
            assert!(matches!(files.read(path), Err(Error::NotFound)), "{path}");
        }
        let path = "/usr/share/terminfo/78/xterm";
        let explicit = Files::default()
            .with_file(path.into(), Arc::from(b"override".as_slice()))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(&*selected.read(path).unwrap(), b"override");

        let selected = select_native_root(&Files::default(), root, Some(TERMINFO_ROOT))
            .unwrap()
            .with_file(TERMINFO_ROOT.into(), Arc::from(b"guest image".as_slice()))
            .unwrap();
        assert_eq!(&*selected.read(TERMINFO_ROOT).unwrap(), b"guest image");
    }

    #[cfg(unix)]
    #[test]
    fn installed_charset_mounts_admit_databases_and_confine_aliases() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unused", 8);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let esdb = root.join(CHARSET_ESDB_ROOT.trim_start_matches('/'));
        let mapper = root.join(CHARSET_MAPPER_ROOT.trim_start_matches('/'));
        for directory in [&lib, &cache, &esdb.join("UTF/sub"), &mapper.join("ISO646")] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        fs::write(esdb.join("esdb.dir"), b"UTF-8 UTF/UTF-8.esdb\n").unwrap();
        fs::write(esdb.join("esdb.dir.db"), b"LOOKUP\0\0").unwrap();
        fs::write(esdb.join("UTF/UTF-8.esdb"), b"ESDB\0\0\0\0").unwrap();
        fs::write(esdb.join("UTF/wrong.esdb"), b"MAPPER\0\0").unwrap();
        fs::write(esdb.join("UTF/sub/deep.esdb"), b"ESDB\0\0\0\0").unwrap();
        fs::write(mapper.join("charset.pivot.pvdb"), b"CSPIVOT\0").unwrap();
        fs::write(mapper.join("ISO646/UCS.mps"), b"MAPPER\0\0").unwrap();
        fs::write(mapper.join("ISO646/DE.646"), b"# translation\n").unwrap();
        fs::write(mapper.join("ISO646/unrelated.txt"), b"host data").unwrap();
        fs::write(lib.join("outside"), b"MAPPER\0\0").unwrap();
        symlink(lib.join("outside"), mapper.join("ISO646/escaped.mps")).unwrap();

        let files = select_native_root(&Files::default(), root, None).unwrap();
        for path in [
            "/usr/share/i18n/esdb/esdb.dir",
            "/usr/share/i18n/esdb/esdb.dir.db",
            "/usr/share/i18n/esdb/UTF/UTF-8.esdb",
            "/usr/share/i18n/csmapper/charset.pivot.pvdb",
            "/usr/share/i18n/csmapper/ISO646/UCS.mps",
            "/usr/share/i18n/csmapper/ISO646/DE.646",
        ] {
            assert!(!files.read(path).unwrap().is_empty(), "{path}");
        }
        for path in [
            "/usr/share/i18n/esdb/UTF/wrong.esdb",
            "/usr/share/i18n/esdb/UTF/sub/deep.esdb",
            "/usr/share/i18n/csmapper/ISO646/unrelated.txt",
            "/usr/share/i18n/csmapper/ISO646/escaped.mps",
        ] {
            assert!(matches!(files.read(path), Err(Error::NotFound)), "{path}");
        }
        let path = "/usr/share/i18n/esdb/UTF/UTF-8.esdb";
        let explicit = Files::default()
            .with_file(path.into(), Arc::from(b"override".as_slice()))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(&*selected.read(path).unwrap(), b"override");
    }

    #[cfg(unix)]
    #[test]
    fn installed_firmlink_manifest_preserves_namespace_boundaries() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"outside file", 20);
        let root = &fixture.dir;
        for path in ["usr/lib", "usr/share", "System/Library/dyld"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();

        let files = Files::default();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(
            selected.lookup(FIRMLINK_MANIFEST),
            Err(Error::NotFound)
        ));

        let manifest = root.join(FIRMLINK_MANIFEST.trim_start_matches('/'));
        let contents = b"/Applications\tApplications\n";
        fs::write(&manifest, contents).unwrap();
        fs::write(root.join("usr/share/adjacent"), b"unselected").unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert_eq!(&*selected.read(FIRMLINK_MANIFEST).unwrap(), contents);
        assert!(matches!(
            selected.lookup("/usr/share/adjacent"),
            Err(Error::NotFound)
        ));

        let supplied = files
            .with_file(
                FIRMLINK_MANIFEST.into(),
                Arc::from(b"caller manifest".as_slice()),
            )
            .unwrap();
        let selected = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(
            &*selected.read(FIRMLINK_MANIFEST).unwrap(),
            b"caller manifest"
        );

        let selected = select_native_root(&files, root, Some(FIRMLINK_MANIFEST)).unwrap();
        assert!(matches!(
            selected.lookup(FIRMLINK_MANIFEST),
            Err(Error::NotFound)
        ));

        fs::remove_file(&manifest).unwrap();
        symlink(&fixture.path, &manifest).unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(
            selected.lookup(FIRMLINK_MANIFEST),
            Err(Error::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installed_fallback_font_preserves_namespace_boundaries() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unrelated", 9);
        let root = &fixture.dir;
        for path in ["usr/lib", "System/Library/dyld", "System/Library/Fonts"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        let font = root.join(LAST_RESORT_FONT.trim_start_matches('/'));
        let adjacent = "/System/Library/Fonts/other.otf";
        fs::write(&font, b"fallback font").unwrap();
        fs::write(root.join(adjacent.trim_start_matches('/')), b"unselected").unwrap();

        let files = Files::default();
        let selected = select_native_root(&files, root, None).unwrap();
        assert_eq!(&*selected.read(LAST_RESORT_FONT).unwrap(), b"fallback font");
        assert!(matches!(selected.lookup(adjacent), Err(Error::NotFound)));

        let supplied = files
            .with_file(
                LAST_RESORT_FONT.into(),
                Arc::from(b"caller font".as_slice()),
            )
            .unwrap();
        let selected = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(&*selected.read(LAST_RESORT_FONT).unwrap(), b"caller font");

        let parent = "/System/Library/Fonts";
        let selected = select_native_root(&files, root, Some(parent))
            .unwrap()
            .with_file(parent.into(), Arc::from(b"main image".as_slice()))
            .unwrap();
        assert!(matches!(
            selected.lookup(LAST_RESORT_FONT),
            Err(Error::NotDirectory)
        ));

        fs::remove_file(&font).unwrap();
        symlink(&fixture.path, &font).unwrap();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(
            selected.lookup(LAST_RESORT_FONT),
            Err(Error::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installed_appearance_catalogs_stay_inside_the_system_bundle() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unrelated", 9);
        let root = &fixture.dir;
        let bundle = root.join(APPKIT_APPEARANCE_ROOT.trim_start_matches('/'));
        for directory in [
            root.join("usr/lib"),
            root.join("System/Library/dyld"),
            bundle.join("Resources/nested"),
            bundle.join("MacOS"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        fs::write(bundle.join("Info.plist"), b"bundle info").unwrap();
        fs::write(bundle.join("Resources/SystemAppearance.car"), b"catalog").unwrap();
        for unselected in [
            "MacOS/SystemAppearance",
            "Resources/nested/Other.car",
            "Resources/Other.plist",
        ] {
            fs::write(bundle.join(unselected), b"unselected").unwrap();
        }
        symlink(&fixture.path, bundle.join("Resources/External.car")).unwrap();

        let files = Files::default();
        let selected = select_native_root(&files, root, None).unwrap();
        let catalog = format!("{APPKIT_APPEARANCE_ROOT}/Resources/SystemAppearance.car");
        let info = format!("{APPKIT_APPEARANCE_ROOT}/Info.plist");
        assert_eq!(&*selected.read(&catalog).unwrap(), b"catalog");
        assert_eq!(&*selected.read(&info).unwrap(), b"bundle info");
        for hidden in [
            "MacOS/SystemAppearance",
            "Resources/nested/Other.car",
            "Resources/Other.plist",
            "Resources/External.car",
        ] {
            assert!(matches!(
                selected.read(&format!("{APPKIT_APPEARANCE_ROOT}/{hidden}")),
                Err(Error::NotFound)
            ));
        }
        let supplied = files
            .with_file(catalog.clone(), Arc::from(b"caller catalog".as_slice()))
            .unwrap();
        let selected = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(&*selected.read(&catalog).unwrap(), b"caller catalog");

        let parent = "/System/Library/CoreServices";
        let selected = select_native_root(&files, root, Some(parent))
            .unwrap()
            .with_file(parent.into(), Arc::from(b"main image".as_slice()))
            .unwrap();
        assert!(matches!(
            selected.lookup(&catalog),
            Err(Error::NotDirectory)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installed_applescript_bundle_selects_only_the_component_and_its_fixed_resources() {
        use crate::user::image::macho::{CPU_TYPE_ARM64, MH_BUNDLE, MH_EXECUTE, MH_MAGIC_64};
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unrelated", 9);
        let root = &fixture.dir;
        let bundle = root.join(APPLE_SCRIPT_ROOT.trim_start_matches('/'));
        for directory in [
            root.join("usr/lib"),
            root.join("System/Library/dyld"),
            bundle.join("MacOS"),
            bundle.join("Resources/en.lproj"),
            bundle.join("_CodeSignature"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        let mut image = [0; 32];
        image[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        image[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        image[12..16].copy_from_slice(&MH_BUNDLE.to_le_bytes());
        fs::write(bundle.join("MacOS/AppleScript"), image).unwrap();
        fs::write(bundle.join("MacOS/Neighbor"), image).unwrap();
        fs::write(bundle.join("Resources/AppleScript.rsrc"), b"resource").unwrap();
        fs::write(bundle.join("Resources/Neighbor.rsrc"), b"neighbor").unwrap();
        symlink(&fixture.path, bundle.join("Info.plist")).unwrap();
        let neighbor = bundle
            .parent()
            .unwrap()
            .with_file_name("Neighbor.component");
        fs::create_dir_all(neighbor.join("Contents")).unwrap();
        fs::write(neighbor.join("Contents/Info.plist"), b"neighbor").unwrap();

        let executable = format!("{APPLE_SCRIPT_ROOT}/MacOS/AppleScript");
        let resource = format!("{APPLE_SCRIPT_ROOT}/Resources/AppleScript.rsrc");
        let files = Files::default();
        let selected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(
            selected.lookup(&executable).unwrap().1.kind,
            Kind::Backed(_)
        ));
        assert_eq!(&*selected.read(&resource).unwrap(), b"resource");
        for hidden in ["Info.plist", "MacOS/Neighbor", "Resources/Neighbor.rsrc"] {
            assert!(matches!(
                selected.lookup(&format!("{APPLE_SCRIPT_ROOT}/{hidden}")),
                Err(Error::NotFound)
            ));
        }
        assert!(matches!(
            selected.lookup("/System/Library/Components/Neighbor.component/Contents/Info.plist"),
            Err(Error::NotFound)
        ));

        let supplied = files
            .clone()
            .with_file(executable.clone(), Arc::from(b"caller image".as_slice()))
            .unwrap();
        let overridden = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(&*overridden.read(&executable).unwrap(), b"caller image");
        image[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        fs::write(bundle.join("MacOS/AppleScript"), image).unwrap();
        let rejected = select_native_root(&files, root, None).unwrap();
        assert!(matches!(rejected.lookup(&executable), Err(Error::NotFound)));
    }

    #[test]
    fn installed_sandbox_profiles_are_confined_read_only_data() {
        use crate::user::supplied_fs::Error;
        use std::fs;

        let fixture = TestFile::new(b"unrelated", 9);
        let root = &fixture.dir;
        let profiles = root.join(SANDBOX_PROFILE_ROOT.trim_start_matches('/'));
        for directory in [
            root.join("usr/lib"),
            root.join("System/Library/dyld"),
            profiles.join("nested"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(root.join("usr/lib/dyld"), b"dyld").unwrap();
        fs::write(
            root.join("System/Library/dyld/dyld_shared_cache_arm64e"),
            b"cache",
        )
        .unwrap();
        fs::write(profiles.join("agent.sb"), b"(import \"system.sb\")").unwrap();
        fs::write(profiles.join("system.sb"), b"(deny default)").unwrap();
        fs::write(profiles.join("other.txt"), b"unrelated").unwrap();
        fs::write(
            profiles.join("nested/secret.sb"),
            b"outside the profile set",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink("agent.sb", profiles.join("alias.sb")).unwrap();
            symlink("other.txt", profiles.join("other.sb")).unwrap();
            symlink("nested/secret.sb", profiles.join("nested.sb")).unwrap();
            symlink(&fixture.path, profiles.join("external.sb")).unwrap();
        }

        let files = Files::default();
        let selected = select_native_root(&files, root, None).unwrap();
        let path = |name| format!("{SANDBOX_PROFILE_ROOT}/{name}");
        let agent = path("agent.sb");
        for (name, bytes) in [
            ("agent.sb", &b"(import \"system.sb\")"[..]),
            ("system.sb", &b"(deny default)"[..]),
        ] {
            let entry = selected.lookup(&path(name)).unwrap().1;
            assert!(selected.is_installed_entry(&entry));
            assert_eq!(&*entry.bytes().unwrap(), bytes);
        }
        for hidden in ["other.txt", "nested/secret.sb"] {
            assert!(matches!(selected.read(&path(hidden)), Err(Error::NotFound)));
        }
        #[cfg(unix)]
        {
            assert_eq!(
                &*selected.read(&path("alias.sb")).unwrap(),
                b"(import \"system.sb\")"
            );
            for hidden in ["other.sb", "nested.sb", "external.sb"] {
                assert!(matches!(selected.read(&path(hidden)), Err(Error::NotFound)));
            }
        }
        let supplied = files
            .with_file(agent.clone(), Arc::from(&b"caller profile"[..]))
            .unwrap();
        let override_files = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(&*override_files.read(&agent).unwrap(), b"caller profile");
        let selected = select_native_root(&files, root, Some(SANDBOX_PROFILE_ROOT))
            .unwrap()
            .with_file(SANDBOX_PROFILE_ROOT.into(), Arc::from(&b"main image"[..]))
            .unwrap();
        assert!(matches!(selected.read(&agent), Err(Error::NotDirectory)));
    }

    #[cfg(unix)]
    #[test]
    fn installed_locale_mount_confines_selected_resources() {
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unused", 8);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let locales = root.join("usr/share/locale");
        let source = locales.join("base");
        let selected = locales.join("example.UTF-8");
        for dir in [&lib, &cache, &source, &selected.join("LC_MESSAGES")] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        fs::write(lib.join("unselected"), b"outside locale").unwrap();
        fs::write(source.join("LC_CTYPE"), b"character types").unwrap();
        fs::write(selected.join("LC_MESSAGES/LC_MESSAGES"), b"messages").unwrap();
        fs::write(selected.join("unselected"), b"not a locale resource").unwrap();
        symlink("../base/LC_CTYPE", selected.join("LC_CTYPE")).unwrap();
        symlink(&lib.join("unselected"), selected.join("LC_NUMERIC")).unwrap();
        symlink(&lib, locales.join("outside")).unwrap();

        let ctype = "/usr/share/locale/example.UTF-8/LC_CTYPE";
        let files = select_native_root(&Files::default(), root, None).unwrap();
        assert_eq!(&*files.read(ctype).unwrap(), b"character types");
        assert_eq!(
            &*files
                .read("/usr/share/locale/example.UTF-8/LC_MESSAGES/LC_MESSAGES")
                .unwrap(),
            b"messages"
        );
        let children = |directory| {
            files
                .children(directory)
                .unwrap()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>()
        };
        assert_eq!(children("/usr/share/locale"), ["base", "example.UTF-8"]);
        assert_eq!(
            children("/usr/share/locale/example.UTF-8"),
            ["LC_CTYPE", "LC_MESSAGES"]
        );
        for path in [
            "/usr/share/locale/example.UTF-8/LC_NUMERIC",
            "/usr/share/locale/example.UTF-8/unselected",
            "/usr/share/locale/outside/LC_TIME",
            "/usr/lib/unselected",
        ] {
            assert!(matches!(files.read(path), Err(Error::NotFound)), "{path}");
        }

        let supplied = Files::default()
            .with_file(ctype.into(), Arc::from(&b"supplied"[..]))
            .unwrap();
        let files = select_native_root(&supplied, root, None).unwrap();
        assert_eq!(&*files.read(ctype).unwrap(), b"supplied");
    }

    #[cfg(unix)]
    #[test]
    fn installed_language_modules_are_read_only_and_confined_to_the_system_tree() {
        use crate::user::image::macho::{CPU_TYPE_X86_64, MH_BUNDLE, MH_EXECUTE, MH_MAGIC_64};
        use crate::user::supplied_fs::Error;
        use std::{fs, os::unix::fs::symlink};

        let fixture = TestFile::new(b"unused", 8);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let perl = root.join("System/Library/Perl/5.34");
        let xs = perl.join("darwin-thread-multi-2level/auto/Example");
        let versions = root.join(RUBY_VERSIONS.trim_start_matches('/'));
        let ruby = versions.join("2.6/usr/lib/ruby/2.6.0");
        for dir in [&lib, &cache, &xs, &ruby] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        fs::write(perl.join("Example.pm"), b"package Example; 1;").unwrap();
        fs::write(lib.join("Other.pm"), b"outside installed Perl").unwrap();
        symlink(lib.join("Other.pm"), perl.join("Escape.pm")).unwrap();
        fs::write(ruby.join("example.rb"), b"Example = 42").unwrap();
        fs::write(ruby.join("example.gemspec"), b"Gem::Specification.new").unwrap();
        fs::write(
            versions.join("2.6/unselected.rb"),
            b"file outside the runtime tree",
        )
        .unwrap();
        fs::write(lib.join("outside.rb"), b"outside Ruby").unwrap();
        symlink(lib.join("outside.rb"), ruby.join("escape.rb")).unwrap();
        symlink("2.6", versions.join("Current")).unwrap();

        let mut header = [0u8; 32];
        header[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        header[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        header[12..16].copy_from_slice(&MH_BUNDLE.to_le_bytes());
        fs::write(xs.join("Example.bundle"), header).unwrap();
        fs::write(perl.join("Unqualified.bundle"), header).unwrap();
        fs::write(lib.join("Other.bundle"), header).unwrap();
        fs::write(ruby.join("example.bundle"), header).unwrap();
        header[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        fs::write(xs.join("Executable.bundle"), header).unwrap();
        fs::write(ruby.join("executable.bundle"), header).unwrap();

        let selected = select_native_root(&Files::default(), root, None).unwrap();
        let module = "/System/Library/Perl/5.34/Example.pm";
        let bundle =
            "/System/Library/Perl/5.34/darwin-thread-multi-2level/auto/Example/Example.bundle";
        let entry = selected.lookup(module).unwrap().1;
        assert!(entry.host_file().is_some());
        assert_eq!(&*selected.read(module).unwrap(), b"package Example; 1;");
        let entry = selected.lookup(bundle).unwrap().1;
        assert!(entry.host_file().is_some());
        let ruby_root = format!("{RUBY_VERSIONS}/Current/usr/lib/ruby/2.6.0");
        for name in ["example.rb", "example.gemspec", "example.bundle"] {
            let path = format!("{ruby_root}/{name}");
            assert!(
                selected.lookup(&path).unwrap().1.host_file().is_some(),
                "{path}"
            );
        }
        for path in [
            "/System/Library/Perl/5.34/Escape.pm",
            "/System/Library/Perl/5.34/Unqualified.bundle",
            "/System/Library/Perl/5.34/darwin-thread-multi-2level/auto/Example/Executable.bundle",
            "/usr/lib/Other.pm",
            "/usr/lib/Other.bundle",
            &format!("{ruby_root}/escape.rb"),
            &format!("{ruby_root}/executable.bundle"),
            &format!("{RUBY_VERSIONS}/2.6/unselected.rb"),
        ] {
            assert!(
                matches!(selected.lookup(path), Err(Error::NotFound)),
                "{path}"
            );
        }

        let explicit = Files::default()
            .with_file(module.into(), Arc::from(&b"override"[..]))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(&*selected.read(module).unwrap(), b"override");
    }

    #[test]
    fn installed_framework_service_directories_require_framework_image_paths() {
        for path in [
            "/System/Library/Frameworks/Test.framework/Test",
            "/System/Library/PrivateFrameworks/Test.framework/Versions/A/Test",
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/Test.framework/Versions/Current/Test",
        ] {
            assert_eq!(
                framework_service_directory(path),
                path.rsplit_once('/')
                    .map(|(path, _)| format!("{path}/XPCServices"))
            );
        }
        for path in [
            "/tmp/Test.framework/Versions/A/Test",
            "/System/Library/Frameworks/Test.framework/Versions/../Test",
            "/System/Library/Frameworks/Test.framework/Resources/Test",
            "/System/Library/Frameworks/Test.framework/Versions/A/Other",
        ] {
            assert!(framework_service_directory(path).is_none(), "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn installed_framework_files_follow_bundle_aliases() {
        use crate::user::image::macho::{CPU_TYPE_ARM64, MH_DYLIB, MH_EXECUTE, MH_MAGIC_64};
        use crate::user::supplied_fs::Error;
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
        };

        let fixture = TestFile::new(b"root", 4);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let cache = root.join("System/Library/dyld");
        let system = root.join("System/Library/Frameworks");
        let cryptex = root.join("System/Cryptexes/OS/System/Library/Frameworks");
        let private = root.join("System/Library/PrivateFrameworks");
        let public = system.join("Public.framework");
        let overlay = cryptex.join("Overlay.framework");
        let local = private.join("Private.framework");
        for dir in [&lib, &cache] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(lib.join("dyld"), b"dyld").unwrap();
        fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        for (bundle, manifest) in [
            (&public, b"public".as_slice()),
            (&overlay, b"overlay"),
            (&local, b"private"),
        ] {
            let resources = bundle.join("Versions/A/Resources");
            fs::create_dir_all(&resources).unwrap();
            fs::write(resources.join("Info.plist"), manifest).unwrap();
            symlink("A", bundle.join("Versions/Current")).unwrap();
            symlink("Versions/Current/Resources", bundle.join("Resources")).unwrap();
        }
        symlink(&overlay, system.join("Overlay.framework")).unwrap();
        let unrelated = public.join("Versions/A/Resources/Other.plist");
        fs::write(&unrelated, b"other resource").unwrap();
        let escaped = system.join("Escaped.framework/Resources");
        fs::create_dir_all(&escaped).unwrap();
        symlink(&unrelated, escaped.join("Info.plist")).unwrap();
        let substituted = system.join("Substituted.framework/Resources");
        fs::create_dir_all(&substituted).unwrap();
        symlink(
            public.join("Resources/Info.plist"),
            substituted.join("Info.plist"),
        )
        .unwrap();
        let nested = public.join("Versions/A/Resources/Helper.app/Resources");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("Info.plist"), b"helper metadata").unwrap();

        let services = overlay.join("Versions/A/XPCServices");
        let service = "com.example.Worker.xpc";
        let contents = services.join(service).join("Contents");
        let executables = contents.join("MacOS");
        fs::create_dir_all(&executables).unwrap();
        symlink("Versions/Current/XPCServices", overlay.join("XPCServices")).unwrap();
        fs::write(contents.join("Info.plist"), b"worker manifest").unwrap();
        let mut image = [0u8; 32];
        image[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        image[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        image[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        let program = executables.join("Worker");
        fs::write(&program, image).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        let nonexecutable = executables.join("Nonexecutable");
        fs::write(&nonexecutable, image).unwrap();
        fs::set_permissions(&nonexecutable, fs::Permissions::from_mode(0o644)).unwrap();
        let script = executables.join("Script");
        fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        image[12..16].copy_from_slice(&MH_DYLIB.to_le_bytes());
        let library = executables.join("Library");
        fs::write(&library, image).unwrap();
        fs::set_permissions(&library, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&program, executables.join("Alias")).unwrap();
        let redirected = services.join("Redirected.xpc/Contents");
        fs::create_dir_all(&redirected).unwrap();
        symlink(contents.join("Info.plist"), redirected.join("Info.plist")).unwrap();
        fs::write(contents.join("Unrelated.plist"), b"unrelated").unwrap();

        let selected = select_native_root(&Files::default(), root, None).unwrap();
        let public_guest = "/System/Library/Frameworks/Public.framework";
        for (bundle, manifest) in [
            (public_guest, b"public".as_slice()),
            ("/System/Library/Frameworks/Overlay.framework", b"overlay"),
            (
                "/System/Library/PrivateFrameworks/Private.framework",
                b"private",
            ),
        ] {
            for alias in [
                "Resources",
                "Versions/Current/Resources",
                "Versions/A/Resources",
            ] {
                let path = format!("{bundle}/{alias}/Info.plist");
                assert_eq!(&*selected.read(&path).unwrap(), manifest, "{path}");
            }
        }
        for path in [
            "/System/Library/Frameworks/Escaped.framework/Resources/Info.plist",
            "/System/Library/Frameworks/Substituted.framework/Resources/Info.plist",
            &format!("{public_guest}/Resources/Other.plist"),
            &format!("{public_guest}/Resources/Helper.app/Resources/Info.plist"),
        ] {
            assert!(
                matches!(selected.lookup(path), Err(Error::NotFound)),
                "{path}"
            );
        }
        let framework = "/System/Library/Frameworks/Overlay.framework";
        for view in [
            "XPCServices",
            "Versions/Current/XPCServices",
            "Versions/A/XPCServices",
        ] {
            let bundle = format!("{framework}/{view}/{service}/Contents");
            let manifest = format!("{bundle}/Info.plist");
            let executable = format!("{bundle}/MacOS/Worker");
            assert_eq!(&*selected.read(&manifest).unwrap(), b"worker manifest");
            for path in [&manifest, &executable] {
                let entry = selected.lookup(path).unwrap().1;
                assert!(selected.is_installed_entry(&entry), "{path}");
            }
            assert_eq!(
                &*selected.read(&executable).unwrap(),
                &fs::read(&program).unwrap()
            );
        }
        let services = format!("{framework}/XPCServices");
        let bundle = format!("{services}/{service}/Contents");
        let manifest = format!("{bundle}/Info.plist");
        let replaced = selected
            .with_file(manifest.clone(), Arc::from(&b"caller manifest"[..]))
            .unwrap();
        let entry = replaced.lookup(&manifest).unwrap().1;
        assert!(!replaced.is_installed_entry(&entry));
        assert_eq!(
            &*selected.read(&format!("{bundle}/MacOS/Library")).unwrap(),
            &image
        );
        for path in [
            format!("{bundle}/Unrelated.plist"),
            format!("{bundle}/MacOS/Nonexecutable"),
            format!("{bundle}/MacOS/Script"),
            format!("{bundle}/MacOS/Alias"),
            format!("{services}/Redirected.xpc/Contents/Info.plist"),
        ] {
            assert!(
                matches!(selected.lookup(&path), Err(Error::NotFound)),
                "{path}"
            );
        }

        let override_path = format!("{public_guest}/Resources/Info.plist");
        let explicit = Files::default()
            .with_file(override_path.clone(), Arc::from(&b"caller manifest"[..]))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(&*selected.read(&override_path).unwrap(), b"caller manifest");
    }

    #[cfg(unix)]
    #[test]
    fn installed_dylibs_preserve_explicit_files_and_reject_other_backings() {
        use crate::user::image::macho::{
            CPU_TYPE_ARM64, FAT_MAGIC, MH_DYLIB, MH_EXECUTE, MH_MAGIC_64,
        };
        let fixture = TestFile::new(b"root", 4);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let framework = root.join("System/Library/Frameworks/Example.framework");
        let version = framework.join("Versions/A");
        let runtime_path = "/System/Library/Perl/5.0/CORE";
        let runtime = root.join(runtime_path.trim_start_matches('/'));
        let cryptex_path = "/System/Cryptexes/OS/System/Library/Perl/CORE";
        let cryptex = root.join(cryptex_path.trim_start_matches('/'));
        let rosetta_path = "/System/Cryptexes/Rosetta/usr/lib";
        let rosetta = root.join(rosetta_path.trim_start_matches('/'));
        let cache = root.join("System/Library/dyld");
        for dir in [&lib, &version, &runtime, &cryptex, &rosetta, &cache] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(lib.join("dyld"), b"dyld").unwrap();
        std::fs::write(cache.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        let mut thin = [0u8; 32];
        thin[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        thin[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        thin[12..16].copy_from_slice(&MH_DYLIB.to_le_bytes());
        std::fs::write(lib.join("libonly.dylib"), thin).unwrap();
        std::fs::write(version.join("Example"), thin).unwrap();
        std::fs::write(runtime.join("liblanguage.dylib"), thin).unwrap();
        std::fs::write(runtime.join("settings.txt"), b"unrelated runtime metadata").unwrap();
        std::fs::write(cryptex.join("libalternate.dylib"), thin).unwrap();
        std::fs::write(rosetta.join("libextra.dylib"), thin).unwrap();
        std::os::unix::fs::symlink("A", framework.join("Versions/Current")).unwrap();
        std::os::unix::fs::symlink("Versions/Current/Example", framework.join("Example")).unwrap();
        std::fs::hard_link(version.join("Example"), version.join("HardLink")).unwrap();
        std::fs::write(version.join("DifferentFile"), thin).unwrap();
        let outside = root.join("secret.dylib");
        std::fs::write(&outside, thin).unwrap();
        std::os::unix::fs::symlink(&outside, lib.join("escape.dylib")).unwrap();
        std::os::unix::fs::symlink(&outside, runtime.join("escape.dylib")).unwrap();
        std::fs::write(lib.join("text.dylib"), b"unrelated text").unwrap();
        let mut executable = thin;
        executable[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        std::fs::write(lib.join("executable"), executable).unwrap();

        let slice = 1u32 << 15;
        let mut fat = vec![0; slice as usize];
        for (field, value) in [
            FAT_MAGIC,
            1,
            CPU_TYPE_ARM64,
            0,
            slice,
            thin.len() as u32,
            15,
        ]
        .into_iter()
        .enumerate()
        {
            fat[field * 4..(field + 1) * 4].copy_from_slice(&value.to_be_bytes());
        }
        fat.extend_from_slice(&thin);
        std::fs::write(lib.join("libfat.dylib"), &fat).unwrap();
        fat[slice as usize + 12..slice as usize + 16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        std::fs::write(lib.join("mixed.dylib"), fat).unwrap();

        let caller = TestFile::new(b"caller", 6);
        let explicit = Files::default()
            .with_file("/usr/lib/libonly.dylib".into(), Arc::from(&b"explicit"[..]))
            .unwrap()
            .with_host_roots(std::collections::BTreeMap::from([(
                "/other".into(),
                caller.dir.clone(),
            )]))
            .unwrap();
        let selected = select_native_root(&explicit, root, None).unwrap();
        assert_eq!(
            &*selected.read("/usr/lib/libonly.dylib").unwrap(),
            b"explicit"
        );
        let framework = "/System/Library/Frameworks/Example.framework";
        let versioned = selected
            .lookup(&format!("{framework}/Versions/A/Example"))
            .unwrap()
            .1;
        for alias in ["Example", "Versions/Current/Example", "Versions/A/HardLink"] {
            let alias = selected.lookup(&format!("{framework}/{alias}")).unwrap().1;
            assert_eq!(alias.ino, versioned.ino);
            assert_eq!(&*alias.bytes().unwrap(), &thin);
        }
        let separate = selected
            .lookup(&format!("{framework}/Versions/A/DifferentFile"))
            .unwrap()
            .1;
        assert_ne!(separate.ino, versioned.ino);
        assert_eq!(
            &*selected
                .read(&format!("{rosetta_path}/libextra.dylib"))
                .unwrap(),
            &thin
        );
        for path in [
            format!("{runtime_path}/liblanguage.dylib"),
            format!("{cryptex_path}/libalternate.dylib"),
        ] {
            let entry = selected.lookup(&path).unwrap().1;
            assert!(entry.host_file().is_some(), "{path}");
            assert_eq!(&*selected.read(&path).unwrap(), &thin);
        }
        for path in [
            format!("{runtime_path}/settings.txt"),
            format!("{runtime_path}/escape.dylib"),
        ] {
            assert!(selected.lookup(&path).is_err(), "{path}");
        }
        assert_eq!(
            &*selected
                .read(&format!(
                    "/other/{}",
                    caller.path.file_name().unwrap().to_str().unwrap()
                ))
                .unwrap(),
            b"caller"
        );
        assert!(matches!(
            selected.lookup("/usr/lib/libfat.dylib").unwrap().1.kind,
            Kind::Backed(_)
        ));
        for path in [
            "/usr/lib/escape.dylib",
            "/usr/lib/text.dylib",
            "/usr/lib/executable",
            "/usr/lib/mixed.dylib",
            "/secret.dylib",
        ] {
            assert!(selected.lookup(path).is_err(), "{path}");
        }
        let names: Vec<_> = selected
            .children("/usr/lib")
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["dyld", "libfat.dylib", "libonly.dylib"]);

        let framework_root = "/System/Library/Frameworks";
        let blocked = explicit
            .with_file(framework_root.into(), Arc::from(&b"caller file"[..]))
            .unwrap();
        let selected = select_native_root(&blocked, root, None).unwrap();
        assert_eq!(&*selected.read(framework_root).unwrap(), b"caller file");
        assert!(
            selected
                .lookup("/System/Library/Frameworks/Example.framework/Example")
                .is_err()
        );
        assert!(selected.lookup("/usr/lib/libfat.dylib").is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn native_darwin_files_report_a_host_mismatch() {
        assert_eq!(
            native(&Files::default()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_runtime_executes_system_programs_in_a_closed_process() {
        use crate::user::darwin::abi::DarwinAbi;
        let files = native(&Files::default()).expect("macOS host dyld and shared cache");
        // The runtime belongs to the host OS. A translated x86-64 test process
        // on Apple silicon need not have an x86-64 cache installed. Exercise
        // each supplied cache ABI explicitly, independently of the compiler ABI.
        let mut abis = Vec::new();
        for (abi, name) in [
            (DarwinAbi::Arm64, "arm64e"),
            (DarwinAbi::Arm64, "arm64"),
            (DarwinAbi::X86_64, "x86_64h"),
            (DarwinAbi::X86_64, "x86_64"),
        ] {
            let path = format!("/System/Library/dyld/dyld_shared_cache_{name}");
            if files.lookup(&path).is_ok() && !abis.contains(&abi) {
                abis.push(abi);
            }
        }
        assert!(
            !abis.is_empty(),
            "no supported primary shared cache supplied"
        );
        for abi in abis {
            eprintln!("closed native runtime cache ABI: {abi:?}");
            run_system_programs(&files, abi);
        }
    }

    #[cfg(target_os = "macos")]
    fn run_system_programs(files: &Files, abi: crate::user::darwin::abi::DarwinAbi) {
        use crate::user::darwin::{
            DarwinConfig, DarwinProcess, ExitStatus, RunStatus, loader::ImageFile,
        };
        let version_tool = "/usr/bin/sw_vers";
        let version = std::process::Command::new(version_tool)
            .arg("-productVersion")
            .output()
            .unwrap();
        assert!(version.status.success());
        assert!(version.stderr.is_empty());
        let listing = std::process::Command::new("/bin/ls")
            .args(["-1", "/bin"])
            .env_clear()
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(listing.status.success());
        assert!(listing.stderr.is_empty());
        for (path, arguments, expected) in [
            (
                "/bin/ls",
                vec![b"-1".to_vec(), b"/bin".to_vec()],
                listing.stdout,
            ),
            ("/usr/bin/true", vec![], vec![]),
            (
                "/usr/bin/printf",
                vec![b"%s\\n".to_vec(), b"native-cache".to_vec()],
                b"native-cache\n".to_vec(),
            ),
            (
                version_tool,
                vec![b"-productVersion".to_vec()],
                version.stdout,
            ),
        ] {
            let console = crate::user::console::CapturedConsole::new(Vec::new(), 65536).unwrap();
            let mut argv = vec![b"/program".to_vec()];
            argv.extend(arguments);
            let mut config =
                DarwinConfig::embedded("/program", argv, vec![], files.clone(), console.clone());
            config.abi = Some(abi);
            config.arena_bytes = 256 << 20;
            config.slice_insns = 4096;
            let image = ImageFile::new(std::fs::read(path).unwrap(), "/program");
            let mut process = DarwinProcess::spawn(config, image).unwrap();
            assert!(!process.proc.config.host_services);
            assert!(process.proc.vfs.is_closed());
            // Bound guest work, independently of time spent descheduled by
            // unrelated host workloads. Each turn requests at most slice_insns
            // CPU instructions; this is a cooperative functional-test bound.
            const MAX_TURNS: u64 = 16_384;
            const SLICE_TURNS: u64 = 256;
            let mut remaining = MAX_TURNS;
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            loop {
                assert!(
                    remaining != 0,
                    "{path}: native runtime exceeded {MAX_TURNS} scheduler turns"
                );
                let turns = remaining.min(SLICE_TURNS);
                remaining -= turns;
                match process.run_slice(turns, &cancelled) {
                    RunStatus::BudgetExhausted => {}
                    RunStatus::Complete(status) => {
                        let mut stderr = vec![0; 65536];
                        let stderr_len = console
                            .drain(crate::user::console::OutputStream::Stderr, &mut stderr)
                            .unwrap();
                        assert_eq!(
                            status,
                            ExitStatus::Exited(0),
                            "{path}: {}",
                            String::from_utf8_lossy(&stderr[..stderr_len])
                        );
                        assert_eq!(&stderr[..stderr_len], b"", "{path}");
                        assert!(
                            process.proc.shared_region.is_some(),
                            "{path} did not use the shared cache"
                        );
                        let mut stdout = vec![0; 65536];
                        let n = console
                            .drain(crate::user::console::OutputStream::Stdout, &mut stdout)
                            .unwrap();
                        assert_eq!(&stdout[..n], expected, "{path}");
                        eprintln!(
                            "{path} {abi:?}: completed within {} scheduler turns",
                            MAX_TURNS - remaining
                        );
                        break;
                    }
                    other => panic!("{path}: native runtime stopped: {other:?}"),
                }
            }
        }
    }
}
