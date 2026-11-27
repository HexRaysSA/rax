//! Counted NT names retain filesystem spelling; no Win32 dot/space cleanup.

#[cfg(unix)]
pub(in super::super) mod unix;

use super::super::named_object::{Checked, status};
use super::attributes::Attributes;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::fs::find_case_insensitive;
use crate::user::windows::hle::Ctx;
use crate::user::windows::layout::WOW64_TEB_FS_REDIRECTION;
use crate::user::windows::memory::Mem;
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const CLR_LOADER: &str = "mscoreei.dll";
const CLR_V4: &str = "v4.0.30319";
const CLR_VERSION_DIRECTORIES: [&str; 2] = [CLR_V4, "Upgrades.4.0.30319"];

pub(in super::super) fn clr_version_directory_name(c: &Ctx, name: &[u16]) -> bool {
    CLR_VERSION_DIRECTORIES
        .iter()
        .any(|version| equal(c, name, &version.encode_utf16().collect::<Vec<_>>()))
}

fn clr_image_name(c: &Ctx, version: &[u16], name: &[u16]) -> Option<&'static str> {
    if !clr_version_directory_name(c, version) {
        return None;
    }
    let names: &[&str] = if equal(c, version, &CLR_V4.encode_utf16().collect::<Vec<_>>()) {
        &[CLR_LOADER, "clr.dll", "mscorwks.dll"]
    } else {
        &[CLR_LOADER]
    };
    names
        .iter()
        .copied()
        .find(|name_match| equal(c, name, &name_match.encode_utf16().collect::<Vec<_>>()))
}

pub(in super::super) struct Resolved {
    pub(in super::super) host: PathBuf,
    pub(in super::super) base: PathBuf,
    pub(in super::super) root: Option<u64>,
    /// A counted child name resolved relative to the retained directory handle.
    pub(in super::super) relative: Option<PathBuf>,
    pub(in super::super) directory: bool,
    pub(in super::super) runtime_library: bool,
    pub(in super::super) no_reparse: bool,
}

fn canonical_root(c: &Ctx, path: &Path) -> Checked<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
                status(STATUS_OBJECT_PATH_NOT_FOUND)
            }
            std::io::ErrorKind::PermissionDenied => status(STATUS_ACCESS_DENIED),
            _ => Err(c.unsupported(format!("mapped file root: {error}")).into()),
        },
    }
}

pub(in super::super) fn equal(c: &Ctx, a: &[u16], b: &[u16]) -> bool {
    let table = c.p.registry.upcase_table();
    let fold = |unit: u16| {
        table.get(usize::from(unit)).copied().unwrap_or_else(|| {
            if (97..=122).contains(&unit) {
                unit - 32
            } else {
                unit
            }
        })
    };
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| fold(*a) == fold(*b))
}

fn host_component(c: &Ctx, units: &[u16]) -> Checked<OsString> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let _ = c;
        Ok(OsString::from_wide(units))
    }
    #[cfg(not(windows))]
    {
        String::from_utf16(units).map(OsString::from).map_err(|_| {
            c.unsupported("unpaired UTF-16 file name cannot be represented by this host filesystem")
                .into()
        })
    }
}

fn append(c: &Ctx, mut host: PathBuf, parts: &[&[u16]]) -> Checked<PathBuf> {
    for part in parts {
        let spelling = host_component(c, part)?;
        let exact = host.join(&spelling);
        if exact.try_exists().unwrap_or(false) {
            host = exact;
            continue;
        }
        let mut found = None;
        if let Ok(entries) = std::fs::read_dir(&host) {
            for entry in entries {
                let entry = entry
                    .map_err(|error| c.unsupported(format!("file directory capture: {error}")))?;
                #[cfg(windows)]
                let units: Vec<u16> = {
                    use std::os::windows::ffi::OsStrExt;
                    entry.file_name().encode_wide().collect()
                };
                #[cfg(not(windows))]
                let units: Vec<u16> = match entry.file_name().to_str() {
                    Some(name) => name.encode_utf16().collect(),
                    None => continue,
                };
                if equal(c, part, &units) {
                    if found.is_some() {
                        return Err(c
                            .unsupported("ambiguous case-insensitive mapped file name")
                            .into());
                    }
                    found = Some(entry.path());
                }
            }
        }
        host = found.unwrap_or(exact);
    }
    Ok(host)
}

fn parts<'a>(c: &Ctx, name: &'a [u16]) -> Checked<(Vec<&'a [u16]>, bool)> {
    let directory = name.last() == Some(&u16::from(b'\\'));
    let trimmed = if directory {
        &name[..name.len() - 1]
    } else {
        name
    };
    if trimmed.is_empty() {
        return Ok((Vec::new(), directory));
    }
    let mut parts = Vec::new();
    for part in trimmed.split(|unit| *unit == u16::from(b'\\')) {
        if part.is_empty()
            || part == [46, 46]
            || part.contains(&0)
            || part
                .iter()
                .any(|unit| [34, 42, 47, 60, 62, 63, 124].contains(unit))
        {
            return status(STATUS_OBJECT_NAME_INVALID);
        }
        if part == [46] {
            return status(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if part.contains(&u16::from(b':')) {
            return Err(c.unsupported("NT alternate data stream metadata").into());
        }
        parts.push(part);
    }
    Ok((parts, directory))
}

fn confined_child(c: &Ctx, directory: &Path, name: &str, missing: u32) -> Checked<PathBuf> {
    let Some(path) = find_case_insensitive(directory, name) else {
        return status(missing);
    };
    let canonical = canonical_root(c, &path)?;
    if canonical.parent() != Some(directory)
        || !canonical
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(name))
    {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(canonical)
}

fn selected_mui(
    c: &Ctx,
    runtime: &NativeRuntime,
    path: &[u16],
    system32_alias: bool,
) -> Checked<Option<(PathBuf, PathBuf)>> {
    let Some(separator) = path.iter().position(|&unit| unit == u16::from(b'\\')) else {
        return Ok(None);
    };
    let (locale, filename) = (&path[..separator], &path[separator + 1..]);
    if locale.is_empty()
        || locale.len() > 85
        || !locale.split(|&unit| unit == u16::from(b'-')).all(|part| {
            (1..=8).contains(&part.len())
                && part
                    .iter()
                    .all(|&unit| matches!(unit, 48..=57 | 65..=90 | 97..=122))
        })
        || filename.contains(&u16::from(b'\\'))
    {
        return Ok(None);
    }
    let filename = String::from_utf16(filename)
        .map_err(|_| c.unsupported("selected MUI filename is not Unicode"))?;
    let Some((owner, suffix)) = filename.rsplit_once('.') else {
        return Ok(None);
    };
    if !suffix.eq_ignore_ascii_case("mui") {
        return Ok(None);
    }
    let installed_executable = c.p.modules.installed_executable
        && c.p
            .modules
            .list
            .first()
            .is_some_and(|exe| owner.eq_ignore_ascii_case(&exe.name));
    let installed_dll = owner.to_ascii_lowercase().ends_with(".dll")
        && runtime
            .dll(owner)
            .map_err(|error| c.unsupported(format!("selected MUI owner: {error}")))?
            .is_some();
    if !installed_executable && !installed_dll {
        return Ok(None);
    }
    let version = &c.p.cfg.version;
    let qualified_profile = matches!(
        (
            version.major,
            version.minor,
            version.build,
            c.p.object_namespace.native_machine
        ),
        (10, 0, 20348 | 26100, Some(0x8664)) | (10, 0, 26200 | 29708, Some(0xaa64))
    );
    let native_system32 = system32_alias
        && qualified_profile
        && c.t
            .teb_allocation
            .companion()
            .is_some_and(|teb| matches!(c.mem().ptr(teb + WOW64_TEB_FS_REDIRECTION, 8), Ok(1)));
    let directory = if native_system32 {
        let parent = runtime
            .directory
            .parent()
            .ok_or_else(|| c.unsupported("installed Windows directory has no parent"))?;
        confined_child(c, parent, "System32", STATUS_OBJECT_PATH_NOT_FOUND)?
    } else {
        runtime.directory.clone()
    };
    let locale = String::from_utf16(locale).expect("validated ASCII locale name");
    let locale = confined_child(c, &directory, &locale, STATUS_OBJECT_PATH_NOT_FOUND)?;
    let file = confined_child(c, &locale, &filename, STATUS_OBJECT_NAME_NOT_FOUND)?;
    Ok(Some((directory, file)))
}

fn selected_main_file(c: &Ctx, runtime: &NativeRuntime, path: &[u16]) -> Checked<Option<PathBuf>> {
    if c.p.cfg.host_filesystem || !c.p.modules.installed_executable {
        return Ok(None);
    }
    let executable = c.p.modules.executable_path();
    let Some(relative) = runtime.executable_relative(executable) else {
        return Ok(None);
    };
    let name: Vec<u16> = executable.encode_utf16().collect();
    let suffix: Vec<u16> = ".config".encode_utf16().collect();
    let config = path.len() == name.len() + suffix.len()
        && equal(c, &path[..name.len()], &name)
        && equal(c, &path[name.len()..], &suffix);
    if !config && !equal(c, path, &name) {
        return Ok(None);
    }
    let (parents, filename) = relative.rsplit_once('\\').unwrap_or(("", relative));
    let mut directory = runtime.directory.clone();
    for part in parents.split('\\').filter(|part| !part.is_empty()) {
        directory = confined_child(c, &directory, part, STATUS_OBJECT_PATH_NOT_FOUND)?;
        if !directory.is_dir() {
            return status(STATUS_OBJECT_PATH_NOT_FOUND);
        }
    }
    let filename = if config {
        format!("{filename}.config")
    } else {
        filename.to_owned()
    };
    let host = confined_child(c, &directory, &filename, STATUS_OBJECT_NAME_NOT_FOUND)?;
    if !host.is_file() {
        return status(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    Ok(Some(host))
}

fn selected(c: &Ctx, path: &[u16]) -> Checked<Option<(PathBuf, PathBuf, bool)>> {
    let Some(runtime) = &c.p.native else {
        return Ok(None);
    };
    if let Some(file) = selected_main_file(c, runtime, path)? {
        return Ok(Some((runtime.directory.clone(), file, true)));
    }
    if let Some(separator) = path.iter().rposition(|unit| *unit == u16::from(b'\\'))
        && let Some(version) = path[..separator]
            .rsplit(|unit| *unit == u16::from(b'\\'))
            .next()
        && let Some(name) = clr_image_name(c, version, &path[separator + 1..])
        && let Some(framework) = framework_directory(c, &path[..separator])?
        && let Some(base) = framework.framework
    {
        let image = confined_child(c, &base, name, STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !image.is_file() {
            return status(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return Ok(Some((base, image, true)));
    }
    let windows = runtime.guest_root.trim_end_matches('\\');
    let sort_table: Vec<_> = format!(r"{windows}\Globalization\Sorting\SortDefault.nls")
        .encode_utf16()
        .collect();
    if equal(c, path, &sort_table) {
        let root = runtime
            .directory
            .parent()
            .ok_or_else(|| c.unsupported("installed Windows directory has no parent"))?;
        let global = confined_child(c, root, "Globalization", STATUS_OBJECT_PATH_NOT_FOUND)?;
        let base = confined_child(c, &global, "Sorting", STATUS_OBJECT_PATH_NOT_FOUND)?;
        let file = confined_child(c, &base, "SortDefault.nls", STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !file.is_file() {
            return status(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return Ok(Some((base, file, false)));
    }
    let mut prefixes = vec![(runtime.guest_directory.clone(), false)];
    if c.arch() == WinArch::X86 {
        prefixes.push((format!(r"{windows}\System32"), true));
    }
    for (prefix, system32_alias) in prefixes {
        let prefix: Vec<u16> = prefix.encode_utf16().collect();
        if path.len() <= prefix.len()
            || !equal(c, &path[..prefix.len()], &prefix)
            || path[prefix.len()] != u16::from(b'\\')
        {
            continue;
        }
        let basename = &path[prefix.len() + 1..];
        if !c.p.cfg.host_filesystem && basename.contains(&u16::from(b'\\')) {
            return selected_mui(c, runtime, basename, system32_alias)
                .map(|selected| selected.map(|(base, file)| (base, file, false)));
        }
        if basename.len() < 5 {
            continue;
        }
        let extension = &basename[basename.len() - 4..];
        let dll = equal(c, extension, &[46, 100, 108, 108]);
        let executable = !c.p.cfg.host_filesystem && equal(c, extension, &[46, 101, 120, 101]);
        if !dll && !executable {
            continue;
        }
        if basename.contains(&u16::from(b'\\')) || basename.contains(&u16::from(b'/')) {
            continue;
        }
        let name = String::from_utf16(basename)
            .map_err(|_| c.unsupported("selected runtime image basename is not Unicode"))?;
        if executable && !runtime.admits_child_executable(c.arch(), &name) {
            continue;
        }
        return match runtime.dll_paths(&name) {
            Ok(Some((spelling, _))) => Ok(Some((
                runtime.directory.clone(),
                spelling,
                name.eq_ignore_ascii_case(CLR_LOADER),
            ))),
            Ok(None) => status(STATUS_OBJECT_NAME_NOT_FOUND),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                status(STATUS_ACCESS_DENIED)
            }
            Err(error) => Err(c
                .unsupported(format!("selected runtime image metadata path: {error}"))
                .into()),
        };
    }
    Ok(None)
}

pub(in super::super) fn resolve(
    c: &Ctx,
    attrs: &Attributes,
    name: Option<&[u16]>,
) -> Checked<Resolved> {
    resolve_kind(c, attrs, name, true)
}

pub(in super::super) fn resolve_open(
    c: &Ctx,
    attrs: &Attributes,
    name: Option<&[u16]>,
) -> Checked<Resolved> {
    resolve_kind(c, attrs, name, true)
}

pub(in super::super) fn dos_tail<'a>(c: &Ctx, name: &'a [u16]) -> Option<&'a [u16]> {
    let short: Vec<u16> = "\\??\\".encode_utf16().collect();
    let long: Vec<u16> = "\\DosDevices\\".encode_utf16().collect();
    if let Some(path) = name.strip_prefix(short.as_slice()) {
        Some(path)
    } else if name.len() >= long.len() && equal(c, &name[..long.len()], &long) {
        Some(&name[long.len()..])
    } else {
        None
    }
}

/// The finite directory tree exposed by the closed installed runtime.
pub(in super::super) fn guest_directories(c: &Ctx) -> Option<Vec<String>> {
    if c.p.cfg.host_filesystem {
        return None;
    }
    let runtime = c.p.native.as_ref()?;
    let drive = runtime.guest_root.split_once(':')?.0;
    let windows = runtime.guest_root.trim_end_matches('\\');
    let mut names = vec![
        format!("{drive}:\\"),
        windows.to_owned(),
        runtime.guest_directory.trim_end_matches('\\').to_owned(),
    ];
    if c.arch() == WinArch::X86 {
        let system32 = format!(r"{windows}\System32");
        if !names[2].eq_ignore_ascii_case(&system32) {
            names.push(system32);
        }
    }
    Some(names)
}

pub(in super::super) struct GuestDirectory {
    pub(in super::super) guest: String,
    pub(in super::super) framework: Option<PathBuf>,
    pub(in super::super) framework_installation: bool,
}

/// Select the CLR installation root and its supported version directories
/// for this guest architecture.
pub(in super::super) fn framework_directory(
    c: &Ctx,
    dos: &[u16],
) -> Checked<Option<GuestDirectory>> {
    let Some(runtime) = c.p.native.as_ref().filter(|_| !c.p.cfg.host_filesystem) else {
        return Ok(None);
    };
    let directory = match c.arch() {
        WinArch::Arm64 => "FrameworkArm64",
        WinArch::X64 => "Framework64",
        WinArch::X86 => "Framework",
    };
    let root = runtime.guest_root.trim_end_matches('\\');
    let prefix = format!(r"{root}\Microsoft.NET\{directory}");
    let Some((guest, version)) = std::iter::once((prefix.clone(), None))
        .chain(
            CLR_VERSION_DIRECTORIES
                .into_iter()
                .map(|version| (format!(r"{prefix}\{version}"), Some(version))),
        )
        .find(|(guest, _)| equal(c, dos, &guest.encode_utf16().collect::<Vec<_>>()))
    else {
        return Ok(None);
    };
    let windows = runtime
        .directory
        .parent()
        .ok_or_else(|| c.unsupported("installed Windows directory has no parent"))?;
    let framework = confined_child(c, windows, "Microsoft.NET", STATUS_OBJECT_PATH_NOT_FOUND)?;
    let framework = confined_child(c, &framework, directory, STATUS_OBJECT_PATH_NOT_FOUND)?;
    let framework = match version {
        Some(version) => confined_child(c, &framework, version, STATUS_OBJECT_NAME_NOT_FOUND)?,
        None => framework,
    };
    if !framework.is_dir() {
        return status(crate::user::windows::nt::status::STATUS_NOT_A_DIRECTORY);
    }
    Ok(Some(GuestDirectory {
        guest,
        framework: Some(framework),
        framework_installation: version.is_none(),
    }))
}

/// Match an absolute DOS name or a name relative to a guest-only directory handle.
pub(in super::super) fn guest_directory(
    c: &Ctx,
    root: u64,
    name: &[u16],
) -> Checked<Option<GuestDirectory>> {
    let Some(names) = guest_directories(c) else {
        return Ok(None);
    };
    let absolute;
    let dos = if root == 0 {
        let Some(dos) = dos_tail(c, name) else {
            return Ok(None);
        };
        dos
    } else {
        let Some(Object::File(file)) = c.p.objects.get(root) else {
            return Ok(None);
        };
        let FileIdentity::GuestDirectory(directory) = &file.lifetime.identity else {
            return Ok(None);
        };
        if name.first() == Some(&u16::from(b'\\')) || parts(c, name).is_err() {
            return Ok(None);
        }
        let mut path: Vec<_> = directory.encode_utf16().collect();
        if !name.is_empty() && !directory.ends_with('\\') {
            path.push(u16::from(b'\\'));
        }
        path.extend_from_slice(name);
        absolute = path;
        &absolute
    };
    let trimmed = dos.strip_suffix(&[u16::from(b'\\')]).unwrap_or(dos);
    if let Some(guest) = names.into_iter().find(|path| {
        let name = if path.ends_with(":\\") { dos } else { trimmed };
        equal(c, name, &path.encode_utf16().collect::<Vec<_>>())
    }) {
        return Ok(Some(GuestDirectory {
            guest,
            framework: None,
            framework_installation: false,
        }));
    }
    framework_directory(c, trimmed)
}

/// Admit one counted child name in the selected installed system directory.
#[cfg(windows)]
pub(super) fn installed_entry<'a>(
    c: &'a Ctx,
    root: u64,
    name: &[u16],
) -> Checked<Option<(&'a Path, PathBuf)>> {
    let Some(runtime) = &c.p.native else {
        return Ok(None);
    };
    let (parent, leaf) = name
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\'))
        .map_or((&[][..], name), |at| (&name[..at], &name[at + 1..]));
    let separator = u16::from(b'\\');
    if leaf.is_empty()
        || parent.last() == Some(&separator)
        || root != 0 && name.first() == Some(&separator)
    {
        return Ok(None);
    }
    let Some(directory) = guest_directory(c, root, parent)? else {
        return Ok(None);
    };
    if directory.framework.is_some()
        || directory.guest.ends_with(":\\")
        || directory.guest == runtime.guest_root.trim_end_matches('\\')
    {
        return Ok(None);
    }
    let (components, _) = parts(c, leaf)?;
    let [component] = components.as_slice() else {
        return Ok(None);
    };
    Ok(Some((
        &runtime.directory,
        PathBuf::from(host_component(c, component)?),
    )))
}

#[cfg(windows)]
pub(super) fn installed_directory<'a>(c: &'a Ctx, guest: &str) -> Checked<&'a Path> {
    let runtime = c.p.native.as_ref().expect("admitted installed directory");
    let host = if guest.ends_with(":\\") {
        runtime
            .directory
            .ancestors()
            .find(|path| path.has_root() && path.parent().is_none())
    } else if guest == runtime.guest_root.trim_end_matches('\\') {
        runtime.directory.parent()
    } else {
        Some(runtime.directory.as_path())
    };
    host.ok_or_else(|| {
        c.unsupported("installed DOS directory has no host counterpart")
            .into()
    })
}

fn resolve_kind(
    c: &Ctx,
    attrs: &Attributes,
    name: Option<&[u16]>,
    retained_directory: bool,
) -> Checked<Resolved> {
    let root = if attrs.root == 0 {
        None
    } else {
        let Some(root) = c.p.objects.get(attrs.root) else {
            return status(
                if attrs.root == c.arch().ptr(u64::MAX) || attrs.root == c.arch().ptr(u64::MAX - 1)
                {
                    STATUS_OBJECT_TYPE_MISMATCH
                } else {
                    STATUS_INVALID_HANDLE
                },
            );
        };
        Some(root)
    };
    let Some(name) = name else {
        return status(if root.is_some() {
            STATUS_OBJECT_NAME_INVALID
        } else {
            STATUS_OBJECT_PATH_SYNTAX_BAD
        });
    };
    if let Some(root) = root {
        let file = match root {
            Object::File(file) => file,
            _ => {
                return status(if name.first() == Some(&u16::from(b'\\')) {
                    STATUS_OBJECT_PATH_SYNTAX_BAD
                } else {
                    STATUS_OBJECT_TYPE_MISMATCH
                });
            }
        };
        if name.first() == Some(&u16::from(b'\\')) {
            return status(STATUS_INVALID_PARAMETER);
        }
        if !name.is_empty() && !file.directory {
            return status(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if let FileIdentity::GuestDirectory(guest) = &file.lifetime.identity {
            let (components, directory) = parts(c, name)?;
            if components.is_empty() || directory {
                return status(STATUS_ACCESS_DENIED);
            }
            let mut absolute: Vec<u16> = guest.encode_utf16().collect();
            if absolute.last() != Some(&u16::from(b'\\')) {
                absolute.push(u16::from(b'\\'));
            }
            absolute.extend_from_slice(name);
            let Some((base, host, no_reparse)) = selected(c, &absolute)? else {
                return status(STATUS_ACCESS_DENIED);
            };
            return Ok(Resolved {
                host,
                base,
                root: None,
                relative: None,
                directory: false,
                runtime_library: true,
                no_reparse,
            });
        }
        if !c.p.cfg.host_filesystem && !c.p.objects.runtime_library(attrs.root) {
            return status(STATUS_ACCESS_DENIED);
        }
        if file.null {
            return Err(c.unsupported("NT NUL device metadata").into());
        }
        let (parts, directory) = parts(c, name)?;
        if retained_directory && file.host.is_some() {
            let mut relative = PathBuf::new();
            for part in &parts {
                relative.push(host_component(c, part)?);
            }
            return Ok(Resolved {
                host: file.host_path.join(&relative),
                base: file.host_path.clone(),
                root: Some(attrs.root),
                relative: Some(relative),
                directory,
                runtime_library: c.p.objects.runtime_library(attrs.root),
                no_reparse: false,
            });
        }
        let base = if name.is_empty() && file.host.is_some() {
            // An empty relative name queries the retained file object even
            // after its old pathname was renamed, replaced or removed.
            file.host_path.clone()
        } else {
            canonical_root(c, &file.host_path)?
        };
        return Ok(Resolved {
            host: append(c, base.clone(), &parts)?,
            base,
            root: name.is_empty().then_some(attrs.root),
            relative: None,
            directory,
            runtime_library: c.p.objects.runtime_library(attrs.root),
            no_reparse: false,
        });
    }
    if name.is_empty() || name[0] != u16::from(b'\\') {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    let Some(path) = dos_tail(c, name) else {
        return Err(c
            .unsupported("NT metadata name outside mapped DOS drive namespace")
            .into());
    };
    if path.len() < 3
        || !matches!(path[0],65..=90 | 97..=122)
        || path[1] != u16::from(b':')
        || path[2] != u16::from(b'\\')
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    let (components, directory) = parts(c, &path[3..])?;
    let selected_path = if directory {
        &path[..path.len() - 1]
    } else {
        path
    };
    if let Some((base, host, no_reparse)) = selected(c, selected_path)? {
        return Ok(Resolved {
            base,
            host,
            root: None,
            relative: None,
            directory,
            runtime_library: true,
            no_reparse,
        });
    }
    if !c.p.cfg.host_filesystem {
        return status(STATUS_ACCESS_DENIED);
    }
    let Some(root) = c.p.cfg.drives.root(char::from(path[0] as u8)) else {
        return status(STATUS_OBJECT_PATH_NOT_FOUND);
    };
    let base = canonical_root(c, root)?;
    Ok(Resolved {
        host: append(c, base.clone(), &components)?,
        base,
        root: None,
        relative: None,
        directory,
        runtime_library: false,
        no_reparse: false,
    })
}
