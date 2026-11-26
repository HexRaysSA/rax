//! Native Linux runtime selection for a closed process. Installed libraries
//! and runtime data are read-only; there is no general host path
//! fallback, host descriptor exposure, or separate sysroot requirement.
#[cfg(target_os = "linux")]
use crate::user::supplied_fs::WorkspaceFlavor;
use crate::user::supplied_fs::{Device, Files};
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[cfg(any(target_os = "linux", test))]
mod ld_cache;

#[cfg(any(target_os = "linux", test))]
const PERL_MODULE_ROOTS: &[&str] = &["/usr/share/perl", "/usr/share/perl5"];
#[cfg(any(target_os = "linux", test))]
const TERMINFO_ROOTS: &[&str] = &["/etc/terminfo", "/usr/share/terminfo"];
#[cfg(any(target_os = "linux", test))]
const MESSAGE_CATALOG_ROOTS: &[&str] = &[
    "/usr/share/locale",
    "/usr/share/locale-langpack",
    "/usr/local/share/locale",
];
#[cfg(any(target_os = "linux", test))]
const LOCALE_ALIAS: &str = "/usr/share/locale/locale.alias";
#[cfg(target_os = "linux")]
const LOCALE_ALIAS_TARGET: &str = "/etc/locale.alias";
#[cfg(any(target_os = "linux", test))]
const PROGRAM_ROOTS: [&str; 4] = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];
#[cfg(target_os = "linux")]
const STDBUF_LIBRARY: &str = "/usr/libexec/coreutils/libstdbuf.so";
#[cfg(any(target_os = "linux", test))]
const CONFINED_ROOTS: &[&str] = &[
    PERL_MODULE_ROOTS[0],
    PERL_MODULE_ROOTS[1],
    TERMINFO_ROOTS[0],
    TERMINFO_ROOTS[1],
    MESSAGE_CATALOG_ROOTS[0],
    MESSAGE_CATALOG_ROOTS[1],
    MESSAGE_CATALOG_ROOTS[2],
    PROGRAM_ROOTS[0],
    PROGRAM_ROOTS[1],
    PROGRAM_ROOTS[2],
    PROGRAM_ROOTS[3],
];

/// Select installed Linux runtime roots, the dynamic-linker cache, and the
/// installed ELF libraries that cache names outside the roots, plus installed
/// executable programs, the packaged stdbuf helper, Perl modules, compiled
/// terminfo, GNU message catalogs, timezone, protocol and service data. Include
/// guest loopback names and a synthetic `/dev/null` in the guest namespace. Explicit
/// supplied files override installed files. Later `dlopen` calls use the same
/// namespace. Unregistered runtime roots require explicit selection.
pub fn native(files: &Files) -> io::Result<Files> {
    select_native(files, None)
}

/// Select the native runtime without mounting a program directory over
/// the explicit main image's absolute guest path.
pub fn native_for_executable(files: &Files, executable: &str) -> io::Result<Files> {
    select_native(files, Some(executable))
}

fn select_native(files: &Files, executable: Option<&str>) -> io::Result<Files> {
    #[cfg(target_os = "linux")]
    {
        select_installed_for_executable(files, Path::new("/"), executable)
            .map(|files| files.with_temp_workspace(WorkspaceFlavor::Linux))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (files, executable);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Linux runtime selection requires a Linux host",
        ))
    }
}

#[cfg(all(target_os = "linux", test))]
fn select_installed(files: &Files, root: &Path) -> io::Result<Files> {
    select_installed_for_executable(files, root, None)
}

#[cfg(target_os = "linux")]
fn select_installed_for_executable(
    files: &Files,
    root: &Path,
    executable: Option<&str>,
) -> io::Result<Files> {
    use crate::user::supplied_fs::Error;

    let mut roots = installed_roots(root);
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no installed Linux library directories",
        ));
    }
    let zoneinfo = root.join("usr/share/zoneinfo");
    if zoneinfo.is_dir() {
        roots.insert("/usr/share/zoneinfo".into(), zoneinfo);
    }
    let unshadowed = |mount: &str| {
        !executable.is_some_and(|image| {
            image == mount
                || mount
                    .strip_prefix(image)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    };
    for &path in PERL_MODULE_ROOTS
        .iter()
        .chain(TERMINFO_ROOTS)
        .chain(MESSAGE_CATALOG_ROOTS)
    {
        let host = root.join(path.trim_start_matches('/'));
        if unshadowed(path) && host.symlink_metadata().is_ok_and(|info| info.is_dir()) {
            roots.insert(path.into(), host);
        }
    }
    for &[legacy, standard] in PROGRAM_ROOTS.as_chunks::<2>().0 {
        let host_legacy = root.join(legacy.trim_start_matches('/'));
        let host_standard = root.join(standard.trim_start_matches('/'));
        let standard_selected = unshadowed(standard)
            && host_standard
                .symlink_metadata()
                .is_ok_and(|info| info.is_dir());
        // Merged /usr installations alias the root-level directory.
        if unshadowed(legacy)
            && host_legacy.symlink_metadata().is_ok_and(|info| {
                info.is_dir()
                    || (info.is_symlink()
                        && standard_selected
                        && host_legacy
                            .canonicalize()
                            .ok()
                            .zip(host_standard.canonicalize().ok())
                            .is_some_and(|(legacy, standard)| legacy == standard))
            })
        {
            roots.insert(legacy.into(), host_legacy);
        }
        if standard_selected {
            roots.insert(standard.into(), host_standard);
        }
    }
    let cache = root.join("etc/ld.so.cache");
    let files = select(files, roots, cache.is_file().then_some(cache))?;
    let files = if unshadowed(STDBUF_LIBRARY)
        && matches!(
            files.lookup_with_follow(STDBUF_LIBRARY, false),
            Err(Error::NotFound)
        ) {
        with_stdbuf_library(files, root)?
    } else {
        files
    };
    // libc reads these tables for local name and locale lookups.
    let databases = ["/etc/protocols", "/etc/services", LOCALE_ALIAS_TARGET]
        .into_iter()
        .filter(|path| unshadowed(path) && matches!(files.lookup(path), Err(Error::NotFound)))
        .map(|path| (path.to_owned(), root.join(path.trim_start_matches('/'))))
        .filter(|(_, host)| host.symlink_metadata().is_ok_and(|info| info.is_file()))
        .collect();
    let files = files.with_host_files(databases)?;
    // Some distributions install this exact alias to the selected /etc file.
    // Record the link in the guest without traversing it on the host.
    let alias = root.join(LOCALE_ALIAS.trim_start_matches('/'));
    let files = if unshadowed(LOCALE_ALIAS)
        && alias
            .read_link()
            .is_ok_and(|target| target == Path::new(LOCALE_ALIAS_TARGET))
    {
        files
            .with_native_symlink(LOCALE_ALIAS, LOCALE_ALIAS_TARGET)
            .map_err(io::Error::other)?
    } else {
        files
    };
    // Only guest loopback names are available without an explicit hosts file.
    let hosts = "/etc/hosts";
    let files = if matches!(files.lookup_with_follow(hosts, false), Err(Error::NotFound)) {
        files
            .with_file(
                hosts.into(),
                b"127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n"[..].into(),
            )
            .map_err(io::Error::other)?
    } else {
        files
    };
    crate::user::supplied_fs::timezone::select_default(files, root)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn installed_roots(root: &Path) -> BTreeMap<String, PathBuf> {
    // A biarch glibc installation can put the i386 interpreter in lib32
    // while ELF PT_INTERP still names /lib/ld-linux.so.2.
    [
        "/lib",
        "/lib32",
        "/lib64",
        "/usr/lib",
        "/usr/lib32",
        "/usr/lib64",
        "/usr/local/lib",
    ]
    .into_iter()
    .filter_map(|name| {
        let host = root.join(name.trim_start_matches('/'));
        host.is_dir().then(|| (name.to_owned(), host))
    })
    .collect()
}

#[cfg(any(target_os = "linux", test))]
fn select(
    files: &Files,
    roots: BTreeMap<String, PathBuf>,
    cache: Option<PathBuf>,
) -> io::Result<Files> {
    #[cfg(target_os = "linux")]
    let library_roots = roots
        .keys()
        .filter(|name| !CONFINED_ROOTS.contains(&name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let files = files
        .with_device(Device::Null)
        .and_then(|files| files.with_device(Device::Zero))
        .and_then(|files| files.with_device(Device::Urandom))
        .map_err(io::Error::other)?;
    let files =
        files.with_linux_library_roots(roots, Some(accept_installed_file), CONFINED_ROOTS)?;
    let Some(cache) = cache.filter(|_| files.lookup("/etc/ld.so.cache").is_err()) else {
        return Ok(files);
    };
    let files = files.with_host_file("/etc/ld.so.cache".into(), &cache)?;
    #[cfg(target_os = "linux")]
    let files = with_cached_libraries(files, &library_roots)?;
    Ok(files)
}

#[cfg(any(target_os = "linux", test))]
fn under_root(path: &str, roots: &[&str]) -> bool {
    roots.iter().any(|&root| {
        path.strip_prefix(root)
            .is_some_and(|relative| relative.starts_with('/'))
    })
}

#[cfg(any(target_os = "linux", test))]
fn accept_installed_file(path: &str, host: &Path, _file: &std::fs::File) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    if under_root(path, &PROGRAM_ROOTS) {
        return accept_installed_program(_file);
    }
    for &root in TERMINFO_ROOTS {
        if let Some(entry) = path
            .strip_prefix(root)
            .and_then(|tail| tail.strip_prefix('/'))
        {
            return crate::user::supplied_fs::terminfo::accepts(entry, _file);
        }
    }
    if path == LOCALE_ALIAS {
        return Ok(true);
    }
    for &root in MESSAGE_CATALOG_ROOTS {
        if let Some(entry) = path
            .strip_prefix(root)
            .and_then(|tail| tail.strip_prefix('/'))
        {
            return accept_message_catalog(entry, _file);
        }
    }
    Ok(!under_root(path, PERL_MODULE_ROOTS)
        || (is_perl_runtime_file(Path::new(path)) && is_perl_runtime_file(host)))
}

#[cfg(any(target_os = "linux", test))]
fn accept_message_catalog(path: &str, mut file: &std::fs::File) -> io::Result<bool> {
    use std::io::Read;

    let mut parts = path.splitn(3, '/');
    let (Some(locale), Some(category), Some(catalog)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(false);
    };
    if locale.is_empty()
        || !category
            .strip_prefix("LC_")
            .is_some_and(|name| !name.is_empty())
        || !catalog
            .strip_suffix(".mo")
            .is_some_and(|domain| !domain.is_empty() && !domain.contains('/'))
    {
        return Ok(false);
    }

    // The guest's gettext implementation parses the catalog. Select only
    // complete GNU MO headers in either of the two supported byte orders.
    const GNU_MO_MAGIC: u32 = 0x9504_12de;
    let mut header = [0; 28];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(header.starts_with(&GNU_MO_MAGIC.to_le_bytes())
            || header.starts_with(&GNU_MO_MAGIC.to_be_bytes())),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn accept_installed_program(file: &std::fs::File) -> io::Result<bool> {
    use crate::user::image::elf::{ET_DYN, ET_EXEC, identify};
    use crate::user::linux::exec::{BINPRM_BUF_SIZE, parse_script};
    use std::os::unix::fs::{FileExt, PermissionsExt};

    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Ok(false);
    }
    let mut header = [0; BINPRM_BUF_SIZE];
    let length = metadata.len().min(BINPRM_BUF_SIZE as u64) as usize;
    let header = &mut header[..length];
    match file.read_exact_at(header, 0) {
        Ok(()) => {
            let executable = identify(header).is_ok_and(|elf| {
                elf.elf_class().is_some()
                    && elf.elf_data().is_some()
                    && matches!(elf.e_type, ET_EXEC | ET_DYN)
            });
            Ok(executable || parse_script(header).is_ok())
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_perl_runtime_file(path: &Path) -> bool {
    path.ends_with("unicore/version")
        || matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("pm" | "pl" | "al" | "ph")
        )
}

#[cfg(target_os = "linux")]
fn with_cached_libraries(files: Files, roots: &[String]) -> io::Result<Files> {
    use crate::user::supplied_fs::Error;
    use std::{collections::BTreeSet, path::Path};

    // Parse only a cache selected from the host. The guest uses its original
    // bytes and remains responsible for directory, ABI and hwcap precedence.
    let Ok(cache) = files.read("/etc/ld.so.cache") else {
        return Ok(files);
    };
    let mut selected = BTreeMap::new();
    for name in ld_cache::paths(&cache).collect::<BTreeSet<_>>() {
        let path = Path::new(name);
        if roots.iter().any(|root| path.starts_with(root))
            || !matches!(files.lookup(name), Err(Error::NotFound))
        {
            continue;
        }
        // Stale entries and files unusable as shared objects remain absent.
        if let Ok(source) = open_installed_shared_object(path, 0) {
            selected.insert(name.to_owned(), source.into());
        }
    }
    files
        .with_selected_backings(selected)
        .map_err(io::Error::other)
}

#[cfg(target_os = "linux")]
fn with_stdbuf_library(files: Files, root: &Path) -> io::Result<Files> {
    // Coreutils can install this helper outside the normal library roots and
    // addresses it directly. Admit only the regular ELF backing at that path.
    let source = root.canonicalize().ok().and_then(|root| {
        let path = root.join(STDBUF_LIBRARY.trim_start_matches('/'));
        let parent = path.parent()?;
        if parent.canonicalize().ok().as_deref() != Some(parent) {
            return None;
        }
        open_installed_shared_object(&path, libc::O_NOFOLLOW).ok()
    });
    let Some(source) = source else {
        return Ok(files);
    };
    files
        .with_selected_backings(BTreeMap::from([(STDBUF_LIBRARY.into(), source.into())]))
        .map_err(io::Error::other)
}

#[cfg(target_os = "linux")]
fn open_installed_shared_object(
    path: &Path,
    flags: libc::c_int,
) -> io::Result<crate::user::mm::HostFileSource> {
    use crate::user::mm::HostFileSource;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | flags)
        .open(path)?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "installed ELF shared object");
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut header = [0; 18];
    file.read_exact_at(&mut header, 0)?;
    let byte_order = header[5];
    let kind = [header[16], header[17]];
    if &header[..4] != b"\x7fELF"
        || !matches!(header[4], 1 | 2)
        || header[6] != 1
        || !matches!((byte_order, kind), (1, [3, 0]) | (2, [0, 3]))
    {
        return Err(invalid());
    }
    HostFileSource::new(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_message_catalogs_are_read_only_and_confined() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let installed = root.join("usr/share/locale/fr/LC_MESSAGES");
        let distro = root.join("usr/share/locale-langpack/fr/LC_MESSAGES");
        let local = root.join("usr/local/share/locale/fr/LC_TIME");
        let lib = root.join("usr/lib");
        for directory in [&installed, &distro, &local, &lib] {
            fs::create_dir_all(directory).unwrap();
        }
        let mut little = [0; 28];
        little[..4].copy_from_slice(&0x9504_12de_u32.to_le_bytes());
        let mut big = little;
        big[..4].copy_from_slice(&0x9504_12de_u32.to_be_bytes());
        fs::write(installed.join("app.mo"), little).unwrap();
        fs::write(distro.join("distro.mo"), big).unwrap();
        fs::write(local.join("local.mo"), little).unwrap();
        fs::write(installed.join("short.mo"), &little[..4]).unwrap();
        fs::write(installed.join("text.mo"), [b'a'; 28]).unwrap();
        fs::write(installed.join("source.po"), little).unwrap();
        fs::write(installed.parent().unwrap().join("misplaced.mo"), little).unwrap();
        fs::write(lib.join("outside.mo"), little).unwrap();
        symlink("app.mo", installed.join("alias.mo")).unwrap();
        symlink("../../../../lib/outside.mo", installed.join("escape.mo")).unwrap();
        let aliases = root.join("etc/locale.alias");
        let alias_link = root.join("usr/share/locale/locale.alias");
        fs::create_dir_all(aliases.parent().unwrap()).unwrap();
        fs::write(&aliases, b"french fr_FR.ISO-8859-1\n").unwrap();
        symlink(LOCALE_ALIAS_TARGET, &alias_link).unwrap();

        let files = select_installed(&Files::default(), root).unwrap();
        let app = "/usr/share/locale/fr/LC_MESSAGES/app.mo";
        for (path, bytes) in [
            (app, little),
            ("/usr/share/locale/fr/LC_MESSAGES/alias.mo", little),
            ("/usr/share/locale-langpack/fr/LC_MESSAGES/distro.mo", big),
            ("/usr/local/share/locale/fr/LC_TIME/local.mo", little),
        ] {
            assert_eq!(&*files.read(path).unwrap(), &bytes);
            assert!(matches!(
                files.unlink_workspace_file(path, (0, 0), &[]),
                Err(Error::ReadOnly)
            ));
        }
        for path in [
            "/usr/share/locale/fr/LC_MESSAGES/short.mo",
            "/usr/share/locale/fr/LC_MESSAGES/text.mo",
            "/usr/share/locale/fr/LC_MESSAGES/source.po",
            "/usr/share/locale/fr/LC_MESSAGES/escape.mo",
            "/usr/share/locale/fr/misplaced.mo",
        ] {
            assert!(matches!(files.read(path), Err(Error::NotFound)), "{path}");
        }
        assert_eq!(
            &*files.read(LOCALE_ALIAS).unwrap(),
            b"french fr_FR.ISO-8859-1\n"
        );

        fs::remove_file(&alias_link).unwrap();
        symlink("/usr/lib/outside.mo", &alias_link).unwrap();
        let files = select_installed(&Files::default(), root).unwrap();
        assert!(matches!(files.read(LOCALE_ALIAS), Err(Error::NotFound)));

        fs::remove_file(&alias_link).unwrap();
        fs::write(&alias_link, b"french fr_FR.ISO-8859-1\n").unwrap();
        let files = select_installed(&Files::default(), root).unwrap();
        assert_eq!(
            &*files.read(LOCALE_ALIAS).unwrap(),
            b"french fr_FR.ISO-8859-1\n"
        );

        let supplied = Files::default()
            .with_file(app.into(), Arc::from(&b"caller catalog"[..]))
            .unwrap();
        assert_eq!(
            &*select_installed(&supplied, root)
                .unwrap()
                .read(app)
                .unwrap(),
            b"caller catalog"
        );
        let executable = "/usr/share/locale";
        let selected =
            select_installed_for_executable(&Files::default(), root, Some(executable)).unwrap();
        assert!(
            selected
                .with_file(executable.into(), Arc::from(&b"guest image"[..]))
                .is_ok()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_terminfo_is_read_only_and_confined() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let shared = root.join("usr/share/terminfo/x");
        let local = root.join("etc/terminfo/76");
        let libraries = root.join("usr/lib");
        for directory in [&shared, &local, &libraries] {
            fs::create_dir_all(directory).unwrap();
        }
        let mut legacy = [0; 12];
        legacy[..2].copy_from_slice(&0o432_u16.to_le_bytes());
        let mut extended = legacy;
        extended[..2].copy_from_slice(&0o1036_u16.to_le_bytes());
        fs::write(shared.join("xterm"), extended).unwrap();
        fs::write(local.join("vt100"), legacy).unwrap();
        fs::write(shared.join("xtext"), b"not terminfo").unwrap();
        fs::write(shared.join("xshort"), &legacy[..2]).unwrap();
        fs::write(shared.join("misplaced"), legacy).unwrap();
        fs::write(libraries.join("outside"), legacy).unwrap();
        symlink("xterm", shared.join("xalias")).unwrap();
        symlink("../../../lib/outside", shared.join("xescape")).unwrap();

        let files = Files::default()
            .with_file(
                "/usr/share/terminfo/x/xoverride".into(),
                Arc::from(&b"supplied"[..]),
            )
            .unwrap();
        fs::write(shared.join("xoverride"), extended).unwrap();
        let files = select_installed(&files, root).unwrap();
        for (path, bytes) in [
            ("/usr/share/terminfo/x/xterm", extended),
            ("/usr/share/terminfo/x/xalias", extended),
            ("/etc/terminfo/76/vt100", legacy),
        ] {
            assert_eq!(&*files.read(path).unwrap(), &bytes);
            assert!(matches!(
                files.unlink_workspace_file(path, (0, 0), &[]),
                Err(Error::ReadOnly)
            ));
        }
        for name in ["xtext", "xshort", "misplaced", "xescape"] {
            assert!(matches!(
                files.read(&format!("/usr/share/terminfo/x/{name}")),
                Err(Error::NotFound)
            ));
        }
        assert_eq!(
            &*files.read("/usr/share/terminfo/x/xoverride").unwrap(),
            b"supplied"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_stdbuf_selects_only_the_packaged_read_only_shared_object() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let libexec = root.join("usr/libexec");
        let package = libexec.join("coreutils");
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        fs::create_dir_all(&package).unwrap();
        let path = package.join("libstdbuf.so");
        let sibling = package.join("unselected.so");
        let files = Files::default();
        let missing = |files: &Files| {
            assert!(matches!(files.read(STDBUF_LIBRARY), Err(Error::NotFound)));
        };
        missing(&select_installed(&files, root).unwrap());
        fs::write(&path, b"not ELF").unwrap();
        missing(&select_installed(&files, root).unwrap());

        let mut elf = [0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 3;
        fs::write(&path, elf).unwrap();
        fs::write(&sibling, elf).unwrap();
        let selected = select_installed(&files, root).unwrap();
        assert_eq!(&*selected.read(STDBUF_LIBRARY).unwrap(), &elf);
        assert!(matches!(
            selected.read("/usr/libexec/coreutils/unselected.so"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            selected.unlink_workspace_file(STDBUF_LIBRARY, (0, 0), &[]),
            Err(Error::ReadOnly)
        ));

        let supplied = files
            .with_file(STDBUF_LIBRARY.into(), Arc::from(&b"supplied"[..]))
            .unwrap();
        assert_eq!(
            &*select_installed(&supplied, root)
                .unwrap()
                .read(STDBUF_LIBRARY)
                .unwrap(),
            b"supplied"
        );
        for main in ["/usr/libexec", "/usr/libexec/coreutils", STDBUF_LIBRARY] {
            let selected = select_installed_for_executable(&files, root, Some(main)).unwrap();
            missing(&selected);
            assert!(
                selected
                    .with_file(main.into(), Arc::from(&b"main"[..]))
                    .is_ok()
            );
        }

        fs::remove_file(&path).unwrap();
        symlink(&sibling, &path).unwrap();
        missing(&select_installed(&files, root).unwrap());
        fs::remove_file(&path).unwrap();
        fs::write(path, elf).unwrap();
        let elsewhere = root.join("other");
        fs::rename(&package, &elsewhere).unwrap();
        symlink(elsewhere, package).unwrap();
        missing(&select_installed(&files, root).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_programs_select_elf_and_shebang_files_within_the_distribution_bins() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{
            fs::{self, Permissions},
            os::unix::fs::{PermissionsExt, symlink},
            sync::Arc,
        };

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let bin = root.join("usr/bin");
        let local_bin = root.join("usr/local/bin");
        let sbin = root.join("sbin");
        let usr_sbin = root.join("usr/sbin");
        for path in [&lib, &bin, &local_bin, &sbin, &usr_sbin] {
            fs::create_dir_all(path).unwrap();
        }
        symlink("usr/bin", root.join("bin")).unwrap();
        symlink("program", bin.join("alias")).unwrap();
        symlink("../lib/external", bin.join("external")).unwrap();
        let mut elf = [0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 3;
        for path in [
            bin.join("program"),
            lib.join("external"),
            local_bin.join("unselected"),
            sbin.join("legacy-tool"),
            usr_sbin.join("system-tool"),
        ] {
            fs::write(&path, elf).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(bin.join("non-executable"), elf).unwrap();
        fs::set_permissions(bin.join("non-executable"), Permissions::from_mode(0o644)).unwrap();
        fs::write(bin.join("text"), b"unselected").unwrap();
        fs::set_permissions(bin.join("text"), Permissions::from_mode(0o755)).unwrap();
        let script = b"#!/bin/sh\n:\n";
        fs::write(bin.join("script"), script).unwrap();
        fs::set_permissions(bin.join("script"), Permissions::from_mode(0o755)).unwrap();
        fs::write(bin.join("invalid-script"), b"#! \n").unwrap();
        fs::set_permissions(bin.join("invalid-script"), Permissions::from_mode(0o755)).unwrap();

        symlink("../lib/external", usr_sbin.join("escape")).unwrap();
        let selected = select_installed(&Files::default(), root).unwrap();
        for path in [
            "/bin/program",
            "/usr/bin/program",
            "/bin/alias",
            "/sbin/legacy-tool",
            "/usr/sbin/system-tool",
        ] {
            assert_eq!(&*selected.read(path).unwrap(), &elf);
        }
        assert_eq!(&*selected.read("/bin/script").unwrap(), script);
        for path in [
            "/bin/non-executable",
            "/bin/text",
            "/bin/invalid-script",
            "/bin/external",
            "/usr/local/bin/unselected",
            "/usr/sbin/escape",
            "/sbin/system-tool",
        ] {
            assert!(
                matches!(selected.read(path), Err(Error::NotFound)),
                "{path}"
            );
        }
        assert_eq!(&*selected.read("/usr/lib/external").unwrap(), &elf);
        let selected = selected
            .with_file("/bin/program".into(), Arc::from(&b"guest main"[..]))
            .unwrap();
        assert_eq!(&*selected.read("/bin/program").unwrap(), b"guest main");
        assert_eq!(&*selected.read("/usr/bin/program").unwrap(), &elf);

        for path in PROGRAM_ROOTS {
            let selected =
                select_installed_for_executable(&Files::default(), root, Some(path)).unwrap();
            let selected = selected
                .with_file(path.into(), Arc::from(&b"guest main"[..]))
                .unwrap();
            assert_eq!(&*selected.read(path).unwrap(), b"guest main");
        }

        fs::rename(&sbin, root.join("legacy-sbin")).unwrap();
        symlink("usr/sbin", &sbin).unwrap();
        let selected = select_installed(&Files::default(), root).unwrap();
        assert_eq!(&*selected.read("/sbin/system-tool").unwrap(), &elf);
        assert!(matches!(
            selected.read("/sbin/escape"),
            Err(Error::NotFound)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_perl_modules_follow_version_aliases_within_read_only_roots() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unselected", 10);
        let root = &fixture.dir;
        let lib = root.join("usr/lib");
        let perl = root.join("usr/share/perl");
        let version = perl.join("5.38.2");
        let vendor = root.join("usr/share/perl5");
        for path in [&lib, &version.join("unicore"), &vendor] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(version.join("Core.pm"), b"package Core; 1;").unwrap();
        fs::write(version.join("unicore/Data.pl"), b"1;").unwrap();
        fs::write(version.join("unicore/version"), b"15.0.0\n").unwrap();
        fs::write(version.join("README"), b"unselected").unwrap();
        fs::write(vendor.join("Vendor.pm"), b"package Vendor; 1;").unwrap();
        fs::write(lib.join("Outside.pm"), b"outside").unwrap();
        symlink("5.38.2", perl.join("5.38")).unwrap();
        symlink(&fixture.path, version.join("Outside.pm")).unwrap();
        symlink("../../../lib/Outside.pm", version.join("OtherRoot.pm")).unwrap();
        symlink("README", version.join("Disguised.pm")).unwrap();

        let files = Files::default();
        let selected = select_installed(&files, root).unwrap();
        let core = "/usr/share/perl/5.38/Core.pm";
        assert_eq!(&*selected.read(core).unwrap(), b"package Core; 1;");
        assert_eq!(
            selected
                .lookup_with_follow("/usr/share/perl/5.38", false)
                .unwrap()
                .1
                .link_target(),
            Some(&b"5.38.2"[..])
        );
        assert_eq!(
            &*selected.read("/usr/share/perl5/Vendor.pm").unwrap(),
            b"package Vendor; 1;"
        );
        assert_eq!(
            &*selected
                .read("/usr/share/perl/5.38/unicore/version")
                .unwrap(),
            b"15.0.0\n"
        );
        assert_eq!(
            &*selected
                .read("/usr/share/perl/5.38/unicore/Data.pl")
                .unwrap(),
            b"1;"
        );
        assert_eq!(&*selected.read("/usr/lib/Outside.pm").unwrap(), b"outside");
        for path in [
            "/usr/share/perl/5.38/README",
            "/usr/share/perl/5.38/Disguised.pm",
            "/usr/share/perl/5.38/Outside.pm",
            "/usr/share/perl/5.38/OtherRoot.pm",
        ] {
            assert!(
                matches!(selected.read(path), Err(Error::NotFound)),
                "{path}"
            );
        }
        assert!(matches!(
            selected.unlink_workspace_file(core, (0, 0), &[]),
            Err(Error::ReadOnly)
        ));

        let supplied = files
            .with_file(core.into(), Arc::from(&b"supplied"[..]))
            .unwrap();
        assert_eq!(
            &*select_installed(&supplied, root)
                .unwrap()
                .read(core)
                .unwrap(),
            b"supplied"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_network_databases_are_selected_as_fixed_regular_files() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unselected", 10);
        let root = &fixture.dir;
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        let etc = root.join("etc");
        fs::create_dir(&etc).unwrap();
        fs::write(etc.join("protocols"), b"tcp 6 TCP\n").unwrap();
        fs::write(etc.join("services"), b"https 443/tcp\n").unwrap();
        fs::write(etc.join("nsswitch.conf"), b"services: other\n").unwrap();

        let files = Files::default();
        let selected = select_installed(&files, root).unwrap();
        assert_eq!(&*selected.read("/etc/protocols").unwrap(), b"tcp 6 TCP\n");
        assert_eq!(
            &*selected.read("/etc/services").unwrap(),
            b"https 443/tcp\n"
        );
        assert!(matches!(
            selected.read("/etc/nsswitch.conf"),
            Err(Error::NotFound)
        ));

        let supplied = files
            .with_file("/etc/services".into(), Arc::from(&b"local 1234/tcp\n"[..]))
            .unwrap();
        fs::remove_file(etc.join("protocols")).unwrap();
        symlink(&fixture.path, etc.join("protocols")).unwrap();
        let selected = select_installed(&supplied, root).unwrap();
        assert_eq!(
            &*selected.read("/etc/services").unwrap(),
            b"local 1234/tcp\n"
        );
        assert!(matches!(
            selected.read("/etc/protocols"),
            Err(Error::NotFound)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_runtime_supplies_guest_loopback_names() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, sync::Arc};

        let fixture = TestFile::new(b"unselected", 10);
        let root = &fixture.dir;
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        fs::create_dir(root.join("etc")).unwrap();
        fs::write(root.join("etc/hosts"), b"10.0.0.1 host-only\n").unwrap();
        fs::write(root.join("etc/resolv.conf"), b"search host-only\n").unwrap();

        let files = Files::default();
        let hosts = "/etc/hosts";
        let selected = select_installed(&files, root).unwrap();
        assert_eq!(
            &*selected.read(hosts).unwrap(),
            b"127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n"
        );
        assert!(matches!(
            selected.lookup("/etc/resolv.conf"),
            Err(Error::NotFound)
        ));

        let custom = &b"127.0.0.2 localhost\n"[..];
        let supplied = files.with_file(hosts.into(), Arc::from(custom)).unwrap();
        let selected = select_installed(&supplied, root).unwrap();
        assert_eq!(&*selected.read(hosts).unwrap(), custom);

        let blocked = files
            .with_file("/etc".into(), Arc::from(&b"file"[..]))
            .unwrap();
        let selected = select_installed(&blocked, root).unwrap();
        assert!(matches!(selected.lookup(hosts), Err(Error::NotDirectory)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_timezone_selection_preserves_overrides_and_root_boundaries() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{fs, os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"outside", 7);
        let root = &fixture.dir;
        let zones = root.join("usr/share/zoneinfo");
        let localtime = root.join("etc/localtime");
        fs::create_dir_all(zones.join("America")).unwrap();
        fs::create_dir(root.join("etc")).unwrap();
        let mut header = [0; 44];
        header[..5].copy_from_slice(b"TZif2");
        fs::write(zones.join("America/New_York"), header).unwrap();
        symlink("America/New_York", zones.join("EST5EDT")).unwrap();
        symlink(&fixture.path, zones.join("outside")).unwrap();
        symlink("../usr/share/zoneinfo/EST5EDT", &localtime).unwrap();

        let files = Files::default();
        assert_eq!(
            select_installed(&files, root).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        let selected = select_installed(&files, root).unwrap();
        for path in ["/usr/share/zoneinfo/EST5EDT", "/etc/localtime"] {
            assert_eq!(&*selected.read(path).unwrap(), &header, "{path}");
        }
        for path in ["/usr/share/zoneinfo/outside", "/backing"] {
            assert!(matches!(selected.read(path), Err(Error::NotFound)));
        }
        let override_path = "/usr/share/zoneinfo/America/New_York";
        let explicit = Files::new(BTreeMap::from([
            (override_path.into(), Arc::from(&b"supplied zone"[..])),
            ("/etc/localtime".into(), Arc::from(&b"supplied default"[..])),
        ]))
        .unwrap();
        let selected = select_installed(&explicit, root).unwrap();
        assert_eq!(&*selected.read(override_path).unwrap(), b"supplied zone");
        assert_eq!(
            &*selected.read("/etc/localtime").unwrap(),
            b"supplied default"
        );

        fs::remove_file(&localtime).unwrap();
        fs::write(localtime, b"not a TZif file").unwrap();
        let selected = select_installed(&files, root).unwrap();
        assert!(matches!(
            selected.read("/etc/localtime"),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn selected_runtime_roots_preserve_overrides_and_optional_cache() {
        let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"installed", 9);
        let explicit = Files::new(BTreeMap::from([
            (
                "/lib/backing".into(),
                std::sync::Arc::from(&b"override"[..]),
            ),
            (
                "/etc/ld.so.cache".into(),
                std::sync::Arc::from(&b"supplied-cache"[..]),
            ),
        ]))
        .unwrap();
        let selected = select(
            &explicit,
            BTreeMap::from([("/lib".into(), fixture.dir.clone())]),
            Some(fixture.path.clone()),
        )
        .unwrap();
        assert_eq!(&*selected.read("/lib/backing").unwrap(), b"override");
        assert_eq!(
            &*selected.read("/etc/ld.so.cache").unwrap(),
            b"supplied-cache"
        );
        let selected = select(
            &Files::default(),
            BTreeMap::from([("/lib".into(), fixture.dir.clone())]),
            Some(fixture.path.clone()),
        )
        .unwrap();
        assert_eq!(&*selected.read("/etc/ld.so.cache").unwrap(), b"installed");
        assert_eq!(
            selected.lookup("/dev/null").unwrap().1.device(),
            Some(Device::Null)
        );
        assert_eq!(
            selected.lookup("/dev/zero").unwrap().1.device(),
            Some(Device::Zero)
        );
        assert_eq!(
            selected.lookup("/dev/urandom").unwrap().1.device(),
            Some(Device::Urandom)
        );
        assert!(selected.lookup("/etc/passwd").is_err());
        let selected = select(
            &Files::default(),
            BTreeMap::from([("/lib".into(), fixture.dir.clone())]),
            None,
        )
        .unwrap();
        assert!(selected.lookup("/etc/ld.so.cache").is_err());
    }

    #[test]
    fn installed_roots_fill_gaps_behind_caller_mounts() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};

        let caller = TestFile::new(b"caller", 6);
        let installed = TestFile::new(b"installed", 9);
        std::fs::write(installed.dir.join("native-only"), b"native-only").unwrap();
        std::fs::write(caller.dir.join("shadow"), b"shadow").unwrap();
        let files = Files::new(BTreeMap::from([(
            "/lib/backing".into(),
            std::sync::Arc::from(&b"explicit"[..]),
        )]))
        .unwrap()
        .with_host_roots(BTreeMap::from([
            ("/lib".into(), caller.dir.clone()),
            ("/overlay".into(), caller.dir.clone()),
        ]))
        .unwrap();
        let selected = select(
            &files,
            BTreeMap::from([
                ("/lib".into(), installed.dir.clone()),
                ("/overlay/shadow/nested".into(), installed.dir.clone()),
            ]),
            None,
        )
        .unwrap();

        assert_eq!(&*selected.read("/lib/backing").unwrap(), b"explicit");
        assert_eq!(&*selected.read("/lib/shadow").unwrap(), b"shadow");
        assert_eq!(&*selected.read("/lib/native-only").unwrap(), b"native-only");
        assert!(matches!(
            files.read("/lib/native-only"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            selected.read("/overlay/shadow/nested/native-only"),
            Err(Error::NotDirectory)
        ));
        let caller_entry = selected.lookup("/lib/shadow").unwrap().1;
        let installed_entry = selected.lookup("/lib/native-only").unwrap().1;
        assert_ne!(caller_entry.ino, installed_entry.ino);
    }

    #[cfg(unix)]
    #[test]
    fn installed_directory_symlinks_resolve_parent_after_following() {
        use crate::user::supplied_fs::{Error, test_backing::TestFile};
        use std::{os::unix::fs::symlink, sync::Arc};

        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        let lib = root.join("usr/lib64");
        std::fs::create_dir_all(lib.join("sub/child")).unwrap();
        std::fs::create_dir(lib.join("alternate")).unwrap();
        std::fs::write(root.join("root-marker"), b"root").unwrap();
        std::fs::write(root.join("usr/root-marker"), b"usr").unwrap();
        std::fs::write(lib.join("sub/nested-marker"), b"nested").unwrap();
        symlink("usr/lib64", root.join("lib64")).unwrap();
        symlink("sub/child", lib.join("directory-link")).unwrap();
        symlink("directory-link", lib.join("second-link")).unwrap();
        symlink("../..", lib.join("outside")).unwrap();
        let files = Files::new(BTreeMap::from([
            ("/root-marker".into(), Arc::from(&b"root"[..])),
            ("/usr/root-marker".into(), Arc::from(&b"usr"[..])),
        ]))
        .unwrap();
        let roots = installed_roots(root);
        let selected = select(&files, roots.clone(), None).unwrap();
        for path in [
            "lib64/../root-marker",
            "lib64/../../root-marker",
            "usr/lib64/sub/child/../nested-marker",
            "usr/lib64/directory-link/../nested-marker",
            "lib64/second-link/../nested-marker",
        ] {
            let native = std::fs::read(root.join(path)).unwrap();
            let emulated = selected.read(&format!("/{path}")).unwrap();
            assert_eq!(&*emulated, native, "{path}");
        }
        assert!(matches!(
            selected.lookup("/usr/lib64/sub/nested-marker/.."),
            Err(Error::NotDirectory)
        ));
        assert!(matches!(
            selected.lookup("/usr/lib64/outside/../root-marker"),
            Err(Error::NotFound)
        ));
        let with_caller_mount = files
            .with_host_roots(BTreeMap::from([("/lib64".into(), lib.join("alternate"))]))
            .unwrap();
        let selected = select(&with_caller_mount, roots, None).unwrap();
        assert_eq!(&*selected.read("/lib64/../root-marker").unwrap(), b"root");
    }

    #[cfg(unix)]
    #[test]
    fn installed_roots_resolve_the_i386_interpreter_across_lib32_layouts() {
        use std::os::unix::fs::symlink;

        for (lib, lib32) in [("lib", "lib32"), ("usr/lib", "usr/lib32")] {
            let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"outside", 7);
            let root = &fixture.dir;
            let lib = root.join(lib);
            let lib32 = root.join(lib32);
            std::fs::create_dir_all(&lib).unwrap();
            std::fs::create_dir_all(&lib32).unwrap();
            if !root.join("lib").exists() {
                symlink("usr/lib", root.join("lib")).unwrap();
            }
            std::fs::write(lib32.join("ld-linux.so.2"), b"interpreter").unwrap();
            symlink("../lib32/ld-linux.so.2", lib.join("ld-linux.so.2")).unwrap();
            symlink(&fixture.path, lib32.join("outside")).unwrap();

            let selected = select(&Files::default(), installed_roots(root), None).unwrap();
            assert_eq!(
                &*selected.read("/lib/ld-linux.so.2").unwrap(),
                b"interpreter"
            );
            let runtime_path = format!("/{}", lib32.strip_prefix(root).unwrap().display());
            assert_eq!(
                &*selected
                    .read(&format!("{runtime_path}/ld-linux.so.2"))
                    .unwrap(),
                b"interpreter"
            );
            assert!(selected.lookup(&format!("{runtime_path}/outside")).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_linker_cache_admits_only_named_shared_objects_and_preserves_overrides() {
        let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"unused", 6);
        let library = fixture.dir.join("libcached.so.1");
        let neighbor = fixture.dir.join("libunlisted.so.1");
        let invalid = fixture.dir.join("libnonelf.so.1");
        let mut header = [0; 64];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16] = 3;
        std::fs::write(&library, header).unwrap();
        std::fs::write(&neighbor, header).unwrap();
        std::fs::write(&invalid, b"not an ELF object").unwrap();
        let library = library.to_str().unwrap();
        let cache = fixture.dir.join("ld.so.cache");
        std::fs::write(
            &cache,
            ld_cache::fixture(&[library, invalid.to_str().unwrap()]),
        )
        .unwrap();
        let roots = BTreeMap::from([("/lib".into(), fixture.dir.clone())]);
        let selected = select(&Files::default(), roots.clone(), Some(cache.clone())).unwrap();
        assert_eq!(&*selected.read(library).unwrap(), &header);
        assert!(selected.lookup(neighbor.to_str().unwrap()).is_err());
        assert!(selected.lookup(invalid.to_str().unwrap()).is_err());
        let explicit = Files::default()
            .with_file(library.into(), std::sync::Arc::from(&b"supplied"[..]))
            .unwrap();
        let selected = select(&explicit, roots, Some(cache)).unwrap();
        assert_eq!(&*selected.read(library).unwrap(), b"supplied");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn native_selection_reports_unavailable_on_other_hosts() {
        assert_eq!(
            native(&Files::default()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_runtime_executes_installed_dynamic_programs_without_a_sysroot() {
        use crate::user::linux::{
            ExitStatus, LinuxConfig, LinuxProcess, RunStatus, loader::ImageFile,
        };
        let files = native(&Files::default()).expect("installed Linux runtime");
        for (path, arguments, environment, expected) in [
            ("/bin/true", vec![], vec![], ""),
            (
                "/usr/bin/printf",
                vec![b"%s\\n".to_vec(), b"native-libc".to_vec()],
                vec![],
                "native-libc\n",
            ),
            (
                "/usr/bin/printf",
                vec![b"%s\\n".to_vec(), b"preloaded-libm".to_vec()],
                vec![b"LD_PRELOAD=libm.so.6".to_vec()],
                "preloaded-libm\n",
            ),
        ] {
            let mut argv = vec![b"/program".to_vec()];
            argv.extend(arguments);
            let mut config =
                LinuxConfig::embedded("/program", argv, environment, vec![], 65536).unwrap();
            config.supplied_files = Some(files.clone());
            config.arena_bytes = 256 << 20;
            let crate::user::console::Console::Captured(console) = &config.console else {
                panic!()
            };
            let console = console.clone();
            let mut process = LinuxProcess::spawn(
                config,
                ImageFile::new(std::fs::read(path).unwrap(), "/program"),
            )
            .unwrap();
            assert!(!process.state.config.host_services);
            assert!(process.state.config.sysroot.is_none());
            assert!(process.state.mm().program.interp_base > 0);
            assert!(process.state.exe_host_path.is_none());
            let preloaded = expected == "preloaded-libm\n";
            let deadline = crate::host::time::Instant::now() + std::time::Duration::from_secs(30);
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            loop {
                match process.run_slice(4096, &cancelled) {
                    RunStatus::BudgetExhausted => assert!(
                        crate::host::time::Instant::now() < deadline,
                        "{path}: native runtime exceeded 30 s"
                    ),
                    RunStatus::Complete(status) => {
                        let mut stderr = vec![0; 65536];
                        let n = console
                            .drain(crate::user::console::OutputStream::Stderr, &mut stderr)
                            .unwrap();
                        assert_eq!(
                            status,
                            ExitStatus::Exited(0),
                            "{path}: {}",
                            String::from_utf8_lossy(&stderr[..n])
                        );
                        assert_eq!(
                            n,
                            0,
                            "{path}: loader diagnostics: {}",
                            String::from_utf8_lossy(&stderr[..n])
                        );
                        let mut stdout = vec![0; 65536];
                        let n = console
                            .drain(crate::user::console::OutputStream::Stdout, &mut stdout)
                            .unwrap();
                        assert_eq!(&stdout[..n], expected.as_bytes(), "{path}");
                        if preloaded {
                            assert!(
                                process.space().vma_snapshot().iter().any(|vma| vma
                                    .name
                                    .as_deref()
                                    .is_some_and(|name| name.contains("libm.so.6"))),
                                "LD_PRELOAD did not map the installed libm"
                            );
                        }
                        break;
                    }
                    other => panic!("{path}: native runtime stopped: {other:?}"),
                }
            }
        }
    }
}
