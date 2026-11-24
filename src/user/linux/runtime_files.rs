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
const PROGRAM_ROOTS: &[&str] = &["/bin", "/usr/bin"];
#[cfg(any(target_os = "linux", test))]
const CONFINED_ROOTS: &[&str] = &[
    PERL_MODULE_ROOTS[0],
    PERL_MODULE_ROOTS[1],
    PROGRAM_ROOTS[0],
    PROGRAM_ROOTS[1],
];

/// Select installed Linux runtime roots, the dynamic-linker cache, and the
/// installed ELF libraries that cache names outside the roots, plus installed
/// executable programs, Perl modules, timezone, protocol and service data. Include
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
    for &path in PERL_MODULE_ROOTS {
        let host = root.join(path.trim_start_matches('/'));
        if host.symlink_metadata().is_ok_and(|info| info.is_dir()) {
            roots.insert(path.into(), host);
        }
    }
    let bin = root.join("bin");
    let usr_bin = root.join("usr/bin");
    let unshadowed = |mount: &str| {
        !executable.is_some_and(|image| {
            image == mount
                || mount
                    .strip_prefix(image)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    };
    let usr_bin_selected =
        unshadowed(PROGRAM_ROOTS[1]) && usr_bin.symlink_metadata().is_ok_and(|info| info.is_dir());
    // /bin may be a distinct directory or the distribution alias for /usr/bin.
    if unshadowed(PROGRAM_ROOTS[0])
        && bin.symlink_metadata().is_ok_and(|info| {
            info.is_dir()
                || (info.is_symlink()
                    && usr_bin_selected
                    && bin
                        .canonicalize()
                        .ok()
                        .zip(usr_bin.canonicalize().ok())
                        .is_some_and(|(bin, usr_bin)| bin == usr_bin))
        })
    {
        roots.insert(PROGRAM_ROOTS[0].into(), bin);
    }
    if usr_bin_selected {
        roots.insert(PROGRAM_ROOTS[1].into(), usr_bin);
    }
    let cache = root.join("etc/ld.so.cache");
    let files = select(files, roots, cache.is_file().then_some(cache))?;
    // The libc files backend reads these tables for local name lookups.
    let databases = ["/etc/protocols", "/etc/services"]
        .into_iter()
        .filter(|path| matches!(files.lookup(path), Err(Error::NotFound)))
        .map(|path| (path.to_owned(), root.join(path.trim_start_matches('/'))))
        .filter(|(_, host)| host.symlink_metadata().is_ok_and(|info| info.is_file()))
        .collect();
    let files = files.with_host_files(databases)?;
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
    if under_root(path, PROGRAM_ROOTS) {
        return accept_installed_program(_file);
    }
    Ok(!under_root(path, PERL_MODULE_ROOTS)
        || (is_perl_runtime_file(Path::new(path)) && is_perl_runtime_file(host)))
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
        if let Ok(source) = open_cached_library(path) {
            selected.insert(name.to_owned(), source.into());
        }
    }
    files
        .with_selected_backings(selected)
        .map_err(io::Error::other)
}

#[cfg(target_os = "linux")]
fn open_cached_library(path: &std::path::Path) -> io::Result<crate::user::mm::HostFileSource> {
    use crate::user::mm::HostFileSource;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "cached ELF shared object");
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
        for path in [&lib, &bin, &local_bin] {
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

        let selected = select_installed(&Files::default(), root).unwrap();
        for path in ["/bin/program", "/usr/bin/program", "/bin/alias"] {
            assert_eq!(&*selected.read(path).unwrap(), &elf);
        }
        assert_eq!(&*selected.read("/bin/script").unwrap(), script);
        for path in [
            "/bin/non-executable",
            "/bin/text",
            "/bin/invalid-script",
            "/bin/external",
            "/usr/local/bin/unselected",
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

        for path in ["/bin", "/usr/bin"] {
            let selected =
                select_installed_for_executable(&Files::default(), root, Some(path)).unwrap();
            let selected = selected
                .with_file(path.into(), Arc::from(&b"guest main"[..]))
                .unwrap();
            assert_eq!(&*selected.read(path).unwrap(), b"guest main");
        }
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
