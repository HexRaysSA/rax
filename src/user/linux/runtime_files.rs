//! Native Linux runtime selection for a closed process. Installed loader and
//! library directories are mounted read-only; there is no general host path
//! fallback, host descriptor exposure, or separate sysroot requirement.
#[cfg(target_os = "linux")]
use crate::user::supplied_fs::WorkspaceFlavor;
use crate::user::supplied_fs::{Device, Files};
use std::io;
#[cfg(any(target_os = "linux", all(test, unix)))]
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::{collections::BTreeMap, path::PathBuf};
#[cfg(any(target_os = "linux", test))]
mod ld_cache;

/// Select installed Linux runtime roots, the dynamic-linker cache, and the
/// installed ELF libraries that cache names outside the roots. Include a
/// synthetic `/dev/null` in the guest namespace. Explicit
/// supplied files override installed files. Later `dlopen` calls use the same
/// namespace. Unregistered runtime roots require explicit selection.
pub fn native(files: &Files) -> io::Result<Files> {
    #[cfg(target_os = "linux")]
    {
        let roots = installed_roots(Path::new("/"));
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no installed Linux library directories",
            ));
        }
        let cache = PathBuf::from("/etc/ld.so.cache");
        select(files, roots, cache.is_file().then_some(cache))
            .map(|files| files.with_temp_workspace(WorkspaceFlavor::Linux))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = files;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Linux runtime selection requires a Linux host",
        ))
    }
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
    let root_names = roots.keys().cloned().collect::<Vec<_>>();
    let files = files
        .with_device(Device::Null)
        .and_then(|files| files.with_device(Device::Zero))
        .and_then(|files| files.with_device(Device::Urandom))
        .map_err(io::Error::other)?;
    let files = files.with_linux_library_roots(roots)?;
    let Some(cache) = cache.filter(|_| files.lookup("/etc/ld.so.cache").is_err()) else {
        return Ok(files);
    };
    let files = files.with_host_file("/etc/ld.so.cache".into(), &cache)?;
    #[cfg(target_os = "linux")]
    let files = with_cached_libraries(files, &root_names)?;
    Ok(files)
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
