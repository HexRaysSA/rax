//! Native Linux runtime selection for a closed process. Installed loader and
//! library directories are mounted read-only; there is no general host path
//! fallback, host descriptor exposure, or separate sysroot requirement.
use crate::user::supplied_fs::Files;
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::{collections::BTreeMap, path::PathBuf};

/// Select installed Linux runtime roots and the dynamic-linker cache. Explicit
/// supplied files override installed files. Libraries loaded later by `dlopen`
/// are discovered through the same selected roots, rather than a dependency
/// snapshot. Nonstandard runtime locations can be selected by the caller using
/// [`Files::with_host_roots`] instead of this convenience selector.
pub fn native(files: &Files) -> io::Result<Files> {
    #[cfg(target_os = "linux")]
    {
        let mut roots = BTreeMap::new();
        for name in ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"] {
            let path = PathBuf::from(name);
            if path.is_dir() {
                roots.insert(name.to_owned(), path);
            }
        }
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no installed Linux library directories",
            ));
        }
        let cache = PathBuf::from("/etc/ld.so.cache");
        select(files, roots, cache.is_file().then_some(cache))
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

#[cfg(any(target_os = "linux", test))]
fn select(
    files: &Files,
    roots: BTreeMap<String, PathBuf>,
    cache: Option<PathBuf>,
) -> io::Result<Files> {
    let files = files.with_host_roots(roots)?;
    match cache {
        Some(cache) if files.lookup("/etc/ld.so.cache").is_err() => {
            files.with_host_file("/etc/ld.so.cache".into(), &cache)
        }
        _ => Ok(files),
    }
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
        assert!(selected.lookup("/etc/passwd").is_err());
        let selected = select(
            &Files::default(),
            BTreeMap::from([("/lib".into(), fixture.dir.clone())]),
            None,
        )
        .unwrap();
        assert!(selected.lookup("/etc/ld.so.cache").is_err());
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
            assert!(process.state.mm.program.interp_base > 0);
            assert!(process.state.exe_host_path.is_none());
            let preloaded = expected == "preloaded-libm\n";
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            loop {
                match process.run_slice(4096, &cancelled) {
                    RunStatus::BudgetExhausted => assert!(
                        std::time::Instant::now() < deadline,
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
