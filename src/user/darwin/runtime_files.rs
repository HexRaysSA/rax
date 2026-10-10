//! Read-only selection of the macOS host's dyld and split shared caches.
//!
//! Selection happens before guest execution. Only these selected files enter
//! the supplied namespace; this does not enable host-service forwarding. Cache
//! pages are read on demand through retained handles rather than copied in full.
use crate::user::supplied_fs::Files;
use std::io;

/// Add the native macOS runtime, preserving explicit supplied-file overrides.
/// A different host cannot supply its own runtime for a Darwin guest.
pub fn native(files: &Files) -> io::Result<Files> {
    #[cfg(target_os = "macos")]
    {
        select(
            files,
            std::path::Path::new("/usr/lib/dyld"),
            &[
                std::path::PathBuf::from("/System/Library/dyld"),
                std::path::PathBuf::from(
                    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
                ),
            ],
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = files;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Darwin runtime files require a macOS host",
        ))
    }
}

#[cfg(any(target_os = "macos", test))]
fn select(
    files: &Files,
    dyld: &std::path::Path,
    directories: &[std::path::PathBuf],
) -> io::Result<Files> {
    use std::collections::BTreeMap;
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
    files.with_host_files(selected)
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
        use crate::user::darwin::{
            DarwinConfig, DarwinProcess, ExitStatus, RunStatus, loader::ImageFile,
        };
        let files = native(&Files::default()).expect("macOS host dyld and shared cache");
        for (path, arguments, expected) in [
            ("/usr/bin/true", vec![], ""),
            (
                "/usr/bin/printf",
                vec![b"%s\\n".to_vec(), b"native-cache".to_vec()],
                "native-cache\n",
            ),
        ] {
            let console = crate::user::console::CapturedConsole::new(Vec::new(), 65536).unwrap();
            let mut argv = vec![b"/program".to_vec()];
            argv.extend(arguments);
            let mut config =
                DarwinConfig::embedded("/program", argv, vec![], files.clone(), console.clone());
            config.arena_bytes = 256 << 20;
            config.slice_insns = 4096;
            let image = ImageFile::new(std::fs::read(path).unwrap(), "/program");
            let mut process = DarwinProcess::spawn(config, image).unwrap();
            assert!(!process.proc.config.host_services);
            assert!(process.proc.vfs.is_closed());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            loop {
                match process.run_slice(256, &cancelled) {
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
                        assert!(
                            process.proc.shared_region.is_some(),
                            "{path} did not use the shared cache"
                        );
                        let mut stdout = vec![0; 65536];
                        let n = console
                            .drain(crate::user::console::OutputStream::Stdout, &mut stdout)
                            .unwrap();
                        assert_eq!(&stdout[..n], expected.as_bytes(), "{path}");
                        break;
                    }
                    other => panic!("{path}: native runtime stopped: {other:?}"),
                }
            }
        }
    }
}
