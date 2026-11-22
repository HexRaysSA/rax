//! Read-only selection of the macOS host's dyld, caches, on-disk dylibs, and
//! system version metadata.
//!
//! Selection happens before guest execution. Only these selected files enter
//! the supplied namespace alongside a synthetic null character device. Cache
//! pages are read on demand through retained read-only handles.
use crate::user::supplied_fs::{Device, Files};
use std::io;

#[cfg(any(target_os = "macos", test))]
#[path = "runtime_files/dylibs.rs"]
mod dylibs;

#[cfg(any(target_os = "macos", test))]
const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";

/// Public kernel version strings collected when selecting the installed runtime.
#[derive(Clone, Debug)]
pub struct NativeKernelInfo {
    pub(crate) release: Vec<u8>,
    pub(crate) version: Vec<u8>,
}

impl NativeKernelInfo {
    pub(crate) fn capture() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                release: native_kernel_string(libc::KERN_OSRELEASE)?,
                version: native_kernel_string(libc::KERN_VERSION)?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Darwin kernel information requires a macOS host",
        ))
    }
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
    #[cfg(target_os = "macos")]
    {
        select_native_root(files, std::path::Path::new("/"))
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
fn select_native_root(files: &Files, root: &std::path::Path) -> io::Result<Files> {
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
    let files = select_system_version(files, root)?;
    let files = files
        .with_device(Device::Null)
        .and_then(|files| files.with_device(Device::Zero))
        .map_err(io::Error::other)?;
    let roots = [
        "/usr/lib",
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
        "/System/Cryptexes/OS/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/OS/usr/lib",
        "/System/Cryptexes/Rosetta/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/usr/lib",
        "/System/Cryptexes/Rosetta/System/x86Support/usr/lib",
        "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/usr/lib",
    ]
    .into_iter()
    .filter_map(|guest| {
        let host = root.join(guest.trim_start_matches('/'));
        host.is_dir().then(|| (guest.to_owned(), host))
    })
    .collect();
    files.with_native_library_roots(roots, Some(dylibs::accept))
}

#[cfg(any(target_os = "macos", test))]
fn select_system_version(files: Files, root: &std::path::Path) -> io::Result<Files> {
    use crate::user::supplied_fs::Error;

    if !matches!(files.lookup(SYSTEM_VERSION_PLIST), Err(Error::NotFound)) {
        return Ok(files);
    }
    // CoreFoundation's system version lookup reads this installed metadata.
    // Admit the regular file at this path only.
    let host = root.join(SYSTEM_VERSION_PLIST.trim_start_matches('/'));
    match std::fs::symlink_metadata(&host) {
        Ok(metadata) if metadata.is_file() => {
            files.with_host_file(SYSTEM_VERSION_PLIST.into(), &host)
        }
        Ok(_) => Ok(files),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(files),
        Err(error) => Err(error),
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

    #[test]
    fn system_version_metadata_is_selected_without_neighboring_files() {
        let fixture = TestFile::new(b"dyld", 4);
        let dyld = fixture.dir.join("usr/lib/dyld");
        let cache_dir = fixture.dir.join("System/Library/dyld");
        let version = fixture
            .dir
            .join(SYSTEM_VERSION_PLIST.trim_start_matches('/'));
        std::fs::create_dir_all(dyld.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::create_dir_all(version.parent().unwrap()).unwrap();
        std::fs::write(dyld, b"dyld").unwrap();
        std::fs::write(cache_dir.join("dyld_shared_cache_arm64e"), b"cache").unwrap();
        std::fs::write(&version, b"installed").unwrap();
        std::fs::write(version.with_file_name("Unselected.plist"), b"other").unwrap();
        let selected = select_native_root(&Files::default(), &fixture.dir).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"installed");
        assert!(
            selected
                .lookup("/System/Library/CoreServices/Unselected.plist")
                .is_err()
        );

        let supplied = Files::default()
            .with_file(SYSTEM_VERSION_PLIST.into(), Arc::from(&b"supplied"[..]))
            .unwrap();
        let selected = select_native_root(&supplied, &fixture.dir).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"supplied");

        let caller = TestFile::new(b"caller", 6);
        std::fs::write(caller.dir.join("SystemVersion.plist"), b"mounted").unwrap();
        let mounted = Files::default()
            .with_host_roots(std::collections::BTreeMap::from([(
                "/System/Library/CoreServices".into(),
                caller.dir.clone(),
            )]))
            .unwrap();
        let selected = select_native_root(&mounted, &fixture.dir).unwrap();
        assert_eq!(&*selected.read(SYSTEM_VERSION_PLIST).unwrap(), b"mounted");

        let blocked = Files::default()
            .with_file(
                "/System/Library/CoreServices".into(),
                Arc::from(&b"file"[..]),
            )
            .unwrap();
        let selected = select_native_root(&blocked, &fixture.dir).unwrap();
        assert_eq!(
            &*selected.read("/System/Library/CoreServices").unwrap(),
            b"file"
        );
        assert!(selected.lookup(SYSTEM_VERSION_PLIST).is_err());

        #[cfg(unix)]
        {
            std::fs::remove_file(&version).unwrap();
            std::os::unix::fs::symlink(&fixture.path, &version).unwrap();
            let selected = select_native_root(&Files::default(), &fixture.dir).unwrap();
            assert!(selected.lookup(SYSTEM_VERSION_PLIST).is_err());
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
            let selected = select_native_root(&Files::default(), &fixture.dir).unwrap();
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
            let selected = select_native_root(&supplied, &fixture.dir).unwrap();
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
            select_native_root(&Files::default(), &fixture.dir)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
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
        let rosetta_path = "/System/Cryptexes/Rosetta/usr/lib";
        let rosetta = root.join(rosetta_path.trim_start_matches('/'));
        let cache = root.join("System/Library/dyld");
        for dir in [&lib, &version, &rosetta, &cache] {
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
        std::fs::write(rosetta.join("libextra.dylib"), thin).unwrap();
        std::os::unix::fs::symlink("A", framework.join("Versions/Current")).unwrap();
        std::os::unix::fs::symlink("Versions/Current/Example", framework.join("Example")).unwrap();
        let outside = root.join("secret.dylib");
        std::fs::write(&outside, thin).unwrap();
        std::os::unix::fs::symlink(outside, lib.join("escape.dylib")).unwrap();
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
        let selected = select_native_root(&explicit, root).unwrap();
        assert_eq!(
            &*selected.read("/usr/lib/libonly.dylib").unwrap(),
            b"explicit"
        );
        assert_eq!(
            &*selected
                .read("/System/Library/Frameworks/Example.framework/Example")
                .unwrap(),
            &thin
        );
        assert_eq!(
            &*selected
                .read(&format!("{rosetta_path}/libextra.dylib"))
                .unwrap(),
            &thin
        );
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
        let selected = select_native_root(&blocked, root).unwrap();
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
        for (path, arguments, expected) in [
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
