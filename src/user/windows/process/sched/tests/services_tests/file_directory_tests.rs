//! Retained NT enumeration through actual service dispatch on every guest ABI.
use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object};
use std::path::{Path, PathBuf};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "rax-nt-directory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        for name in [
            "alpha.txt",
            "beta.dat",
            "empty",
            "long supplementary 🚀 filename.txt",
        ] {
            std::fs::write(path.join(name), b"owned fixture").unwrap();
        }
        std::fs::create_dir(path.join("subdir")).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            if error.kind() != std::io::ErrorKind::NotFound && !std::thread::panicking() {
                panic!("owned directory fixture cleanup: {error}");
            }
        }
    }
}

fn object(path: &Path) -> Object {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(0x110001)
            .share_mode(7)
            .custom_flags(0x0200_0000)
            .open(path)
            .unwrap()
    };
    #[cfg(not(windows))]
    let file = std::fs::File::open(path).unwrap();
    let identity = FileIdentity::of_open(path, Some(&file), &file.metadata().unwrap()).unwrap();
    Object::File(FileObj {
        host: Some(file),
        host_path: path.into(),
        path: "C:\\fixture".into(),
        access: 0x100001,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(identity)),
        null: false,
        append: false,
        delete_on_close: false,
        directory: true,
        overlapped: false,
    })
}

fn pages(p: &mut Proc) -> u64 {
    p.vm.allocate(
        None,
        2 * PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap()
    .0
}

fn call(p: &mut Proc, t: &mut Thread, args: &[u64], legacy: bool) -> u32 {
    let name = if legacy {
        "NtQueryDirectoryFile"
    } else {
        "NtQueryDirectoryFileEx"
    };
    let number = if legacy { 0x55 } else { 0x44 };
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, number)));
    super::nls_tests::arguments(p, t, &args[..args.len().min(8)]);
    if p.arch == WinArch::Arm64 {
        for (index, arg) in args.iter().enumerate().skip(8) {
            p.space
                .w64(t.cpu.sp() + (index - 8) as u64 * 8, *arg)
                .unwrap();
        }
    } else {
        super::nls_tests::arguments(p, t, args);
        t.cpu.set_gpr(0, u64::from(number));
    }
    let sp = t.cpu.sp();
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, number))
    };
    assert_eq!(outcome, Outcome::Continue, "{}/{name}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn args(
    handle: u64,
    base: u64,
    length: u64,
    class: u64,
    flags: u64,
    name: u64,
    legacy: bool,
) -> Vec<u64> {
    let mut result = vec![
        handle,
        0,
        0,
        0,
        base,
        base + 512,
        length,
        class,
        if legacy { (flags >> 1) & 1 } else { flags },
        name,
    ];
    if legacy {
        result.push(flags & 1);
    }
    result
}

fn name(p: &mut Proc, base: u64, text: &str) -> u64 {
    let pointer = base + 128;
    let raw: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.space.w16(pointer, raw.len() as u16).unwrap();
    p.space.w16(pointer + 2, raw.len() as u16).unwrap();
    p.space
        .wptr(pointer + p.arch.ptr_size(), p.arch.ptr_size(), base + 256)
        .unwrap();
    p.space.wr(base + 256, &raw).unwrap();
    pointer
}

fn information(p: &Proc, base: u64) -> u64 {
    p.space
        .ptr(base + p.arch.ptr_size(), p.arch.ptr_size())
        .unwrap()
}

fn first_name(p: &Proc, base: u64, class: u32) -> String {
    let (start, length) = match class {
        1 => (64, 60),
        2 => (68, 60),
        3 => (94, 60),
        12 => (12, 8),
        37 => (104, 60),
        38 => (80, 60),
        60 => (88, 60),
        63 => (114, 60),
        _ => panic!(),
    };
    let bytes = p.space.u32(base + 512 + length).unwrap() as usize;
    let raw = p.space.bytes(base + 512 + start, bytes).unwrap();
    String::from_utf16(
        &raw.chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn nt_directory_all_record_classes_minimum_truncation_retry_and_publication() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        for legacy in [false, true] {
            let root = Root::new();
            let (mut process, mut thread) = fixture(arch, "NtQueryDirectoryFileEx", 0x44);
            let p = process.state_mut();
            let base = pages(p);
            let filter = name(p, base, "alpha.txt");
            for (class, minimum) in [
                (1, 72),
                (2, 72),
                (3, 96),
                (12, 16),
                (37, 112),
                (38, 88),
                (60, 96),
                (63, 120),
            ] {
                let handle = u64::from(p.objects.insert(object(&root.0)));
                p.space.wr(base, &[0xa5; 32]).unwrap();
                p.space.wr(base + 512, &[0xa5; 1024]).unwrap();
                assert_eq!(
                    call(
                        p,
                        &mut thread,
                        &args(handle, base, minimum - 1, class, 2, filter, legacy),
                        legacy
                    ),
                    STATUS_INFO_LENGTH_MISMATCH,
                    "{arch}/{class}"
                );
                assert_eq!(p.space.bytes(base, 32).unwrap(), [0xa5; 32]);
                assert_eq!(
                    call(
                        p,
                        &mut thread,
                        &args(handle, base, minimum, class, 2, filter, legacy),
                        legacy
                    ),
                    STATUS_BUFFER_OVERFLOW,
                    "{arch}/{class}"
                );
                assert_eq!(information(p, base), minimum);
                assert_eq!(p.space.bytes(base + 512 + minimum, 16).unwrap(), [0xa5; 16]);
                if arch != WinArch::X86 {
                    assert_eq!(p.space.u32(base + 4).unwrap(), 0xa5a5_a5a5);
                }
                assert_eq!(
                    call(
                        p,
                        &mut thread,
                        &args(handle, base, 616, class, 2, 0, legacy),
                        legacy
                    ),
                    STATUS_SUCCESS
                );
                assert_eq!(first_name(p, base, class as u32), "alpha.txt");
                assert_eq!(
                    call(
                        p,
                        &mut thread,
                        &args(handle, base, 616, class, 2, 0, legacy),
                        legacy
                    ),
                    STATUS_NO_MORE_FILES
                );
                assert_eq!(information(p, base), 0);
            }
        }
    }
}

#[test]
fn nt_directory_shared_cursor_independent_open_and_restart_replaces_filter() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        for legacy in [false, true] {
            let root = Root::new();
            let (mut process, mut thread) = fixture(arch, "NtQueryDirectoryFileEx", 0x44);
            let p = process.state_mut();
            let base = pages(p);
            let id = p.objects.create(object(&root.0));
            let first = u64::from(p.objects.open_access(id, false, 0x100001).unwrap());
            let duplicate = u64::from(p.objects.open_access(id, false, 1).unwrap());
            let independent = u64::from(p.objects.insert(object(&root.0)));
            // A unique expression exposes shared cursor ownership without
            // assuming the host filesystem places dot entries first.
            let filter = name(p, base, "alpha.txt");
            for (handle, expected) in [
                (first, STATUS_SUCCESS),
                (duplicate, STATUS_NO_MORE_FILES),
                (independent, STATUS_SUCCESS),
            ] {
                assert_eq!(
                    call(
                        p,
                        &mut thread,
                        &args(handle, base, 616, 3, 2, filter, legacy),
                        legacy
                    ),
                    expected
                );
                if expected == STATUS_SUCCESS {
                    assert_eq!(first_name(p, base, 3), "alpha.txt");
                }
            }
            let alpha = name(p, base, "alpha.txt");
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(duplicate, base, 616, 3, 3, alpha, legacy),
                    legacy
                ),
                STATUS_SUCCESS
            );
            assert_eq!(first_name(p, base, 3), "alpha.txt");
            let ignored = name(p, base, "beta.dat");
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(first, base, 616, 3, 2, ignored, legacy),
                    legacy
                ),
                STATUS_NO_MORE_FILES
            );
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(first, base, 616, 3, 3, ignored, legacy),
                    legacy
                ),
                STATUS_SUCCESS
            );
            assert_eq!(first_name(p, base, 3), "beta.dat");
            let unqueried = u64::from(p.objects.insert(object(&root.0)));
            let retained_path = root.0.with_file_name(format!(
                "{}-retained",
                root.0.file_name().unwrap().to_string_lossy()
            ));
            assert!(!retained_path.exists());
            std::fs::rename(&root.0, &retained_path).unwrap();
            let retained = Root(retained_path);
            std::fs::create_dir(&root.0).unwrap();
            std::fs::write(root.0.join("replacement.txt"), b"replacement").unwrap();
            let alpha = name(p, base, "alpha.txt");
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(first, base, 616, 3, 3, alpha, legacy),
                    legacy
                ),
                STATUS_SUCCESS
            );
            assert_eq!(first_name(p, base, 3), "alpha.txt");
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(unqueried, base, 616, 3, 2, alpha, legacy),
                    legacy
                ),
                STATUS_SUCCESS
            );
            assert_eq!(first_name(p, base, 3), "alpha.txt");
            let replacement = u64::from(p.objects.insert(object(&root.0)));
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &args(replacement, base, 616, 3, 2, alpha, legacy),
                    legacy
                ),
                STATUS_NO_SUCH_FILE
            );
            drop(process);
            drop(retained);
        }
    }
}

#[test]
fn nt_directory_no_cursor_update_keeps_normal_scan_and_first_missing_keeps_iosb() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let root = Root::new();
        let (mut process, mut thread) = fixture(arch, "NtQueryDirectoryFileEx", 0x44);
        let p = process.state_mut();
        let base = pages(p);
        let handle = u64::from(p.objects.insert(object(&root.0)));
        // The unmodified independent open establishes this filesystem's first
        // entry. Directory order is not part of the NT cursor contract.
        let reference = u64::from(p.objects.insert(object(&root.0)));
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(reference, base, 616, 3, 2, 0, false),
                false
            ),
            STATUS_SUCCESS
        );
        let first = first_name(p, base, 3);
        // A unique expression tests cursor isolation without assuming a host
        // filesystem's order among multiple matching directory entries.
        let filter = name(p, base, "alpha.txt");
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(handle, base, 616, 3, 18, filter, false),
                false
            ),
            STATUS_SUCCESS
        );
        assert_eq!(first_name(p, base, 3), "alpha.txt");
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(handle, base, 616, 3, 2, 0, false),
                false
            ),
            STATUS_SUCCESS
        );
        assert_eq!(first_name(p, base, 3), first);
        let missing = u64::from(p.objects.insert(object(&root.0)));
        let filter = name(p, base, "absent.xyz");
        p.space.wr(base, &[0xa5; 32]).unwrap();
        p.space.wr(base + 512, &[0xa5; 616]).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(missing, base, 616, 3, 2, filter, false),
                false
            ),
            STATUS_NO_SUCH_FILE
        );
        assert_eq!(p.space.bytes(base, 32).unwrap(), [0xa5; 32]);
        assert_eq!(p.space.bytes(base + 512, 616).unwrap(), [0xa5; 616]);
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(missing, base, 616, 3, 2, 0, false),
                false
            ),
            STATUS_NO_MORE_FILES
        );
        assert_eq!(information(p, base), 0);
    }
}

#[test]
fn nt_directory_permissions_and_failed_guest_capture_do_not_advance_cursor() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let root = Root::new();
        let (mut process, mut thread) = fixture(arch, "NtQueryDirectoryFileEx", 0x44);
        let p = process.state_mut();
        let base = pages(p);
        let id = p.objects.create(object(&root.0));
        let handle = u64::from(p.objects.open_access(id, false, 1).unwrap());
        let denied = u64::from(p.objects.open_access(id, false, 0x80).unwrap());
        let filter = name(p, base, "alpha.txt");
        p.space.wr(base, &[0xa5; 32]).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(denied, base, 616, 3, 2, filter, false),
                false
            ),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(p.space.bytes(base, 32).unwrap(), [0xa5; 32]);
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(handle, base, 616, 3, 2, 1, false),
                false
            ),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(handle, base, 616, 3, 2, filter, false),
                false
            ),
            STATUS_SUCCESS
        );
        assert_eq!(first_name(p, base, 3), "alpha.txt");
        assert_eq!(
            call(
                p,
                &mut thread,
                &args(0x1234, base, 616, 3, 2, 0, false),
                false
            ),
            STATUS_INVALID_HANDLE
        );
    }
}

#[test]
fn nt_directory_appended_family_preserves_prior_ordinals_and_trap_rvas_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| {
            table
                .iter()
                .any(|export| export.name == "NtQueryDirectoryFileEx")
        })
        .unwrap();
    assert_eq!(family + 1, current.exports.len());
    assert_eq!(current.exports[family - 1][0].name, "NtReadFile");
    assert_eq!(
        current.exports[family]
            .iter()
            .map(|export| export.name)
            .collect::<Vec<_>>(),
        ["NtQueryDirectoryFileEx", "NtQueryDirectoryFile"]
    );
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(current, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice(),
            "{arch}"
        );
        assert_eq!(after.symbols.len(), before.symbols.len() + 2);
    }
}
