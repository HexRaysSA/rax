//! Native file opens: grants, output ordering and retained resource ownership.

#[path = "file_open_tests/paired.rs"]
mod paired;

#[path = "file_open_tests/boundaries.rs"]
mod boundaries;

use super::{Outcome, fixture, handle_stop, stop};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::loader::services::tests::table;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::user::windows::process::{Proc, Thread, WindowsProcess};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct Directory(pub(super) PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "rax-native-file-open-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("private fixture directory: {error}"),
            }
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove private file-open fixtures");
    }
}

pub(super) struct Harness {
    pub(super) process: WindowsProcess,
    thread: Thread,
    pub(super) base: u64,
    pub(super) directory: Directory,
}

impl Harness {
    pub(super) fn new(arch: WinArch) -> Self {
        let directory = Directory::new();
        std::fs::write(directory.0.join("fixture.bin"), b"fixture").unwrap();
        let (mut process, thread) = fixture(arch, "NtOpenFile", 0x33);
        let p = process.state_mut();
        let config = Arc::make_mut(&mut p.cfg);
        config.host_filesystem = true;
        config.drives = crate::user::windows::fs::DriveMap::empty();
        config.drives.set('C', &directory.0);
        let base =
            p.vm.allocate(
                None,
                8 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.space
            .wr(base, &vec![0xa5; 8 * PAGE_SIZE as usize])
            .unwrap();
        let mut h = Self {
            process,
            thread,
            base,
            directory,
        };
        h.name("\\??\\C:\\fixture.bin");
        h
    }

    pub(super) fn attrs(&self) -> u64 {
        self.base + 2 * PAGE_SIZE
    }

    pub(super) fn name(&mut self, name: &str) {
        let at = self.attrs();
        let p = self.process.state_mut();
        let width = p.arch.ptr_size();
        let size = if p.arch.is64() { 48 } else { 24 };
        p.space.wr(at, &vec![0; size]).unwrap();
        p.space.w32(at, size as u32).unwrap();
        p.space.wptr(at + 2 * width, width, at + 64).unwrap();
        p.space.w32(at + 3 * width, 0x840).unwrap();
        let units: Vec<u16> = name.encode_utf16().collect();
        p.space.w16(at + 64, (units.len() * 2) as u16).unwrap();
        p.space.w16(at + 66, 0).unwrap();
        p.space.wptr(at + 64 + width, width, at + 128).unwrap();
        p.space.put_wunits(at + 128, &units).unwrap();
    }

    fn open(&mut self, output: u64, io: u64) -> u32 {
        self.open_with(output, io, 0x100021, 5, 0x60)
    }

    fn open_with(&mut self, output: u64, io: u64, access: u32, share: u32, options: u32) -> u32 {
        self.invoke(&[
            output,
            u64::from(access),
            self.attrs(),
            io,
            u64::from(share),
            u64::from(options),
        ])
    }

    fn invoke(&mut self, args: &[u64; 6]) -> u32 {
        self.invoke_api("NtOpenFile", args)
    }

    pub(super) fn invoke_api(&mut self, name: &str, args: &[u64]) -> u32 {
        let p = self.process.state_mut();
        let module = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((module, table(p.arch, name, 0x33)));
        let sp = self.thread.cpu.sp();
        arguments(p, &mut self.thread, args);
        let result = if p.arch == WinArch::X86 {
            crate::user::windows::process::services::wow64(p, &mut self.thread, 0x1234_0000)
        } else {
            handle_stop(p, &mut self.thread, stop(p.arch, 0x33))
        };
        assert_eq!(result, Outcome::Continue, "{}/{name}", p.arch);
        assert_eq!(self.thread.cpu.pc(), 0x1234_0004);
        assert_eq!(
            self.thread.cpu.sp(),
            sp + if p.arch == WinArch::X86 { 4 } else { 0 }
        );
        assert!(self.thread.frames.is_empty());
        self.thread.cpu.set_sp(sp);
        self.thread.cpu.gpr(0) as u32
    }
}

#[test]
fn srp_device_open_replays_captured_absence_and_preserves_outputs() {
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-srp-device/arm64-26200-open.json"
    ))
    .unwrap();
    let name = evidence["name"].as_str().unwrap();
    let request = &evidence["guest_request"];
    let flags = request["flags"].as_u64().unwrap() as u32;
    let access = request["access"].as_u64().unwrap();
    let share = request["share"].as_u64().unwrap();
    let options = request["options"].as_u64().unwrap();
    let exact = &evidence["exact_control"];
    assert_eq!(exact["opened"], false);
    for field in ["access", "share", "options", "flags"] {
        assert_eq!(request[field], exact[field]);
    }
    assert_eq!(exact["status"], STATUS_OBJECT_NAME_NOT_FOUND);

    for (arch, build, machine, absent, request_flags, request_access, expected) in [
        (WinArch::Arm64, 26200, 0xaa64, true, flags, access, true),
        (WinArch::Arm64, 26200, 0xaa64, false, flags, access, false),
        (WinArch::Arm64, 26201, 0xaa64, true, flags, access, false),
        (WinArch::Arm64, 26200, 0x8664, true, flags, access, false),
        (WinArch::X64, 26200, 0xaa64, true, flags, access, false),
        (WinArch::Arm64, 26200, 0xaa64, true, 0, access, false),
        (WinArch::Arm64, 26200, 0xaa64, true, flags, 0x80, false),
    ] {
        let mut h = Harness::new(arch);
        h.name(name);
        let (output, io, attrs) = (h.base, h.base + 32, h.attrs());
        let p = h.process.state_mut();
        let cfg = Arc::make_mut(&mut p.cfg);
        cfg.host_filesystem = false;
        cfg.version.major = 10;
        cfg.version.minor = 0;
        cfg.version.build = build;
        p.object_namespace.native_machine = Some(machine);
        p.object_namespace.srp_device_absent = absent;
        p.space
            .w32(attrs + 3 * p.arch.ptr_size(), request_flags)
            .unwrap();
        p.space
            .wptr(io, 8, exact["iosb_status"].as_u64().unwrap())
            .unwrap();
        p.space
            .wptr(io + 8, 8, exact["iosb_information"].as_u64().unwrap())
            .unwrap();
        let handles = p.objects.iter().count();
        let before = p.space.bytes(output, 48).unwrap();

        arguments(
            p,
            &mut h.thread,
            &[output, request_access, attrs, io, share, options],
        );
        let result = handle_stop(p, &mut h.thread, stop(arch, 0x33));
        if expected {
            assert_eq!(result, Outcome::Continue);
            assert_eq!(h.thread.cpu.gpr(0), u64::from(STATUS_OBJECT_NAME_NOT_FOUND));
        } else {
            assert!(matches!(result, Outcome::Fail(reason)
                             if reason.contains("outside the captured absence profile")));
        }
        assert_eq!(p.space.bytes(output, 48).unwrap(), before);
        assert_eq!(p.objects.iter().count(), handles);
    }
}

pub(super) fn selection(h: &mut Harness) -> PathBuf {
    let directory = h.directory.0.join("runtime");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("fixture.dll"), b"native").unwrap();
    std::fs::write(directory.join("unselected.exe"), b"unselected").unwrap();
    let mut schema = [0u8; 28];
    schema[..4].copy_from_slice(&6u32.to_le_bytes());
    schema[4..8].copy_from_slice(&28u32.to_le_bytes());
    let p = h.process.state_mut();
    p.native = Some(crate::user::windows::native::NativeRuntime {
        directory: directory.canonicalize().unwrap(),
        guest_root: "C:\\Windows".into(),
        guest_directory: format!(
            "C:\\Windows\\{}",
            if p.arch == WinArch::X86 {
                "SysWOW64"
            } else {
                "System32"
            }
        ),
        version: p.cfg.version.clone(),
        apisets: crate::user::windows::loader::apiset_schema::ApiSetSchema::parse(&schema).unwrap(),
        registry: p.registry.clone(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        code_integrity: Err("controlled absent code integrity metadata".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
        secure_boot_policy: Err("secure boot policy not captured in this fixture".into()),
        policy_catalog: Err("software policy not captured in this fixture".into()),
        code_integrity_policies: Err("code integrity policies not captured in this fixture".into()),
        gui: Default::default(),
    });
    Arc::make_mut(&mut p.cfg).host_filesystem = false;
    directory
}

#[test]
fn native_file_open_selected_runtime_grant_is_read_only_and_cannot_enroll_other_paths() {
    use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let directory = selection(&mut h);
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        h.name("\\??\\C:\\WINDOWS\\SYSTEM32\\FIXTURE.dll");
        for access in [0x100021, 0x120089, 0x100080, 0x100000, 0x02100000] {
            assert_eq!(
                h.open_with(output, io, access, 7, 0x60),
                STATUS_SUCCESS,
                "{arch}/{access:#x}"
            );
            let p = h.process.state_mut();
            let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
            assert!(p.objects.runtime_library(handle));
            assert_eq!(p.objects.access(handle).unwrap() & !0x1200a9, 0);
            p.objects.close(handle).unwrap();
        }
        for access in [0x100002, 0x110000, 0x120116, 0x100100, 0x01100000] {
            assert_eq!(
                h.open_with(output, io, access, 7, 0x60),
                STATUS_ACCESS_DENIED,
                "{arch}/{access:#x}"
            );
        }
        for path in [
            "\\??\\C:\\fixture.bin",
            "\\??\\C:\\Windows\\System32\\unselected.exe",
        ] {
            h.name(path);
            assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED, "{arch}/{path}");
        }
        assert_eq!(
            std::fs::read(directory.join("fixture.dll")).unwrap(),
            b"native"
        );
        assert!(!h.process.state().cfg.host_filesystem);
    }
}

#[test]
fn native_file_open_mui_satellites_require_an_installed_owner_and_read_only_access() {
    use crate::user::windows::nt::status::{STATUS_ACCESS_DENIED, STATUS_OBJECT_PATH_NOT_FOUND};
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let directory = selection(&mut h);
        let locale = directory.join("en-US");
        std::fs::create_dir(&locale).unwrap();
        let executable = h.process.state().modules.exe().name.clone();
        std::fs::write(
            locale.join(format!("{executable}.mui")),
            b"installed executable",
        )
        .unwrap();
        std::fs::write(locale.join("fixture.dll.mui"), b"installed DLL").unwrap();
        std::fs::write(locale.join("lookalike.dll.mui"), b"foreign DLL").unwrap();
        std::fs::write(locale.join("unselected.exe.mui"), b"foreign executable").unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let prefix = r"\??\C:\WINDOWS\SYSTEM32";
        let executable_path = format!(r"{prefix}\EN-us\{executable}.mui");
        h.name(&executable_path);
        assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED);
        h.process.state_mut().modules.installed_executable = true;
        for (path, contents) in [
            (executable_path, b"installed executable".as_slice()),
            (
                format!(r"{prefix}\en-US\FIXTURE.DLL.MUI"),
                b"installed DLL".as_slice(),
            ),
        ] {
            h.name(&path);
            assert_eq!(
                h.open_with(output, io, 0x100001, 7, 0x60),
                STATUS_SUCCESS,
                "{arch}/{path}"
            );
            let p = h.process.state_mut();
            let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
            assert!(p.objects.runtime_library(handle));
            assert_eq!(p.objects.access(handle), Some(0x100001));
            let Some(crate::user::windows::objects::Object::File(file)) = p.objects.get(handle)
            else {
                panic!("MUI handle must own a file");
            };
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut file.host.as_ref().unwrap(), &mut bytes).unwrap();
            assert_eq!(bytes, contents);
            p.objects.close(handle).unwrap();
            assert_eq!(
                h.open_with(output, io, 0x100002, 7, 0x60),
                STATUS_ACCESS_DENIED
            );
        }
        for name in [
            r"en-US\lookalike.dll.mui",
            r"en-US\unselected.exe.mui",
            r"en_US\fixture.dll.mui",
            r"en-US\nested\fixture.dll.mui",
            r"fixture.dll.mui",
        ] {
            h.name(&format!(r"{prefix}\{name}"));
            assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED, "{arch}/{name}");
        }
        h.name(&format!(r"{prefix}\zz-ZZ\fixture.dll.mui"));
        assert_eq!(h.open(output, io), STATUS_OBJECT_PATH_NOT_FOUND);
        #[cfg(unix)]
        {
            let foreign = h.directory.0.join("fixture.bin");
            std::os::unix::fs::symlink(foreign, locale.join("fixture.dll.mui.link")).unwrap();
            std::fs::rename(
                locale.join("fixture.dll.mui.link"),
                locale.join("fixture.dll.mui"),
            )
            .unwrap();
            h.name(&format!(r"{prefix}\en-US\fixture.dll.mui"));
            assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED);
        }
        assert!(!h.process.state().cfg.host_filesystem);
    }
}

#[test]
fn native_file_open_confines_the_default_sort_table_to_read_only_access() {
    use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;
    use crate::user::windows::objects::Object;

    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        selection(&mut h);
        let sorting = h.directory.0.join("Globalization").join("Sorting");
        std::fs::create_dir_all(&sorting).unwrap();
        std::fs::write(sorting.join("SortDefault.nls"), b"installed sort data").unwrap();
        std::fs::write(sorting.join("Other.nls"), b"unselected data").unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let guest = r"\??\C:\WINDOWS\GLOBALIZATION\SORTING";
        h.name(&format!(r"{guest}\sortdefault.nls"));
        assert_eq!(
            h.open_with(output, io, 0x100001, 7, 0x60),
            STATUS_SUCCESS,
            "{arch}"
        );
        let p = h.process.state_mut();
        let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
        assert!(p.objects.runtime_library(handle));
        let Some(Object::File(file)) = p.objects.get(handle) else {
            panic!("sort table must open a file");
        };
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file.host.as_ref().unwrap(), &mut bytes).unwrap();
        assert_eq!(bytes, b"installed sort data");
        p.objects.close(handle).unwrap();
        assert_eq!(
            h.open_with(output, io, 0x100002, 7, 0x60),
            STATUS_ACCESS_DENIED
        );
        h.name(&format!(r"{guest}\Other.nls"));
        assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED);
        #[cfg(unix)]
        {
            let table = sorting.join("SortDefault.nls");
            std::fs::remove_file(&table).unwrap();
            std::os::unix::fs::symlink(h.directory.0.join("fixture.bin"), table).unwrap();
            h.name(&format!(r"{guest}\SortDefault.nls"));
            assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED);
        }
        assert!(!h.process.state().cfg.host_filesystem);
    }
}

#[test]
fn native_file_open_every_iosb_prefix_has_measured_ownership_and_atomic_store_effects() {
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        for available in 0..=16 {
            let mut h = Harness::new(arch);
            let boundary = h.base + 4 * PAGE_SIZE;
            let io = boundary - available;
            let output = h.base;
            let width = arch.ptr_size();
            h.process
                .state_mut()
                .vm
                .protect(boundary, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let before = h.process.state().objects.iter().count();
            let ok = available >= 2 * width;
            assert_eq!(
                h.open(output, io),
                if ok {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                "{arch}/{available}"
            );
            let p = h.process.state();
            let handle = p.space.ptr(output, width).unwrap();
            let published = arch == WinArch::X86 || available >= 4;
            if published {
                assert_ne!(handle, 0);
                assert_ne!(handle, arch.ptr(0xa5a5a5a5a5a5a5a5));
                let retained = ok || arch != WinArch::X86;
                assert_eq!(
                    matches!(p.objects.get(handle), Some(Object::File(_))),
                    retained,
                    "{arch}/{available}"
                );
                assert_eq!(p.objects.iter().count(), before + usize::from(retained));
            } else {
                assert_eq!(handle, arch.ptr(0xa5a5a5a5a5a5a5a5));
                assert_eq!(p.objects.iter().count(), before);
            }
            let mut expected = vec![0xa5; available as usize];
            if available >= width {
                expected[..width as usize].fill(0);
            }
            if ok {
                expected[width as usize..2 * width as usize]
                    .copy_from_slice(&1u64.to_le_bytes()[..width as usize]);
            }
            assert_eq!(
                p.space.bytes(io, available as usize).unwrap(),
                expected,
                "{arch}/{available}"
            );
        }
    }
}

pub(super) fn arguments(p: &Proc, thread: &mut Thread, args: &[u64]) {
    let sp = thread.cpu.sp();
    thread.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in args.iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, *value as u32)
                    .unwrap();
            }
            thread.cpu.set_gpr(0, 0x33);
        }
        WinArch::X64 => {
            thread.cpu.set_gpr(0, 0x33);
            thread.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.iter().enumerate() {
                if index < 4 {
                    thread.cpu.set_gpr([10, 2, 8, 9][index], *value);
                } else {
                    p.space.w64(sp + 8 + index as u64 * 8, *value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.iter().enumerate() {
                if index < 8 {
                    thread.cpu.set_gpr(index, *value);
                } else {
                    p.space.w64(sp + (index as u64 - 8) * 8, *value).unwrap();
                }
            }
        }
    }
}

#[test]
fn native_file_open_mapped_file_grant_and_iosb_all_abis() {
    use crate::user::windows::objects::Object;
    use std::io::Read;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let output = h.base + 1;
        let io = h.base + PAGE_SIZE;
        assert_eq!(h.open(output, io), STATUS_SUCCESS, "{arch}");
        let p = h.process.state();
        let width = arch.ptr_size();
        let handle = p.space.ptr(output, width).unwrap();
        assert_eq!(p.objects.access(handle), Some(0x100021));
        let Some(Object::File(file)) = p.objects.get(handle) else {
            panic!("native open returned no owned File");
        };
        assert_eq!(file.access, 0x100021);
        assert_eq!(file.share, 5);
        assert!(!file.overlapped);
        let mut host = file
            .host
            .as_ref()
            .expect("retained host file")
            .try_clone()
            .unwrap();
        let mut bytes = [0; 7];
        host.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"fixture");
        assert_eq!(p.space.ptr(io, width).unwrap(), 0);
        assert_eq!(p.space.ptr(io + width, width).unwrap(), 1);
        assert_eq!(p.space.u8(h.base).unwrap(), 0xa5);
        assert_eq!(p.space.u8(output + width).unwrap(), 0xa5);
        assert_eq!(p.space.u8(io + 2 * width).unwrap(), 0xa5);
    }
}

#[test]
fn native_file_open_failed_lookup_updates_only_wow_handle_slot() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        h.name("\\??\\C:\\missing.bin");
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let count = h.process.state().objects.iter().count();
        assert_eq!(h.open(output, io), STATUS_OBJECT_NAME_NOT_FOUND, "{arch}");
        let p = h.process.state();
        let width = arch.ptr_size();
        assert_eq!(
            p.space.ptr(output, width).unwrap(),
            if arch == WinArch::X86 {
                0
            } else {
                0xa5a5_a5a5_a5a5_a5a5
            }
        );
        assert_eq!(
            p.space.bytes(io, (width * 2) as usize).unwrap(),
            vec![0xa5; (width * 2) as usize]
        );
        assert_eq!(p.objects.iter().count(), count);
    }
}

#[test]
fn native_file_open_late_iosb_fault_retains_native_and_retires_wow_handle() {
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let output = h.base;
        let width = arch.ptr_size();
        let unavailable = h.base + 4 * PAGE_SIZE;
        let available = width * 2 - 1;
        let io = unavailable - available;
        h.process
            .state_mut()
            .vm
            .protect(unavailable, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let count = h.process.state().objects.iter().count();
        assert_eq!(h.open(output, io), STATUS_ACCESS_VIOLATION, "{arch}");
        let p = h.process.state();
        let handle = p.space.ptr(output, width).unwrap();
        assert_ne!(handle, 0);
        assert_eq!(p.space.ptr(io, width).unwrap(), 0);
        assert_eq!(
            p.space.bytes(io + width, (width - 1) as usize).unwrap(),
            vec![0xa5; (width - 1) as usize]
        );
        if arch == WinArch::X86 {
            assert!(p.objects.get(handle).is_none());
            assert_eq!(p.objects.iter().count(), count);
        } else {
            assert!(matches!(p.objects.get(handle), Some(Object::File(_))));
            assert_eq!(p.objects.iter().count(), count + 1);
        }
    }
}

#[test]
fn native_file_open_retained_directory_resolves_children_after_rename_and_replacement() {
    use crate::user::windows::objects::Object;
    use std::io::Read;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let original = h.directory.0.join("parent");
        let renamed = h.directory.0.join("renamed");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("child.dat"), b"retained").unwrap();
        h.name("\\??\\C:\\parent");
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        assert_eq!(
            h.open_with(output, io, 0x100001, 7, 0x21),
            STATUS_SUCCESS,
            "{arch}"
        );
        let root = h
            .process
            .state()
            .space
            .ptr(output, arch.ptr_size())
            .unwrap();
        std::fs::rename(&original, &renamed).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("child.dat"), b"replaced").unwrap();
        h.name("CHILD.DAT");
        h.process
            .state()
            .space
            .wptr(h.attrs() + arch.ptr_size(), arch.ptr_size(), root)
            .unwrap();
        assert_eq!(
            h.open_with(output, io, 0x100001, 7, 0x60),
            STATUS_SUCCESS,
            "{arch}"
        );
        let p = h.process.state();
        let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
        let Some(Object::File(file)) = p.objects.get(handle) else {
            panic!("retained child file");
        };
        let mut actual = Vec::new();
        file.host
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, b"retained", "{arch}");
        let attrs = h.attrs();
        assert_eq!(
            h.invoke_api("NtQueryFullAttributesFile", &[attrs, output]),
            STATUS_SUCCESS,
            "{arch}/retained child attributes"
        );
        assert_eq!(
            h.process.state().space.u64(output + 40).unwrap(),
            8,
            "{arch}/retained child size"
        );
        for (name, expected) in [
            ("missing.dat", 0xc0000034),
            ("missing-parent\\child.dat", 0xc000003a),
        ] {
            h.name(name);
            h.process
                .state()
                .space
                .wptr(h.attrs() + arch.ptr_size(), arch.ptr_size(), root)
                .unwrap();
            assert_eq!(
                h.open_with(output, io, 0x100001, 7, 0x60),
                expected,
                "{arch}/{name}/open"
            );
            assert_eq!(
                h.invoke_api("NtQueryFullAttributesFile", &[h.attrs(), output]),
                expected,
                "{arch}/{name}/attributes"
            );
        }
    }
}
