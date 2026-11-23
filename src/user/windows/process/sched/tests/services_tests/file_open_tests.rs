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
        std::fs::write(directory.join("cmd.exe"), b"installed executable").unwrap();
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
            "\\??\\C:\\cmd.exe",
        ] {
            h.name(path);
            assert_eq!(h.open(output, io), STATUS_ACCESS_DENIED, "{arch}/{path}");
        }
        h.name("\\??\\C:\\Windows\\System32\\CMD.EXE");
        assert_eq!(h.open(output, io), STATUS_SUCCESS);
        let p = h.process.state_mut();
        let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
        assert!(p.objects.runtime_library(handle));
        p.objects.close(handle).unwrap();
        assert_eq!(
            h.open_with(output, io, 0x100002, 7, 0x60),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            std::fs::read(directory.join("fixture.dll")).unwrap(),
            b"native"
        );
        assert!(!h.process.state().cfg.host_filesystem);
    }
}

#[test]
fn native_file_open_closed_directories_only_resolve_selected_runtime_files() {
    use crate::user::windows::fs::FileIdentity;
    use crate::user::windows::nt::status::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_INVALID};
    use crate::user::windows::objects::Object;

    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let installed = selection(&mut h);
        std::fs::write(installed.join("cmd.exe"), b"selected image").unwrap();
        std::fs::write(installed.join("unselected.exe"), b"foreign image").unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;

        for (name, access, share, options, relative) in [
            (r"\??\C:\Windows\System32\", 0x100020, 3, 0x21, "cmd.exe"),
            (r"\??\C:\Windows\System32\", 0x100001, 7, 0x4021, "cmd.exe"),
            (r"\??\C:\", 0x100000, 3, 0x4021, r"Windows\System32\cmd.exe"),
        ] {
            h.name(name);
            assert_eq!(
                h.open_with(output, io, access | 2, share, options),
                STATUS_ACCESS_DENIED
            );
            assert_eq!(
                h.open_with(output, io, access, share, options),
                STATUS_SUCCESS
            );
            let width = arch.ptr_size();
            let p = h.process.state_mut();
            let directory = p.space.ptr(output, width).unwrap();
            assert_eq!(p.space.ptr(io + width, width).unwrap(), 1);
            assert_eq!(p.objects.access(directory), Some(access));
            assert!(matches!(
                p.objects.get(directory),
                Some(Object::File(file)) if file.directory && file.host.is_none()
                    && file.host_path.as_os_str().is_empty()
                    && matches!(&file.lifetime.identity, FileIdentity::GuestDirectory(_))
            ));
            let root = h.attrs() + width;
            for (relative, expected) in [
                (relative, STATUS_SUCCESS),
                (r"..\cmd.exe", STATUS_OBJECT_NAME_INVALID),
                ("unselected.exe", STATUS_ACCESS_DENIED),
                ("fixture.bin", STATUS_ACCESS_DENIED),
            ] {
                h.name(relative);
                h.process
                    .state()
                    .space
                    .wptr(root, width, directory)
                    .unwrap();
                assert_eq!(h.open(output, io), expected, "{arch}/{name}/{relative}");
                if expected == STATUS_SUCCESS {
                    let p = h.process.state_mut();
                    let child = p.space.ptr(output, width).unwrap();
                    assert!(p.objects.runtime_library(child));
                    p.objects.close(child).unwrap();
                }
            }
            h.process.state_mut().objects.close(directory).unwrap();
        }
    }
}

#[test]
fn native_file_open_closed_directory_names_and_entries_are_guest_local() {
    use crate::user::windows::nt::status::{STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE};

    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let installed = selection(&mut h);
        std::fs::write(installed.join("CMD.exe"), b"selected image").unwrap();
        std::fs::write(installed.join("foreign.exe"), b"unselected image").unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let width = arch.ptr_size();
        for (full, relative) in [
            (r"\??\C:\", r"\"),
            (r"\??\C:\Windows\System32\", r"\Windows\System32"),
        ] {
            h.name(full);
            assert_eq!(h.open_with(output, io, 0x100001, 7, 0x4021), STATUS_SUCCESS);
            let directory = h.process.state().space.ptr(output, width).unwrap();
            assert_eq!(
                h.invoke_api("NtQueryInformationFile", &[directory, io, output, 256, 9]),
                STATUS_SUCCESS
            );
            let space = &h.process.state().space;
            let length = space.u32(output).unwrap();
            assert_eq!(length as usize, relative.encode_utf16().count() * 2);
            let name = space.bytes(output + 4, length as usize).unwrap();
            let text: Vec<u16> = name
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            assert_eq!(
                String::from_utf16_lossy(&text).to_ascii_lowercase(),
                relative.to_ascii_lowercase()
            );
            if relative == r"\" {
                h.process.state_mut().objects.close(directory).unwrap();
                continue;
            }

            let query_name = h.attrs() + 64;
            h.name("foreign.exe");
            assert_eq!(
                h.invoke_api(
                    "NtQueryDirectoryFileEx",
                    &[directory, 0, 0, 0, io, output, 256, 12, 1, query_name]
                ),
                STATUS_NO_SUCH_FILE
            );
            h.name("cMd.EXE");
            let args = [directory, 0, 0, 0, io, output, 256, 12, 1, query_name];
            assert_eq!(
                h.invoke_api("NtQueryDirectoryFileEx", &args),
                STATUS_SUCCESS
            );
            let space = &h.process.state().space;
            assert_eq!(space.u32(output + 8).unwrap(), 14);
            assert_eq!(
                space.bytes(output + 12, 14).unwrap(),
                b"c\0m\0d\0.\0e\0x\0e\0"
            );
            let second = [directory, 0, 0, 0, io, output, 256, 12, 0, 0];
            assert_eq!(
                h.invoke_api("NtQueryDirectoryFileEx", &second),
                STATUS_NO_MORE_FILES
            );
            h.process.state_mut().objects.close(directory).unwrap();
        }
    }
}

#[test]
fn native_file_open_closed_system_drive_lists_only_guest_directories() {
    use crate::user::windows::nt::status::{STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES};

    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let installed = selection(&mut h);
        std::fs::create_dir(installed.join("foreign")).unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let attrs = h.attrs();
        let width = arch.ptr_size();
        h.name(r"\??\C:\");
        assert_eq!(h.open_with(output, io, 0x100001, 7, 0x4021), STATUS_SUCCESS);
        let drive = h.process.state().space.ptr(output, width).unwrap();

        let scan = [drive, 0, 0, 0, io, output, 256, 3, 0, 0];
        assert_eq!(
            h.invoke_api("NtQueryDirectoryFileEx", &scan),
            STATUS_SUCCESS
        );
        let space = &h.process.state().space;
        assert_eq!(space.u32(output).unwrap(), 0);
        assert_eq!(space.u32(output + 56).unwrap(), 0x10);
        assert_eq!(space.u32(output + 60).unwrap(), 14);
        assert_eq!(
            space.bytes(output + 94, 14).unwrap(),
            b"W\0i\0n\0d\0o\0w\0s\0"
        );
        assert_eq!(
            h.invoke_api("NtQueryDirectoryFileEx", &scan),
            STATUS_NO_MORE_FILES
        );

        h.name("wINDOWS");
        h.process
            .state()
            .space
            .wptr(attrs + width, width, drive)
            .unwrap();
        assert_eq!(
            h.invoke_api("NtQueryAttributesFile", &[attrs, output]),
            STATUS_SUCCESS
        );
        assert_eq!(h.open_with(output, io, 0x100001, 7, 0x4021), STATUS_SUCCESS);
        let windows = h.process.state().space.ptr(output, width).unwrap();
        let scan = [windows, 0, 0, 0, io, output, 256, 12, 0, 0];
        assert_eq!(
            h.invoke_api("NtQueryDirectoryFileEx", &scan),
            STATUS_SUCCESS
        );
        let space = &h.process.state().space;
        let utf16 = |name: &str| {
            name.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let first = if arch == WinArch::X86 {
            "SysWOW64"
        } else {
            "System32"
        };
        assert_eq!(space.bytes(output + 12, 16).unwrap(), utf16(first));
        let next = u64::from(space.u32(output).unwrap());
        if arch == WinArch::X86 {
            assert_ne!(next, 0);
            assert_eq!(
                space.bytes(output + next + 12, 16).unwrap(),
                utf16("System32")
            );
            assert_eq!(space.u32(output + next).unwrap(), 0);
        } else {
            assert_eq!(next, 0);
        }

        h.name(r"System32\foreign");
        h.process
            .state()
            .space
            .wptr(attrs + width, width, windows)
            .unwrap();
        assert_eq!(
            h.open_with(output, io, 0x100001, 7, 0x4021),
            STATUS_ACCESS_DENIED
        );
        h.process.state_mut().objects.close(windows).unwrap();
        h.process.state_mut().objects.close(drive).unwrap();
    }
}

#[test]
fn native_file_open_closed_directory_metadata_and_volume_are_guest_local() {
    use crate::user::windows::nt::status::{STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW};

    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let installed = selection(&mut h);
        std::fs::create_dir(installed.join("unselected")).unwrap();
        let output = h.base;
        let io = h.base + PAGE_SIZE;
        let attrs = h.attrs();
        let width = arch.ptr_size();

        h.name(r"\??\C:\Windows\System32\unselected\");
        assert_eq!(
            h.invoke_api("NtQueryAttributesFile", &[attrs, output]),
            STATUS_ACCESS_DENIED
        );
        for name in [r"\??\C:\", r"\??\C:\Windows\System32\"] {
            h.name(name);
            for (service, attribute_offset) in [
                ("NtQueryAttributesFile", 32),
                ("NtQueryFullAttributesFile", 48),
            ] {
                assert_eq!(
                    h.invoke_api(service, &[attrs, output]),
                    STATUS_SUCCESS,
                    "{arch}/{name}/{service}"
                );
                let space = &h.process.state().space;
                assert_eq!(
                    space.bytes(output, attribute_offset as usize).unwrap(),
                    vec![0; attribute_offset as usize]
                );
                assert_eq!(space.u32(output + attribute_offset).unwrap(), 0x10);
            }
            assert_eq!(h.open_with(output, io, 0x100000, 3, 0x4021), STATUS_SUCCESS);
            let handle = h.process.state().space.ptr(output, width).unwrap();
            for (class, length, status, data) in [
                (1, 24, STATUS_SUCCESS, &[0; 18][..]),
                (
                    5,
                    16,
                    STATUS_BUFFER_OVERFLOW,
                    b"\x06\0\x08\0\xff\0\0\0\x06\0\0\0R\0A\0",
                ),
                (
                    5,
                    24,
                    STATUS_SUCCESS,
                    b"\x06\0\x08\0\xff\0\0\0\x06\0\0\0R\0A\0X\0",
                ),
            ] {
                assert_eq!(
                    h.invoke_api(
                        "NtQueryVolumeInformationFile",
                        &[handle, io, output, length, class]
                    ),
                    status,
                    "{arch}/{name}/{class}"
                );
                let space = &h.process.state().space;
                assert_eq!(space.bytes(output, data.len()).unwrap(), data);
                assert_eq!(space.ptr(io + width, width).unwrap(), data.len() as u64);
            }
            h.process.state_mut().objects.close(handle).unwrap();
        }
    }
}

#[test]
fn native_file_open_server_2022_bcrypt_keeps_the_captured_device_guest_owned() {
    use crate::user::windows::object_namespace::security_device::SecurityDevice;
    use crate::user::windows::objects::Object;

    let arch = WinArch::X64;
    let mut h = Harness::new(arch);
    let device = SecurityDevice {
        kernel: (10, 0, 20348),
        revision: 1,
        native_machine: arch.machine(),
        device_type: 0x39,
        characteristics: 0x100,
    };
    let width = arch.ptr_size();
    let (output, io, attrs) = (h.base, h.base + 64, h.attrs());
    let p = h.process.state_mut();
    Arc::make_mut(&mut p.cfg).host_filesystem = false;
    p.object_namespace.native_machine = Some(arch.machine());
    p.object_namespace.select_security_device(device).unwrap();

    h.name(r"\Device\KsecDD");
    h.process.state().space.w32(attrs + 3 * width, 0).unwrap();
    assert_eq!(h.open_with(output, io, 0x100003, 7, 0x20), STATUS_SUCCESS);
    let p = h.process.state();
    let handle = p.space.ptr(output, width).unwrap();
    assert!(matches!(p.objects.get(handle), Some(Object::SecurityFile(value)) if *value == device));
    assert_eq!(p.objects.access(handle), Some(0x100003));
    assert_eq!(p.space.ptr(io + width, width).unwrap(), 0);
    assert_eq!(
        h.invoke_api("NtQueryVolumeInformationFile", &[handle, io, output, 8, 4]),
        STATUS_SUCCESS
    );
    let p = h.process.state();
    assert_eq!(p.space.u32(output).unwrap(), device.device_type);
    assert_eq!(p.space.u32(output + 4).unwrap(), device.characteristics);
    let observation: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/bcrypt-sha256-arm64.json"
    )))
    .unwrap();
    let hex = observation["watch"]["input_prefix"].as_str().unwrap();
    let request: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect();
    assert_eq!(request.len(), 96);
    assert_eq!(
        h.invoke_api("NtCreateEvent", &[output, 0x1f0003, 0, 1, 0]),
        STATUS_SUCCESS
    );
    let p = h.process.state();
    let event = p.space.u64(output).unwrap();
    let event_id = p.objects.id(event).unwrap();
    let input = h.base + 256;
    p.space.wr(input, &request).unwrap();
    p.space.w64(input + 96, event).unwrap();
    p.space.wr(output, &[0xa5; 8]).unwrap();
    let args = [handle, 0, 0, 0, io, 0x390400, input, 104, output, 8];
    assert_eq!(h.invoke_api("NtDeviceIoControlFile", &args), STATUS_SUCCESS);
    let p = h.process.state();
    assert_eq!(p.space.bytes(io, 16).unwrap(), [0; 16]);
    assert_eq!(p.space.bytes(output, 8).unwrap(), [0xa5; 8]);
    assert_eq!(
        p.objects
            .file_state(handle)
            .unwrap()
            .security_provider_event,
        Some(event_id)
    );
    assert_eq!(h.invoke_api("NtClose", &[event]), STATUS_SUCCESS);
    assert!(h.process.state().objects.obj(event_id).is_some());
    assert_eq!(h.invoke_api("NtClose", &[handle]), STATUS_SUCCESS);
    assert!(h.process.state().objects.obj(event_id).is_none());

    for (name, access) in [
        (r"\Device\KsecDD\child", 0x100003),
        (r"\Device\KsecDD", 0x100001),
    ] {
        h.name(name);
        let p = h.process.state_mut();
        p.space.w32(attrs + 3 * width, 0).unwrap();
        let module = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((module, table(arch, "NtOpenFile", 0x33)));
        let count = p.objects.handle_count();
        arguments(p, &mut h.thread, &[output, access, attrs, io, 7, 0x20]);
        assert!(
            matches!(handle_stop(p, &mut h.thread, stop(arch, 0x33)), Outcome::Fail(reason)
            if reason.contains("Server 2022 security-device open parameters are not selected"))
        );
        assert_eq!(p.objects.handle_count(), count);
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
