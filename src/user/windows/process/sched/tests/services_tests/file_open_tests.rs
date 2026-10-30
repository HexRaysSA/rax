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

struct Directory(PathBuf);

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

struct Harness {
    process: WindowsProcess,
    thread: Thread,
    base: u64,
    directory: Directory,
}

impl Harness {
    fn new(arch: WinArch) -> Self {
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

    fn attrs(&self) -> u64 {
        self.base + 2 * PAGE_SIZE
    }

    fn name(&mut self, name: &str) {
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

    fn invoke_api(&mut self, name: &str, args: &[u64]) -> u32 {
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

fn selection(h: &mut Harness) -> PathBuf {
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

fn arguments(p: &Proc, thread: &mut Thread, args: &[u64]) {
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
                thread.cpu.set_gpr(index, *value);
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
