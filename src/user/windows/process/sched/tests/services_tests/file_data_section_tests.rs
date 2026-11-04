//! File-backed non-image sections through the actual native-service dispatcher.
use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::objects::FileObj;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[path = "file_data_section_tests/coherence.rs"]
mod coherence;
#[path = "file_data_section_tests/details.rs"]
mod details;
#[path = "file_data_section_tests/post_copy.rs"]
mod post_copy;
#[path = "file_data_section_tests/query.rs"]
mod query;
#[path = "file_data_section_tests/scalar.rs"]
mod scalar;
#[path = "file_data_section_tests/sharing.rs"]
mod sharing;
#[path = "file_data_section_tests/transitions.rs"]
mod transitions;

struct FileCase {
    writer: Option<File>,
    path: PathBuf,
    lifetime: Arc<FileLifetime>,
    deleted: bool,
    share: u32,
}
impl FileCase {
    fn new(size: u64) -> Self {
        Self::with_share(size, 7)
    }
    fn with_share(size: u64, share: u32) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let (path, mut writer) = loop {
            let path = std::env::temp_dir().join(format!(
                "rax-data-section-{}-{}.bin",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.access_mode(0x001F01FF).share_mode(share);
            }
            match options.open(&path) {
                Ok(file) => break (path, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("private section file: {error}"),
            }
        };
        writer.set_len(size).unwrap();
        if size != 0 {
            writer.write_all(&[0x11]).unwrap();
        }
        let identity =
            FileIdentity::of_open(&path, Some(&writer), &writer.metadata().unwrap()).unwrap();
        Self {
            writer: Some(writer),
            path,
            lifetime: Arc::new(FileLifetime::new(identity)),
            deleted: false,
            share,
        }
    }
    fn insert(&self, p: &mut Proc, grant: u32) -> u64 {
        let id = p.objects.create(Object::File(FileObj {
            host: Some(self.writer.as_ref().unwrap().try_clone().unwrap()),
            host_path: self.path.clone(),
            path: "\\??\\C:\\owned-data.bin".into(),
            access: 0x001F01FF,
            share: self.share,
            lifetime: self.lifetime.clone(),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }));
        p.objects.open_access(id, false, grant).unwrap().into()
    }
    fn write(&mut self, at: u64, value: u8) {
        let file = self.writer.as_mut().unwrap();
        file.seek(SeekFrom::Start(at)).unwrap();
        file.write_all(&[value]).unwrap();
    }
    fn read(&mut self, at: u64) -> u8 {
        let file = self.writer.as_mut().unwrap();
        file.seek(SeekFrom::Start(at)).unwrap();
        let mut value = [0];
        file.read_exact(&mut value).unwrap();
        value[0]
    }
}
impl Drop for FileCase {
    fn drop(&mut self) {
        drop(self.writer.take());
        if !self.deleted {
            std::fs::remove_file(&self.path).unwrap();
        }
    }
}

fn service(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, SERVICE)));
    call(p, t, args)
}
fn create(p: &mut Proc, t: &mut Thread, b: u64, file: u64, protection: u32) -> u64 {
    assert_eq!(
        service(
            p,
            t,
            "NtCreateSection",
            &[b, 0xF001F, 0, 0, protection.into(), 0x08000000, file]
        ),
        0
    );
    get(p, b)
}
fn map(p: &mut Proc, t: &mut Thread, b: u64, section: u64, base: u64, protection: u32) -> u32 {
    ptr(p, b, base);
    ptr(p, b + 16, 0);
    service(
        p,
        t,
        "NtMapViewOfSection",
        &[
            section,
            p.arch.ptr(u64::MAX),
            b,
            0,
            0,
            0,
            b + 16,
            2,
            0,
            protection.into(),
        ],
    )
}

#[test]
fn native_file_data_sections_share_live_file_bytes_and_copy_individual_views_all_abis() {
    for arch in WinArch::ALL {
        for section_page in [2u32, 4, 8] {
            for view_page in [2u32, 4, 8] {
                let mut file = FileCase::new(1);
                let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
                let p = process.state_mut();
                let b = scratch(p);
                let baseline = p.objects.handle_count();
                let handle = file.insert(p, 0x001F01FF);
                let a = create(p, &mut thread, b, handle, section_page);
                let other = create(p, &mut thread, b, handle, section_page);
                let Object::FileSection(section) = p.objects.get(a).unwrap() else {
                    panic!("typed file Section");
                };
                assert_eq!(section.size, 1);
                let weak = Arc::downgrade(section);
                let mut views = [None; 4];
                for (i, view) in views.iter_mut().enumerate() {
                    let page = if i == 3 { 8 } else { view_page };
                    let address = 0x50000000 + i as u64 * 0x10000;
                    let status = map(
                        p,
                        &mut thread,
                        b,
                        if i == 2 { other } else { a },
                        address,
                        page,
                    );
                    let expected = if page == 4 && section_page != 4 {
                        STATUS_SECTION_PROTECTION
                    } else {
                        0
                    };
                    assert_eq!(
                        status, expected,
                        "{arch} section={section_page} view={page}"
                    );
                    if status == 0 {
                        assert_eq!((get(p, b), get(p, b + 16)), (address, 4096));
                        assert_eq!(p.space.u8(address).unwrap(), 0x11);
                        *view = Some(address);
                    }
                }
                file.write(0, 0x22);
                for address in views.iter().flatten() {
                    assert_eq!(p.space.u8(*address).unwrap(), 0x22);
                }
                if let Some(address) = views[0] {
                    let written = p.space.w8(address, 0x33);
                    assert_eq!(written.is_ok(), view_page != 2);
                    assert_eq!(file.read(0), if view_page == 4 { 0x33 } else { 0x22 });
                    if view_page == 8 {
                        assert_eq!(p.space.u8(views[1].unwrap()).unwrap(), 0x22);
                    }
                }
                p.space.w8(views[3].unwrap(), 0x44).unwrap();
                file.write(0, 0x55);
                for (i, address) in views.iter().enumerate() {
                    if let Some(address) = address {
                        assert_eq!(
                            p.space.u8(*address).unwrap(),
                            if i == 3 {
                                0x44
                            } else if i == 0 && view_page == 8 {
                                0x33
                            } else {
                                0x55
                            }
                        );
                    }
                }
                p.objects.close(handle).unwrap();
                p.objects.close(a).unwrap();
                p.objects.close(other).unwrap();
                assert_eq!(p.objects.handle_count(), baseline);
                assert!(weak.upgrade().is_some());
                for address in views.into_iter().flatten() {
                    assert_eq!(p.vm.query(address).unwrap().kind, mem::MAPPED);
                    assert_eq!(
                        p.vm.free(address, 0, mem::RELEASE),
                        Err(crate::user::windows::memory::VmError::CannotDeleteSection)
                    );
                    assert_eq!(
                        service(
                            p,
                            &mut thread,
                            "NtUnmapViewOfSection",
                            &[arch.ptr(u64::MAX), address]
                        ),
                        0
                    );
                }
                assert!(weak.upgrade().is_none());
                assert_eq!(p.space.attached_extents(), 0);
            }
        }
    }
}

#[test]
fn native_file_data_sections_extend_only_shared_writable_files_and_preserve_the_cursor() {
    for arch in WinArch::ALL {
        for protection in [2u32, 4, 8] {
            let mut file = FileCase::new(1);
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let handle = file.insert(p, 0x001F01FF);
            file.writer
                .as_mut()
                .unwrap()
                .seek(SeekFrom::Start(7))
                .unwrap();
            p.space.w64(b + 64, 65537).unwrap();
            let status = service(
                p,
                &mut thread,
                "NtCreateSection",
                &[b, 0xF001F, 0, b + 64, protection.into(), 0x04000000, handle],
            );
            assert_eq!(
                status,
                if protection == 4 {
                    0
                } else {
                    STATUS_SECTION_TOO_BIG
                }
            );
            assert_eq!(file.writer.as_mut().unwrap().stream_position().unwrap(), 7);
            assert_eq!(
                file.writer.as_ref().unwrap().metadata().unwrap().len(),
                if protection == 4 { 65537 } else { 1 }
            );
            if status == 0 {
                let section = get(p, b);
                assert_eq!(map(p, &mut thread, b, section, 0x50000000, 4), 0);
                assert_eq!(get(p, b + 16), 69632);
                assert_eq!(p.space.u8(0x50010000).unwrap(), 0);
                p.space.w8(0x50010000, 0x66).unwrap();
                assert_eq!(file.read(65536), 0x66);
            }
        }
    }
}

#[test]
fn native_file_data_view_protection_and_commitment_follow_initial_view_rights() {
    for arch in WinArch::ALL {
        let mut file = FileCase::new(8192);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handle = file.insert(p, 0x001F01FF);
        let section = create(p, &mut thread, b, handle, 4);
        assert_eq!(map(p, &mut thread, b, section, 0x50000000, 2), 0);
        assert_eq!(
            p.vm.protect(0x50000000, 4096, 4),
            Err(crate::user::windows::memory::VmError::SectionProtection)
        );
        p.vm.protect(0x50000000, 4096, 8).unwrap();
        p.space.w8(0x50000000, 0x33).unwrap();
        assert_eq!(file.read(0), 0x11);
        assert_eq!(p.vm.allocation_region(0x50000000).unwrap().commit, 4096);
        p.vm.protect(0x50000000, 4096, 2).unwrap();
        assert_eq!(p.vm.allocation_region(0x50000000).unwrap().commit, 4096);
        assert_eq!(map(p, &mut thread, b, section, 0x50100000, 4), 0);
        p.vm.protect(0x50100000, 8192, 8).unwrap();
        p.space.w8(0x50100000, 0x44).unwrap();
        p.vm.protect(0x50100000, 8192, 4).unwrap();
        p.space.w8(0x50100000, 0x55).unwrap();
        p.space.w8(0x50101000, 0x66).unwrap();
        assert_eq!(file.read(0), 0x11);
        assert_eq!(file.read(4096), 0x66);
        assert_eq!(p.vm.allocation_region(0x50100000).unwrap().commit, 4096);
    }
}

#[test]
fn native_file_data_initial_copy_store_preserves_the_shared_cursor_and_partial_file_tail() {
    for arch in WinArch::ALL {
        let mut file = FileCase::new(1);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handle = file.insert(p, 0x001F01FF);
        file.writer
            .as_mut()
            .unwrap()
            .seek(SeekFrom::Start(7))
            .unwrap();
        let section = create(p, &mut thread, b, handle, 8);
        assert_eq!(map(p, &mut thread, b, section, 0x50000000, 8), 0);
        // A first store must read the live source positionally, rather than
        // attach then accidentally modify a shared partial file page.
        p.space.w8(0x50000FFF, 0x77).unwrap();
        assert_eq!(file.writer.as_mut().unwrap().stream_position().unwrap(), 7);
        assert_eq!(file.writer.as_ref().unwrap().metadata().unwrap().len(), 1);
        assert_eq!(p.space.u8(0x50000000).unwrap(), 0x11);
        assert_eq!(p.space.u8(0x50000001).unwrap(), 0);
        assert_eq!(p.space.u8(0x50000FFF).unwrap(), 0x77);
        assert_eq!(file.read(0), 0x11);
    }
}

#[test]
fn native_file_data_execute_only_backing_is_explicitly_unavailable_before_publication() {
    for arch in WinArch::ALL {
        let file = FileCase::new(4096);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handle = file.insert(p, 0x20);
        let Some(Object::File(backing)) = p.objects.get_mut(handle) else {
            panic!("file")
        };
        backing.access = 0x20;
        ptr(p, b, 0xA5A5A5A5);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let result = invoke(
            p,
            &mut thread,
            &[b, 0xF001F, 0, 0, 0x10, 0x08000000, handle],
        );
        assert!(
            matches!(result,Outcome::Fail(ref message)if message.contains("readable admitted file resource")),
            "{result:?}"
        );
        assert_eq!(get(p, b), 0xA5A5A5A5);
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

#[test]
fn native_file_data_view_accepts_the_free_native_minimum_base() {
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::VirtualMemory;
    use crate::user::windows::object_namespace::FileSection;
    let file = FileCase::new(65537);
    let section = FileSection::create(
        file.writer.as_ref().unwrap(),
        file.lifetime.clone(),
        0,
        2,
        None,
    )
    .unwrap();
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 8 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    let mut vm = VirtualMemory::new(space, 65536, 1 << 32);
    vm.map_file_section(section, 65536, 0, 69632, 2).unwrap();
    assert_eq!(vm.query(65536).unwrap().allocation_base, 65536);
    assert_eq!(vm.query(65536).unwrap().size, 69632);
}

#[test]
fn native_file_data_guest_load_store_reload_keeps_each_copied_view_private_all_abis() {
    use crate::user::windows::arch::{CpuStop, WinCpu};
    for arch in WinArch::ALL {
        let mut file = FileCase::new(8192);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handle = file.insert(p, 0x001F01FF);
        let section = create(p, &mut thread, b, handle, 2);
        let data = 0x50000000;
        assert_eq!(map(p, &mut thread, b, section, data, 8), 0);
        let code =
            p.vm.allocate(
                None,
                4096,
                mem::RESERVE | mem::COMMIT,
                prot::EXECUTE_READWRITE,
            )
            .unwrap()
            .0;
        let program = if arch == WinArch::Arm64 {
            // LDRB W0,[X1]; MOVZ W2,#0x33; STRB W2,[X1]; LDRB W3,[X1]; BRK #0.
            [
                0x39400020u32,
                0x52800662,
                0x39000022,
                0x39400023,
                0xD4200000,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
        } else {
            // MOV AL,[RDI/EDI]; MOV BL,AL; MOV byte [RDI/EDI],0x33;
            // MOV AL,[RDI/EDI]; INT3.
            vec![0x8A, 0x07, 0x88, 0xC3, 0xC6, 0x07, 0x33, 0x8A, 0x07, 0xCC]
        };
        p.space.wr(code, &program).unwrap();
        let mut cpu = WinCpu::new(arch, &p.space);
        cpu.set_pc(code);
        cpu.set_gpr(if arch == WinArch::Arm64 { 1 } else { 7 }, data);
        let stop = cpu.run(16);
        match (arch, stop) {
            (WinArch::Arm64, CpuStop::Brk { imm: 0, .. }) => {
                assert_eq!(cpu.gpr(0), 0x11);
                assert_eq!(cpu.gpr(3), 0x33);
            }
            (WinArch::X86 | WinArch::X64, CpuStop::X86Event(event)) => {
                assert_eq!(event.vector, 3);
                assert_eq!(cpu.gpr(3) & 0xFF, 0x11);
                assert_eq!(cpu.gpr(0) & 0xFF, 0x33);
            }
            other => panic!("{arch}: guest copy instruction path {other:?}"),
        }
        assert_eq!(file.read(0), 0x11);
        assert_eq!(p.vm.query(data).unwrap().protect, prot::READWRITE);
        assert_eq!(p.vm.query(data).unwrap().size, 4096);
        assert_eq!(p.vm.query(data + 4096).unwrap().protect, prot::WRITECOPY);
        file.write(0, 0x55);
        assert_eq!(p.space.u8(data).unwrap(), 0x33);
    }
}
