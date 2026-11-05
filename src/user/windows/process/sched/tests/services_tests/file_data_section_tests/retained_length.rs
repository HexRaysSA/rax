//! A real reduced-rights open must suffice after its pathname is replaced.
use super::super::file_open_tests::Harness;
use super::*;

#[test]
fn native_file_data_sections_use_retained_length_without_attribute_or_sync_rights() {
    const CONTENT: &[u8] = b"original retained file bytes";
    for arch in WinArch::ALL {
        for (access, options) in [(0x0010_0001u32, 0x60u32), (1, 0x40)] {
            for protection in [2u32, 8] {
                let mut h = Harness::new(arch);
                let path = h.directory.0.join("fixture.bin");
                let moved = h.directory.0.join("moved.bin");
                std::fs::write(&path, CONTENT).unwrap();
                let baseline = h.process.state().objects.handle_count();
                assert_eq!(
                    h.invoke_api(
                        "NtOpenFile",
                        &[
                            h.base,
                            access.into(),
                            h.attrs(),
                            h.base + PAGE_SIZE,
                            7,
                            options.into()
                        ],
                    ),
                    STATUS_SUCCESS,
                    "{arch}/{access:#x}/{options:#x}"
                );
                let p = h.process.state();
                let file = p.space.ptr(h.base, arch.ptr_size()).unwrap();
                assert_eq!(p.objects.access(file), Some(access));
                #[cfg(windows)]
                {
                    let Object::File(open) = p.objects.get(file).unwrap() else {
                        panic!("retained file open");
                    };
                    assert_eq!(
                        open.host.as_ref().unwrap().metadata().unwrap_err().kind(),
                        std::io::ErrorKind::PermissionDenied,
                        "the real host handle must lack read-attributes access"
                    );
                }
                std::fs::rename(&path, &moved).unwrap();
                std::fs::write(&path, b"replacement").unwrap();
                assert_eq!(
                    h.invoke_api(
                        "NtCreateSection",
                        &[h.base, 0xF001F, 0, 0, protection.into(), 0x0800_0000, file],
                    ),
                    STATUS_SUCCESS,
                    "{arch}/{access:#x}/{options:#x}/{protection:#x}"
                );
                let p = h.process.state_mut();
                let section = p.space.ptr(h.base, arch.ptr_size()).unwrap();
                let Object::FileSection(data) = p.objects.get(section).unwrap() else {
                    panic!("typed data section");
                };
                assert_eq!(data.size, CONTENT.len() as u64);
                assert_eq!(p.objects.access(file), Some(access));
                drop(p.objects.close(file).unwrap());
                let base = h.base + 4 * PAGE_SIZE;
                let size = h.base + 5 * PAGE_SIZE;
                p.space.wptr(base, arch.ptr_size(), 0).unwrap();
                p.space.wptr(size, arch.ptr_size(), 0).unwrap();
                assert_eq!(
                    h.invoke_api(
                        "NtMapViewOfSection",
                        &[
                            section,
                            arch.ptr(u64::MAX),
                            base,
                            0,
                            0,
                            0,
                            size,
                            2,
                            0,
                            protection.into()
                        ],
                    ),
                    STATUS_SUCCESS
                );
                let p = h.process.state();
                let address = p.space.ptr(base, arch.ptr_size()).unwrap();
                assert_eq!(p.space.bytes(address, CONTENT.len()).unwrap(), CONTENT);
                assert_eq!(
                    h.invoke_api("NtUnmapViewOfSection", &[arch.ptr(u64::MAX), address]),
                    STATUS_SUCCESS
                );
                let p = h.process.state_mut();
                drop(p.objects.close(section).unwrap());
                assert_eq!(p.objects.handle_count(), baseline);
                assert_eq!(p.space.attached_extents(), 0);
                assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
                assert_eq!(std::fs::read(&moved).unwrap(), CONTENT);
            }
        }
    }
}
