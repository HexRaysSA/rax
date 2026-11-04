//! Real retained cursor and writes, independent opens, rename and replacement.
use super::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn file_state_set_retained_position_controls_real_io_after_rename_and_mode_changes() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for arch in WinArch::ALL {
        let path = std::env::temp_dir().join(format!(
            "rax-file-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let renamed = path.with_extension("retained");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"0123456789abcdef").unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let identity =
            FileIdentity::of_open(&path, Some(&file), &file.metadata().unwrap()).unwrap();
        let lifetime = Arc::new(FileLifetime::new(identity));
        let make = |file| {
            Object::File(FileObj {
                host: Some(file),
                host_path: path.clone(),
                path: "C:\\retained.bin".into(),
                access: 0x12019f,
                share: 7,
                lifetime: lifetime.clone(),
                null: false,
                append: false,
                delete_on_close: false,
                directory: false,
                overlapped: false,
            })
        };
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let id = p.objects.create(make(file));
        let full = u64::from(p.objects.open_access(id, false, 0x12019f).unwrap());
        let reduced = u64::from(p.objects.open_access(id, false, 0x80).unwrap());
        let independent = u64::from(p.objects.insert(make(std::fs::File::open(&path).unwrap())));
        p.space.w64(base + 64, 3).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &[reduced, base, base + 64, 8, 14]),
            STATUS_SUCCESS
        );
        assert_eq!(
            snapshot(p, &mut thread, full, base + 2 * PAGE_SIZE)[0],
            json!([0, "0300000000000000"])
        );
        assert_eq!(
            snapshot(p, &mut thread, independent, base + 2 * PAGE_SIZE)[0],
            json!([0, "0000000000000000"])
        );
        p.space.w32(base + 64, 0x22).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &[reduced, base, base + 64, 4, 16]),
            STATUS_SUCCESS
        );
        p.space.wr(base + 128, b"XY").unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtWriteFile",
                0x18,
                &[full, 0, 0, 0, base, base + 128, 2, 0, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            snapshot(p, &mut thread, full, base + 2 * PAGE_SIZE)[0],
            json!([0, "0500000000000000"])
        );
        std::fs::rename(&path, &renamed).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        p.space.w64(base + 64, 1).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &[reduced, base, base + 64, 8, 14]),
            STATUS_SUCCESS
        );
        let Object::File(file) = p.objects.get_mut(full).unwrap() else {
            panic!("file");
        };
        let mut observed = [0; 4];
        file.host
            .as_mut()
            .unwrap()
            .read_exact(&mut observed)
            .unwrap();
        assert_eq!(&observed, b"12XY");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert_eq!(std::fs::read(&renamed).unwrap(), b"012XY56789abcdef");
        for h in [full, reduced, independent] {
            p.objects.close(h).unwrap();
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(renamed).unwrap();
    }
}

#[test]
fn file_state_set_delete_on_close_is_not_a_query_mode_bit_and_invalid_modes_leave_state() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let mut resource = resource(p, "file.delete-on-close");
        let Object::File(file) = p.objects.get_mut(resource.handle).unwrap() else {
            panic!("file");
        };
        file.delete_on_close = true;
        let id = p.objects.id(resource.handle).unwrap();
        p.objects.set_file_mode(id, 0x1020);
        assert_eq!(
            snapshot(p, &mut thread, resource.handle, base + 2 * PAGE_SIZE)[1],
            json!([0, "20000000"])
        );
        p.space.w32(base + 64, 0x1000).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &[resource.handle, base, base + 64, 4, 16]),
            STATUS_INVALID_PARAMETER
        );
        assert!(
            matches!(p.objects.get(resource.handle), Some(Object::File(file)) if file.delete_on_close)
        );
        assert_eq!(p.objects.file_mode(resource.handle), Some(0x20));
        resource.parent = None;
        release(p, resource);
    }
}
