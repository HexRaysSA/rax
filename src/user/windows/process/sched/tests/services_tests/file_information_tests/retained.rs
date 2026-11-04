use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::objects::FileObj;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn file_information_retained_cursor_duplicates_independent_opens_and_replacement_all_abis() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for arch in WinArch::ALL {
        let path = std::env::temp_dir().join(format!(
            "rax-file-info-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"retained file query").unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let identity =
            FileIdentity::of_open(&path, Some(&file), &file.metadata().unwrap()).unwrap();
        let lifetime = Arc::new(FileLifetime::new(identity));
        let make = |file| {
            Object::File(FileObj {
                host: Some(file),
                host_path: path.clone(),
                path: "C:\\fixture.bin".into(),
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
        let full = p.objects.open_access(id, false, 0x12019f).unwrap();
        let reduced = p.objects.open_access(id, false, 0x80).unwrap();
        let independent = p.objects.insert(make(std::fs::File::open(&path).unwrap()));
        p.space
            .wr(base, &vec![0xA5; 6 * PAGE_SIZE as usize])
            .unwrap();
        for (h, position) in [(full, 7), (reduced, 7), (independent, 0)] {
            assert_eq!(
                invoke(p, &mut thread, &[u64::from(h), base, base + 64, 8, 14]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u64(base + 64).unwrap(), position);
        }
        p.objects.set_file_mode(id, 0x22);
        for h in [full, reduced] {
            assert_eq!(
                invoke(p, &mut thread, &[u64::from(h), base, base + 64, 4, 16]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), 0x22);
        }
        assert_eq!(
            invoke(
                p,
                &mut thread,
                &[u64::from(independent), base, base + 64, 4, 16]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 64).unwrap(), 0x20);
        assert_eq!(
            invoke(p, &mut thread, &[u64::from(full), base, base + 64, 24, 5]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(base + 72).unwrap(), 19);
        let mut records = std::collections::BTreeMap::new();
        for (class, bytes) in [
            (4, 40),
            (5, 24),
            (6, 8),
            (7, 4),
            (8, 4),
            (14, 8),
            (16, 4),
            (17, 4),
            (34, 56),
            (35, 8),
            (41, 4),
            (43, 4),
            (51, 1),
            (59, 24),
        ] {
            p.space.wr(base, &[0xA5; 128]).unwrap();
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[u64::from(full), base, base + 64, bytes, class]
                ),
                STATUS_SUCCESS,
                "{arch} class{class}"
            );
            assert_eq!(
                p.space
                    .ptr(base + arch.ptr_size(), arch.ptr_size())
                    .unwrap(),
                bytes
            );
            records.insert(class, p.space.bytes(base + 64, bytes as usize).unwrap());
        }
        assert_eq!(&records[&4][..32], &records[&34][..32]);
        assert_eq!(&records[&4][32..36], &records[&35][..4]);
        assert_eq!(&records[&4][32..36], &records[&34][48..52]);
        assert_eq!(&records[&5][..16], &records[&34][32..48]);
        assert_eq!(&records[&6][..8], &records[&59][8..16]);
        assert_eq!(&records[&8], &0x12019fu32.to_le_bytes());
        assert_eq!(&records[&14], &7u64.to_le_bytes());
        assert_eq!(&records[&16], &0x22u32.to_le_bytes());
        assert_eq!(&records[&41], &0u32.to_le_bytes());
        assert_eq!(&records[&43], &2u32.to_le_bytes());
        assert_eq!(&records[&51], &[0]);
        // The retained object remains authoritative after its pathname moves.
        let renamed = path.with_extension("renamed");
        std::fs::rename(&path, &renamed).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            invoke(p, &mut thread, &[u64::from(full), base, base + 64, 24, 5]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(base + 72).unwrap(), 19);
        p.objects.close(u64::from(full)).unwrap();
        p.objects.close(u64::from(reduced)).unwrap();
        p.objects.close(u64::from(independent)).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(renamed).unwrap();
    }
}
