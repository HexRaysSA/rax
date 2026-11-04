use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime, FileNameOrigin};
use crate::user::windows::objects::FileObj;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(super) fn fixture_object(path: &Path, asynchronous: bool, access: u32) -> Object {
    let file = FileNameOrigin::metadata_file(path).unwrap();
    let metadata = file.metadata().unwrap();
    let identity = FileIdentity::of_open(path, Some(&file), &metadata).unwrap();
    Object::File(FileObj {
        host: Some(file),
        host_path: path.to_owned(),
        path: "relative-only".into(),
        access,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(identity)),
        null: false,
        append: false,
        delete_on_close: false,
        directory: metadata.is_dir(),
        overlapped: asynchronous,
    })
}

#[test]
fn file_information_names_replay_all_6048_independent_native_queries() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rax-file-name-profiles-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let mut total = 0;
    for arch in WinArch::ALL {
        let text = match arch {
            WinArch::Arm64 => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-name-information/observations-arm64-compiled-29698-v3.json"
            )),
            WinArch::X64 => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-name-information/observations-x64-compiled-29698-v3.json"
            )),
            WinArch::X86 => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-name-information/observations-x86-managed-29698-v2.json"
            )),
        };
        let corpus: Value = serde_json::from_str(text).unwrap();
        let rows = corpus["rows"].as_array().unwrap();
        let mut paths = BTreeMap::new();
        for role in ["file", "directory"] {
            let sample = rows
                .iter()
                .find(|row| {
                    row["kind"] == "query" && row["object"] == role && row["completed"] == 0
                })
                .unwrap();
            let captured = bytes(sample["output_hex"].as_str().unwrap());
            let start = 16 + sample["offset"].as_u64().unwrap() as usize;
            let count = u32::from_le_bytes(captured[start..start + 4].try_into().unwrap()) as usize;
            let units: Vec<u16> = captured[start + 4..start + 4 + count]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
                .collect();
            let name = String::from_utf16(&units).unwrap();
            let path = name
                .split('\\')
                .filter(|part| !part.is_empty())
                .fold(root.clone(), |path, part| path.join(part));
            if role == "directory" {
                std::fs::create_dir_all(&path).unwrap();
            } else {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, b"independent native name fixture").unwrap();
            }
            paths.insert(role, path);
        }
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let mut handles = BTreeMap::new();
        let mut cases = 0;
        for row in rows.iter().filter(|row| row["kind"] == "query") {
            let role = row["object"].as_str().unwrap();
            let asynchronous = row["asynchronous"].as_bool().unwrap();
            let access = row["access"].as_u64().unwrap() as u32;
            let key = (role.to_owned(), asynchronous, access);
            let handle = *handles.entry(key).or_insert_with(|| {
                let id = p
                    .objects
                    .create(fixture_object(&paths[role], asynchronous, access));
                p.objects.set_file_name_origin(
                    id,
                    FileNameOrigin::capture(&root, Vec::new()).map_err(|e| e.to_string()),
                );
                u64::from(p.objects.open_access(id, false, access).unwrap())
            });
            p.space
                .wr(base, &vec![0xa5; 6 * PAGE_SIZE as usize])
                .unwrap();
            let initial = bytes(row["initial_iosb_hex"].as_str().unwrap());
            p.space.wr(base, &initial).unwrap();
            let output = base + 3 * PAGE_SIZE;
            let status = invoke(
                p,
                &mut thread,
                &[
                    handle,
                    base,
                    output + 16 + row["offset"].as_u64().unwrap(),
                    row["length"].as_u64().unwrap(),
                    9,
                ],
            );
            assert_eq!(
                status,
                row["completed"].as_u64().unwrap() as u32,
                "{arch} {role} async={asynchronous} row={row}"
            );
            let expected = bytes(row["iosb_hex"].as_str().unwrap());
            assert_eq!(
                p.space.bytes(base, expected.len()).unwrap(),
                expected,
                "{arch} IOSB {role} async={asynchronous} row={row}"
            );
            let expected = bytes(row["output_hex"].as_str().unwrap());
            assert_eq!(
                p.space.bytes(output, expected.len()).unwrap(),
                expected,
                "{arch} output {role} async={asynchronous} row={row}"
            );
            cases += 1;
        }
        assert_eq!(cases, 2016);
        total += cases;
    }
    assert_eq!(total, 6048);
    std::fs::remove_dir_all(root).unwrap();
}

fn expect_name(p: &mut Proc, thread: &mut Thread, base: u64, handle: u64, name: &str) {
    p.space.wr(base, &[0xa5; 1024]).unwrap();
    assert_eq!(
        invoke(p, thread, &[handle, base, base + 256, 512, 9]),
        STATUS_SUCCESS
    );
    let expected: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(p.space.u32(base + 256).unwrap() as usize, expected.len());
    assert_eq!(p.space.bytes(base + 260, expected.len()).unwrap(), expected);
    assert_eq!(
        p.space
            .ptr(base + p.arch.ptr_size(), p.arch.ptr_size())
            .unwrap(),
        4 + expected.len() as u64
    );
}

#[test]
fn file_information_names_retain_open_volume_through_duplicates_links_and_root_replacement() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for arch in WinArch::ALL {
        let root = std::env::temp_dir().join(format!(
            "rax-name-origin-{}-{}-{arch}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let original = nested.join("name-λ-🔹.txt");
        let alias = nested.join("alias-λ-🔹.txt");
        let renamed = nested.join("renamed-λ-🔹.txt");
        std::fs::write(&original, b"retained original identity").unwrap();
        std::fs::hard_link(&original, &alias).unwrap();
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let mut handles = Vec::new();
        for (file, volume) in [(&original, &root), (&original, &nested), (&alias, &root)] {
            let id = p.objects.create(fixture_object(file, false, 0x12019f));
            p.objects.set_file_name_origin(
                id,
                FileNameOrigin::capture(volume, Vec::new()).map_err(|e| e.to_string()),
            );
            handles.push(u64::from(
                p.objects.open_access(id, false, 0x12019f).unwrap(),
            ));
        }
        let duplicate = u64::from(p.objects.duplicate(handles[0], false).unwrap());
        expect_name(p, &mut thread, base, handles[0], "\\nested\\name-λ-🔹.txt");
        expect_name(p, &mut thread, base, handles[1], "\\name-λ-🔹.txt");
        expect_name(p, &mut thread, base, handles[2], "\\nested\\alias-λ-🔹.txt");
        std::fs::rename(&original, &renamed).unwrap();
        std::fs::write(&original, b"replacement identity").unwrap();
        expect_name(
            p,
            &mut thread,
            base,
            handles[0],
            "\\nested\\renamed-λ-🔹.txt",
        );
        expect_name(p, &mut thread, base, handles[1], "\\renamed-λ-🔹.txt");
        expect_name(
            p,
            &mut thread,
            base,
            duplicate,
            "\\nested\\renamed-λ-🔹.txt",
        );
        expect_name(p, &mut thread, base, handles[2], "\\nested\\alias-λ-🔹.txt");
        let moved = root.with_extension("moved");
        #[cfg(windows)]
        {
            // The independent native-root-move-v1 control denies a parent
            // rename with an open child, including without retained root
            // handles. Assert that native boundary before rechecking names.
            let error = std::fs::rename(&root, &moved).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(5));
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(&root, &moved).unwrap();
            std::fs::create_dir_all(&nested).unwrap();
            std::fs::write(&original, b"replacement root identity").unwrap();
        }
        expect_name(
            p,
            &mut thread,
            base,
            handles[0],
            "\\nested\\renamed-λ-🔹.txt",
        );
        expect_name(p, &mut thread, base, handles[1], "\\renamed-λ-🔹.txt");
        expect_name(
            p,
            &mut thread,
            base,
            duplicate,
            "\\nested\\renamed-λ-🔹.txt",
        );
        expect_name(p, &mut thread, base, handles[2], "\\nested\\alias-λ-🔹.txt");
        drop(process);
        std::fs::remove_dir_all(root).unwrap();
        #[cfg(not(windows))]
        std::fs::remove_dir_all(moved).unwrap();
    }
}
