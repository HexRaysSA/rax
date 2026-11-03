//! Complete arena/protection replay of the independent native pointer controls.
use super::{Harness, Mem, WinArch};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::objects::Object;
use serde_json::Value;

fn number(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn integer(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn offset(field: usize, size: usize, role: u64) -> usize {
    field * 8192
        + if (7..=9).contains(&role) {
            4096 - size / 2
        } else {
            128 + usize::from(role == 2)
        }
}
fn put(raw: &mut [u8], at: usize, value: u64, width: usize) {
    raw[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

#[test]
fn native_file_create_native_pointer_corpus_replays_all_bytes_protections_and_owned_handles() {
    let mut failures = Vec::new();
    for (arch, corpus) in [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/pointer-arm64-v1.json"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/pointer-x64-v1.json"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/pointer-x86-v1.json"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/mutating-pointer-x64-v1.json"
            )),
        ),
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/mutating-pointer-arm64-v1.json"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/mutating-pointer-x86-v1.json"
            )),
        ),
    ] {
        let data: Value = serde_json::from_str(corpus).unwrap();
        let cases = data["cases"].as_array().unwrap();
        assert!(matches!(cases.len(), 367 | 1101));
        let base = integer(&data["profile"]["base"]);
        let width = arch.ptr_size() as usize;
        let sizes = [
            width,
            if width == 8 { 48 } else { 24 },
            2 * width,
            8,
            2 * width,
            30,
            14,
            12,
        ];
        let mut h = Harness::new(arch);
        h.name("\\??\\C:\\");
        assert_eq!(
            h.invoke_api(
                "NtOpenFile",
                &[h.base, 0x100001, h.attrs(), h.base + 4096, 7, 0x21]
            ),
            0
        );
        let root = h.process.state().space.ptr(h.base, width as u64).unwrap();
        h.process
            .state_mut()
            .vm
            .allocate(
                Some(base),
                16 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
        for case in cases {
            let index = number(&case["index"]);
            let roles: Vec<_> = case["roles"]
                .as_array()
                .unwrap()
                .iter()
                .map(number)
                .collect();
            let parameter = number(&case["parameter"]);
            let alias = number(&case["alias"]);
            let mut raw = vec![0xa5; 65536];
            let mut ptrs = [0u64; 8];
            let mut locations = [0usize; 8];
            for f in 0..8 {
                let role = roles[f];
                ptrs[f] = match role {
                    1 => 0,
                    10 => 1,
                    _ => base + offset(f, sizes[f], role) as u64,
                };
                locations[f] = offset(f, sizes[f], if matches!(role, 1 | 10) { 0 } else { role });
            }
            match alias {
                1 => ptrs[0] = ptrs[2],
                2 => ptrs[0] = ptrs[2] + width as u64,
                3 => ptrs[2] = ptrs[0] + 4,
                4 => ptrs[2] = ptrs[0] - 4,
                _ => {}
            }
            let a = locations[1];
            raw[a..a + sizes[1]].fill(0);
            put(
                &mut raw,
                a,
                if parameter == 8 { 0 } else { sizes[1] as u64 },
                4,
            );
            put(&mut raw, a + width, root, width);
            put(&mut raw, a + 2 * width, ptrs[4], width);
            put(&mut raw, a + 3 * width, 0x40, 4);
            put(
                &mut raw,
                a + if width == 8 { 40 } else { 20 },
                ptrs[7],
                width,
            );
            let u = locations[4];
            raw[u..u + sizes[4]].fill(0);
            put(&mut raw, u, 28, 2);
            put(&mut raw, u + 2, 30, 2);
            put(&mut raw, u + width, ptrs[5], width);
            let name = format!("case-{index:05}.dat");
            let encoded: Vec<u8> = name
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            raw[locations[5]..locations[5] + 30].copy_from_slice(&encoded);
            put(
                &mut raw,
                locations[3],
                if parameter == 5 { u64::MAX } else { 0 },
                8,
            );
            let e = locations[6];
            raw[e..e + 14]
                .copy_from_slice(&[0, 0, 0, 0, 0, 3, 2, 0, b'O', b'n', b'e', 0, 0x12, 0x34]);
            let q = locations[7];
            raw[q..q + 12].copy_from_slice(&[12, 0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0]);
            let file = h.directory.0.join(&name);
            if case.get("existing").is_none_or(|v| number(v) != 0) {
                std::fs::write(&file, b"original").unwrap();
            }
            h.process.state().space.wr(base, &raw).unwrap();
            for (f, role) in roles.iter().copied().enumerate() {
                let protected = match role {
                    3 => Some((0, prot::READONLY)),
                    4 => Some((0, prot::NOACCESS)),
                    5 => Some((0, prot::READWRITE | prot::GUARD)),
                    6 => Some((0, prot::READONLY | prot::GUARD)),
                    7 => Some((1, prot::NOACCESS)),
                    8 => Some((1, prot::READONLY)),
                    9 => Some((1, prot::READWRITE | prot::GUARD)),
                    _ => None,
                };
                if let Some((next, protect)) = protected {
                    h.process
                        .state_mut()
                        .vm
                        .protect(base + (f * 2 + next) as u64 * PAGE_SIZE, PAGE_SIZE, protect)
                        .unwrap();
                }
            }
            let count = h.process.state().objects.iter().count();
            let code = h.invoke_api(
                "NtCreateFile",
                &[
                    ptrs[0],
                    if parameter == 4 {
                        0x04000000
                    } else {
                        0x80100080
                    },
                    ptrs[1],
                    ptrs[2],
                    ptrs[3],
                    if parameter == 7 { 0xffffffff } else { 0 },
                    if parameter == 2 { 8 } else { 7 },
                    case.get("disposition")
                        .map_or(if parameter == 1 { 6 } else { 1 }, number),
                    if parameter == 3 { 0x30 } else { 0x20060 },
                    ptrs[6],
                    case.get("ea_bytes")
                        .map_or(if parameter == 6 { 1 } else { 14 }, number),
                ],
            );
            if code as u64 != integer(&case["status"]) {
                failures.push(format!(
                    "{arch}/{index}/status: {code:#x}, expected {}",
                    case["status"]
                ));
            }
            for page in 0..16 {
                let actual = h
                    .process
                    .state()
                    .vm
                    .query(base + page * PAGE_SIZE)
                    .unwrap()
                    .protect as u64;
                if actual != number(&case["protections"][page as usize]) {
                    failures.push(format!(
                        "{arch}/{index}/protection/{page}: {actual:#x}, expected {}",
                        case["protections"][page as usize]
                    ));
                }
                h.process
                    .state_mut()
                    .vm
                    .protect(base + page * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                    .unwrap();
            }
            let actual = h.process.state().space.bytes(base, 65536).unwrap();
            let mut expected = raw;
            for change in case["changes"].as_array().unwrap() {
                let at = number(&change[0]) as usize;
                let value = bytes(change[1].as_str().unwrap());
                expected[at..at + value.len()].copy_from_slice(&value);
            }
            let published = ptrs[0] >= base && ptrs[0] - base <= 65536 - width as u64;
            let native_output = integer(&case["output"]);
            let dynamic_handle = published
                && (number(&case["handle_valid"]) != 0 || alias == 0)
                && ![0, 1, 0xa5a5a5a5, 0xa5a5a5a5a5a5a5a5].contains(&native_output);
            if dynamic_handle {
                let at = (ptrs[0] - base) as usize;
                let handle = h.process.state().space.ptr(ptrs[0], width as u64).unwrap();
                if handle == 0 {
                    failures.push(format!("{arch}/{index}/missing handle"));
                }
                put(&mut expected, at, handle, width);
                let valid = matches!(h.process.state().objects.get(handle), Some(Object::File(_)));
                if valid != (number(&case["handle_valid"]) != 0) {
                    failures.push(format!("{arch}/{index}/ownership: {valid}"));
                }
                if valid {
                    assert_eq!(h.process.state().objects.access(handle), Some(0x120089));
                    h.process.state_mut().objects.close(handle).unwrap();
                }
            }
            if actual != expected {
                let differences: Vec<_> = actual
                    .iter()
                    .zip(&expected)
                    .enumerate()
                    .filter_map(|(i, (a, e))| (a != e).then_some(format!("{i:#x}:{a:02x}/{e:02x}")))
                    .take(16)
                    .collect();
                failures.push(format!(
                    "{arch}/{index}/complete arena differences: {differences:?}"
                ));
            }
            let leaked = usize::from(matches!(alias, 1 | 2 | 4));
            let actual_count = h.process.state().objects.iter().count();
            if actual_count != count + leaked {
                failures.push(format!(
                    "{arch}/{index}/owned file count: {actual_count}, expected {}",
                    count + leaked
                ));
            }
            let exists = file.exists();
            if exists != (number(&case["exists"]) != 0) {
                failures.push(format!("{arch}/{index}/file existence: {exists}"));
            }
            if exists {
                let expected = if integer(&case["file_size"]) == 8 {
                    b"original".as_slice()
                } else {
                    &[]
                };
                let actual = std::fs::read(&file).unwrap();
                if actual != expected {
                    failures.push(format!(
                        "{arch}/{index}/file effect: {actual:02x?}, expected {expected:02x?}"
                    ));
                }
                std::fs::remove_file(file).unwrap();
            }
        }
        h.process.state_mut().objects.close(root).unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} replay mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
