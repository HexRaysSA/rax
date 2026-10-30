//! Independent native constructor captures, not expectations from product code.
use super::*;
use std::collections::HashMap;

macro_rules! corpus {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-file-section/validation/",
            $name
        ))
    };
}
type Row<'a> = HashMap<&'a str, &'a str>;
fn rows<'a>(text: &'a str, prefix: &str) -> Vec<Row<'a>> {
    text.lines()
        .filter(|line| line.starts_with(prefix))
        .map(|line| {
            line.split_whitespace()
                .skip(1)
                .map(|cell| cell.split_once('=').unwrap())
                .collect()
        })
        .collect()
}
fn n(row: &Row<'_>, key: &str) -> u64 {
    u64::from_str_radix(row[key], 16).unwrap()
}

fn subject(p: &mut Proc) {
    use crate::user::windows::security::{Privilege, Subject};
    // Only the enabled SeSecurityPrivilege field affects this constructor.
    // The independent native corpus was captured under this enabled privilege.
    let subject = Subject {
        statistics: None,
        attributes: None,
        user_attributes: 0,
        user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        groups: vec![],
        restricted: vec![],
        app_container: false,
        privileges: vec![Privilege {
            luid: 8,
            attributes: 2,
        }],
    };
    p.objects
        .select_wnf_catalog(crate::user::windows::wnf::Catalog::selected(vec![], subject).unwrap());
}

fn fixtures(directory: &Directory, arch: WinArch) -> [PathBuf; 3] {
    let paths = [
        directory.0.join("image.dll"),
        directory.0.join("plain.bin"),
        directory.0.join("empty.bin"),
    ];
    let mut bytes = image(arch).to_vec();
    let pe = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    // Match the captured image's SizeOfImage without publishing system DLLs.
    // Original tracked fixture sections and directory bounds remain unchanged.
    let full: u32 = if arch == WinArch::X86 {
        0x8000
    } else {
        0x16000
    };
    bytes[pe + 24 + 56..pe + 24 + 60].copy_from_slice(&full.to_le_bytes());
    std::fs::write(&paths[0], bytes).unwrap();
    std::fs::write(&paths[1], b"plain").unwrap();
    std::fs::write(&paths[2], []).unwrap();
    paths
}

fn replay_create(arch: WinArch, text: &str, count: usize) -> (usize, usize) {
    let observations = rows(text, "case ");
    let faults = rows(text, "fault ");
    assert_eq!(observations.len(), count);
    assert!(faults.is_empty() || faults.len() == count);
    let directory = Directory::new();
    let paths = fixtures(&directory, arch);
    let (mut process, mut t) = fixture(arch, "NtCreateSection", SERVICE);
    let p = process.state_mut();
    subject(p);
    let b = scratch(p);
    let initial = (p.objects.handle_count(), p.objects.iter().count());
    let mut verified = 0;
    let mut bounded = 0;
    let mut differences = vec![];
    for (index, row) in observations.iter().enumerate() {
        p.vm.protect(b, 8 * 4096, prot::READWRITE).unwrap();
        p.space.wr(b, &vec![0; 8 * 4096]).unwrap();
        let sentinel = arch.ptr(u64::MAX - 2);
        ptr(p, b, sentinel);
        let file = insert_file(
            p,
            &paths[row["kind"].parse::<usize>().unwrap()],
            n(row, "file-access") as u32,
        );
        let mut argument_file = file;
        let mut out = if row["null-output"] == "1" { 0 } else { b };
        let mut maximum = match row["maximum-kind"] {
            "0" => 0,
            "1" => b + 4096,
            "2" => b + 4097,
            _ => panic!("maximum kind"),
        };
        p.space
            .w64(b + 4096, row["maximum"].parse::<i64>().unwrap() as u64)
            .unwrap();
        let mut object = 0;
        let oa = b + 8192;
        p.space.w32(oa, if arch.is64() { 48 } else { 24 }).unwrap();
        let mut event = None;
        let mut unsupported_descriptor = false;
        if !faults.is_empty() {
            let fault = &faults[index];
            assert_eq!(fault["role"], row["role"]);
            for recipe in [fault["left"], fault["right"]] {
                match recipe {
                    "-1" | "0" | "1" | "2" | "17" | "18" => {}
                    "3" => out = 0,
                    "4" => {
                        p.vm.protect(b, 4096, prot::NOACCESS).unwrap();
                    }
                    "5" => {
                        p.vm.protect(b, 4096, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "6" => {
                        maximum = b + 4096;
                        p.vm.protect(maximum, 4096, prot::NOACCESS).unwrap();
                    }
                    "7" => {
                        maximum = b + 4096;
                        p.vm.protect(maximum, 4096, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "8" => maximum = b + 4097,
                    "9" => {
                        maximum = b + 4096;
                        p.space.w64(maximum, u64::MAX).unwrap();
                    }
                    "10" => {
                        object = oa;
                        p.vm.protect(oa, 4096, prot::NOACCESS).unwrap();
                    }
                    "11" => {
                        object = oa;
                        p.vm.protect(oa, 4096, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "12" => {
                        object = oa;
                        p.space.w32(oa, 0).unwrap();
                    }
                    "13" => {
                        object = oa;
                        p.space
                            .w32(oa + if arch.is64() { 24 } else { 12 }, u32::MAX)
                            .unwrap();
                    }
                    "14" => {
                        object = oa;
                        ptr(p, oa + if arch.is64() { 32 } else { 16 }, b + 12288);
                        p.vm.protect(b + 12288, 4096, prot::NOACCESS).unwrap();
                        unsupported_descriptor = true;
                    }
                    "15" => argument_file = 0x123456,
                    "16" => {
                        let h = u64::from(p.objects.insert(Object::Event {
                            manual: true,
                            signaled: 0,
                        }));
                        argument_file = h;
                        event = Some(h);
                    }
                    "19" => argument_file = 0,
                    "20" => {
                        object = oa;
                        ptr(p, oa + if arch.is64() { 8 } else { 4 }, 0x123456);
                    }
                    _ => panic!("unknown recipe {recipe}"),
                }
            }
        }
        let allocation = n(row, "attributes");
        let policy_boundary =
            allocation == 0x08000000 || allocation == 0x04000000 || unsupported_descriptor;
        let result = invoke(
            p,
            &mut t,
            &[
                out,
                n(row, "section-access"),
                object,
                maximum,
                n(row, "protection"),
                allocation,
                argument_file,
            ],
        );
        if matches!(result, Outcome::Fail(_)) {
            assert!(
                policy_boundary,
                "unlisted unsupported {arch} row={row:?}: {result:?}"
            );
            bounded += 1;
        } else {
            assert_eq!(result, Outcome::Continue, "{arch} row={row:?}");
            let actual = t.cpu.gpr(0) as u32;
            if actual != n(row, "status") as u32 {
                differences.push(format!("{arch} row={row:?} actual={actual:X}"));
            }
            if !faults.is_empty() {
                let f = &faults[index];
                for (address, key) in [
                    (out, "output-protection"),
                    (maximum, "maximum-protection"),
                    (object, "object-protection"),
                ] {
                    let actual = if address == 0 {
                        0
                    } else {
                        p.vm.query(address).unwrap().protect
                    };
                    if u64::from(actual) != n(f, key) {
                        differences.push(format!(
                            "{arch} role={} {key} actual={actual:X} expected={}",
                            row["role"], f[key]
                        ));
                    }
                }
            }
            let visible = out != 0
                && p.vm
                    .query(out)
                    .is_some_and(|r| r.protect & (prot::NOACCESS | prot::GUARD) == 0);
            if visible {
                let value = get(p, out);
                if row["valid"] == "1" {
                    let Object::ImageSection(section) = p.objects.get(value).unwrap() else {
                        panic!("typed image")
                    };
                    assert_eq!(u64::from(p.objects.access(value).unwrap()), n(row, "grant"));
                    assert_eq!(section.attributes, 0x1800000);
                    let expected_maximum = if row["maximum-kind"] == "1" && row["maximum"] != "0" {
                        row["maximum"].parse::<u64>().unwrap()
                    } else {
                        if arch == WinArch::X86 {
                            0x8000
                        } else {
                            0x16000
                        }
                    };
                    assert_eq!(section.size, expected_maximum);
                    p.objects.close(value).unwrap();
                } else if !faults.is_empty() {
                    let expected = match faults[index]["output"] {
                        "sentinel" => sentinel,
                        "zero" => 0,
                        other => panic!("failed native output {other}"),
                    };
                    assert_eq!(value, expected, "{arch} role={}", row["role"]);
                } else {
                    assert_eq!(value, if arch == WinArch::X86 { 0 } else { sentinel });
                }
            }
            verified += 1;
        }
        p.objects.close(file).unwrap();
        if let Some(h) = event {
            p.objects.close(h).unwrap();
        }
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            initial,
            "{arch} row={row:?}"
        );
    }
    assert!(
        differences.is_empty(),
        "{} differences: {:#?}",
        differences.len(),
        &differences[..differences.len().min(20)]
    );
    (verified, bounded)
}

#[test]
fn native_section_file_replays_independent_ctor_grants_and_capture_priority() {
    let mut counts = (0, 0);
    for (arch, v3, v5, v7) in [
        (
            WinArch::Arm64,
            corpus!("native-file-section-v3-arm64.log"),
            corpus!("native-file-section-v5-arm64.log"),
            corpus!("native-file-section-v7-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-file-section-v3-x64.log"),
            corpus!("native-file-section-v5-x64.log"),
            corpus!("native-file-section-v7-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-file-section-v3-x86.log"),
            corpus!("native-file-section-v5-x86.log"),
            corpus!("native-file-section-v7-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-file-section-v3-x86-laa.log"),
            corpus!("native-file-section-v5-x86-laa.log"),
            corpus!("native-file-section-v7-x86-laa.log"),
        ),
    ] {
        for (text, count) in [(v3, 149), (v5, 272), (v7, 112)] {
            let (verified, bounded) = replay_create(arch, text, count);
            counts.0 += verified;
            counts.1 += bounded;
        }
    }
    assert_eq!(counts.0 + counts.1, 2132);
    println!(
        "native file-section constructor replay: {} matched, {} explicit policy boundaries",
        counts.0, counts.1
    );
}

fn duplicate(p: &mut Proc, t: &mut Thread, args: [u64; 7]) -> u64 {
    use crate::user::windows::hle::{Ctx, Flow, Item, Value};
    let api = crate::user::windows::dll::find("kernel32.dll")
        .unwrap()
        .exports
        .iter()
        .flat_map(|e| e.iter())
        .find_map(|e| match &e.item {
            Item::Func(api) if api.name == "DuplicateHandle" => Some(api),
            _ => None,
        })
        .unwrap();
    let sp = t.cpu.sp();
    for (i, value) in args.into_iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(i, value),
        }
    }
    let mut ctx = Ctx {
        p,
        t,
        api,
        entry_pc: 0x1234,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp - 256,
    };
    match (api.imp)(&mut ctx).unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("integer duplicate result"),
    }
}

#[test]
fn native_section_file_replays_1720_independent_win32_duplicate_grants_and_last_error() {
    let mut total = 0;
    for (arch, text) in [
        (WinArch::Arm64, corpus!("native-file-section-v12-arm64.log")),
        (WinArch::X64, corpus!("native-file-section-v12-x64.log")),
        (WinArch::X86, corpus!("native-file-section-v12-x86.log")),
        (WinArch::X86, corpus!("native-file-section-v12-x86-laa.log")),
    ] {
        let observations = rows(text, "case ");
        assert_eq!(observations.len(), 430);
        let directory = Directory::new();
        let paths = fixtures(&directory, arch);
        let (mut process, mut t) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        subject(p);
        let file = insert_file(p, &paths[0], 0x100021);
        let b = scratch(p);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for row in observations {
            assert_eq!(
                call(
                    p,
                    &mut t,
                    &[b, n(&row, "source-access"), 0, 0, 0x10, 0x1000000, file]
                ),
                0
            );
            let source = get(p, b);
            let id = p.objects.id(source).unwrap();
            let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0xBADC0DE).unwrap();
            ptr(p, b, arch.ptr(u64::MAX - 2));
            let pseudo = arch.ptr(u64::MAX);
            assert_eq!(
                duplicate(
                    p,
                    &mut t,
                    [
                        pseudo,
                        source,
                        pseudo,
                        b,
                        n(&row, "desired"),
                        0,
                        n(&row, "options")
                    ]
                ),
                row["ok"].parse::<u64>().unwrap(),
                "{arch} row={row:?}"
            );
            assert_eq!(
                u64::from(p.space.u32(error).unwrap()),
                n(&row, "error"),
                "{arch} row={row:?}"
            );
            let target = get(p, b);
            if row["ok"] == "1" {
                assert_eq!(p.objects.id(target), Some(id));
                assert_eq!(
                    u64::from(p.objects.access(target).unwrap()),
                    n(&row, "grant"),
                    "{arch} row={row:?}"
                );
                p.objects.close(target).unwrap();
            } else {
                assert_eq!(target, 0);
            }
            p.objects.close(source).unwrap();
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
        p.objects.close(file).unwrap();
    }
    assert_eq!(total, 1720);
}
