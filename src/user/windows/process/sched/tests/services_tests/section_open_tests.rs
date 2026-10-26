//! Independent installed build29683 section-open replay; no host calls.
use super::*;
use crate::user::windows::object_namespace::{
    CapturedEntry, CapturedSection, Namespace, SelectedDirectory,
};
use std::collections::HashMap;
use std::sync::Arc;
const SERVICE: u32 = 0x37;
macro_rules! corpus {
    ($f:literal) => {
        include_str!(concat!(
            "../../../../../../../docs/specifications/windows/native-section-open/",
            $f
        ))
    };
}
#[path = "section_open_duplicate_tests.rs"]
mod duplicate;
#[cfg(windows)]
#[path = "section_open_leaf_tests.rs"]
mod leaf;
#[path = "section_open_profile_tests.rs"]
mod profile;
fn rows<'a>(s: &'a str, prefix: &str) -> Vec<HashMap<&'a str, &'a str>> {
    s.lines()
        .filter(|l| l.starts_with(prefix))
        .map(|l| {
            l.split_whitespace()
                .filter_map(|f| f.split_once('='))
                .collect()
        })
        .collect()
}
fn field(r: &HashMap<&str, &str>, key: &str, radix: u32) -> u64 {
    u64::from_str_radix(r[key], radix).unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn units(s: &str) -> Vec<u16> {
    hex(s)
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect()
}
fn namespace() -> Namespace {
    let raw = corpus!("native-section-open-probe-v3-arm64.log");
    let captures = rows(raw, "case=");
    let mut sections = HashMap::new();
    for r in &captures {
        if r["family"] != "0"
            || r["access"] != "02000000"
            || r["flags"] != "00000040"
            || r["status"] != "00000000"
        {
            continue;
        }
        let b: Vec<_> = r["births"].trim_end_matches(',').split(':').collect();
        assert_eq!(b.len(), 10);
        sections.insert(
            units(b[9]),
            CapturedSection {
                maximum_access: u32::from_str_radix(b[2], 16).unwrap(),
                system_security_status: crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
                attributes: u32::from_str_radix(b[7], 16).unwrap(),
                size: u64::from_str_radix(b[8], 16).unwrap(),
                force_case_insensitive: false,
            },
        );
    }
    assert_eq!(sections.len(), 6);
    let old = include_str!(
        "../../../../../../../docs/specifications/windows/native-object-directory-open/native-object-directory-open-snapshot-arm64.log"
    );
    let dirs = rows(old, "directory ");
    let entries = rows(old, "entry ");
    let links = rows(old, "link ");
    let mut selected: Vec<_> = dirs
        .into_iter()
        .map(|d| {
            let path = units(d["path"]);
            let basic = hex(d["data"]);
            SelectedDirectory {
                maximum_access: u32::from_le_bytes(basic[4..8].try_into().unwrap()),
                system_security_status: crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
                force_case_insensitive: true,
                entries: entries
                    .iter()
                    .filter(|e| e["directory"] == d["ordinal"])
                    .map(|e| {
                        let name = units(e["name"]);
                        let mut full = path.clone();
                        if full.len() != 1 {
                            full.push(92);
                        }
                        full.extend_from_slice(&name);
                        let target = links
                            .iter()
                            .find(|l| l["directory"] == d["ordinal"] && l["name"] == e["name"])
                            .map(|l| units(l["target"]));
                        CapturedEntry {
                            name,
                            kind: units(e["type"]),
                            section: sections.get(&full).copied(),
                            link_access: target.as_ref().map(|_| {
                                crate::user::windows::object_namespace::LinkAccess {
                                    maximum_access: 0x20001,
                                    system_security_status:
                                        crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
                                }
                            }),
                            target,
                        }
                    })
                    .collect(),
                path,
            }
        })
        .collect();
    let path: Vec<_> = "\\KnownDllsChpe32".encode_utf16().collect();
    let subject = rows(raw, "subject ");
    assert_eq!(subject.len(), 1);
    let grant = subject[0]["inputs"]
        .split(',')
        .find(|v| v.starts_with("10:"))
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap();
    selected.push(SelectedDirectory {
        path: path.clone(),
        maximum_access: u32::from_str_radix(grant, 16).unwrap(),
        system_security_status: crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
        force_case_insensitive: true,
        entries: sections
            .iter()
            .filter_map(|(full, section)| {
                let prefix: Vec<_> = path.iter().copied().chain([92]).collect();
                full.strip_prefix(prefix.as_slice())
                    .map(|name| CapturedEntry {
                        name: name.to_vec(),
                        kind: "Section".encode_utf16().collect(),
                        section: Some(*section),
                        target: None,
                        link_access: None,
                    })
            })
            .collect(),
    });
    let upcase: Arc<[u16]> = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect::<Vec<_>>()
        .into();
    let mut n = Namespace::selected(upcase, selected).unwrap();
    n.select_wow_section_root(true).unwrap();
    n.select_wow_system_root(&"C:\\WINDOWS".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    n
}
const NAMES: [&str; 27] = [
    "\\KnownDlls\\kernel32.dll",
    "\\KNOWNDLLS\\KERNEL32.DLL",
    "\\KnownDlls32\\kernel32.dll",
    "\\KnownDlls\\ntdll.dll",
    "\\KnownDlls32\\ntdll.dll",
    "\\KnownDlls\\rax-absent-20261013",
    "\\KnownDlls\\KnownDllPath",
    "\\KnownDlls",
    "kernel32.dll",
    "KERNEL32.DLL",
    "",
    "\\",
    "\\rax-missing\\kernel32.dll",
    "\\KnownDlls\\kernel32.dll\\x",
    "\\KnownDlls\\\\kernel32.dll",
    "kernel32.dll\\x",
    "\\KnownDlls\\kernel32.dll\\",
    "\\KnownDllsChpe32\\kernel32.dll",
    "\\KnownDllsChpe32\\ntdll.dll",
    "KnownDlls32\\kernel32.dll",
    "KnownDlls32\\ntdll.dll",
    "KnownDllsChpe32\\kernel32.dll",
    "KnownDlls\\kernel32.dll",
    "Kernel32.Dll",
    "rax-absent-20261013",
    ".\\kernel32.dll",
    "knowndlls32\\kernel32.dll",
];
fn address(mode: u64, page: u64, local: u64, width: u64, b: u64) -> u64 {
    match mode {
        1 => 0,
        2 => 1,
        3 => b + local + 1,
        4 => b + local + 4,
        5 | 6 | 7 | 9 => b + page * 4096,
        8 => b + (page + 1) * 4096 - width / 2,
        10 => b + local + 2,
        11 => b + local + 3,
        _ => b + local,
    }
}
fn set_mode(p: &mut Proc, b: u64, mode: u64, page: u64) {
    let flags = match mode {
        5 => prot::READWRITE | prot::GUARD,
        6 => prot::NOACCESS,
        7 => prot::READONLY,
        9 => prot::READONLY | prot::GUARD,
        _ => prot::READWRITE,
    };
    if mode == 8 {
        p.vm.protect(b + (page + 1) * 4096, 4096, prot::NOACCESS)
            .unwrap();
    } else if matches!(mode, 5 | 6 | 7 | 9) {
        p.vm.protect(b + page * 4096, 4096, flags).unwrap();
    }
}
fn store(p: &Proc, b: u64, at: u64, data: &[u8]) {
    if at >= b && at <= b + 40 * 4096 - data.len() as u64 {
        p.space.wr(at, data).unwrap();
    }
}

fn call(p: &mut Proc, t: &mut Thread, args: [u64; 3]) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (i, v) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + i as u64 * 4, v as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, v) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2, 8][i], v);
            }
        }
        WinArch::Arm64 => {
            for (i, v) in args.into_iter().enumerate() {
                t.cpu.set_gpr(i, v);
            }
        }
    }
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(outcome, Outcome::Continue, "{} args={args:X?}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}
fn roots(p: &mut Proc) -> [u64; 15] {
    let mut hs = [0; 15];
    for (i, path, access) in [
        (1, "\\", 0x02000000),
        (2, "\\KnownDlls", 0x02000000),
        (3, "\\KnownDlls32", 0x02000000),
        (9, "\\KnownDlls", 0x20000),
        (10, "\\KnownDllsChpe32", 0x02000000),
        (11, "\\KnownDlls32", 0x20000),
        (12, "\\KnownDlls32", 1),
    ] {
        let d = p
            .object_namespace
            .lookup(None, &path.encode_utf16().collect::<Vec<_>>(), 0x40)
            .unwrap();
        let grant = d.grant(access, false).unwrap();
        hs[i] = p.objects.open_directory(d, false, grant).unwrap().into();
    }
    let l = p
        .object_namespace
        .lookup_link(
            None,
            &"\\KnownDlls\\KnownDllPath"
                .encode_utf16()
                .collect::<Vec<_>>(),
            0x40,
        )
        .unwrap();
    hs[4] = p.objects.open_symbolic_link(l, false, 1).unwrap().into();
    let s = p
        .object_namespace
        .lookup_section(
            None,
            &"\\KnownDlls\\ntdll.dll".encode_utf16().collect::<Vec<_>>(),
            0x40,
            false,
        )
        .unwrap();
    let grant = s.grant(0x02000000, false).unwrap();
    hs[5] = p
        .objects
        .open_image_section(s, false, grant)
        .unwrap()
        .into();
    hs[6] = p.arch.ptr(u64::MAX);
    hs[7] = 0xABC;
    hs[8] = hs[2] | 3;
    hs[13] = hs[3] | 3;
    hs[14] = hs[3]
        | if p.arch.is64() {
            0x1_0000_0000
        } else {
            0x4000_0000
        };
    hs
}
fn replay(text: &str, arch: WinArch, families: &[u64]) -> usize {
    let rs = rows(text, "case=");
    assert_eq!(rs.len(), 5646);
    assert!(text.contains("complete cases=5646 inputs-closed=9"));
    let (mut process, mut t) = fixture(arch, "NtOpenSection", SERVICE);
    let p = process.state_mut();
    p.object_namespace = namespace();
    let b =
        p.vm.allocate(None, 40 * 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let before = (p.objects.handle_count(), p.objects.iter().count());
    let hs = roots(p);
    let baseline = (p.objects.handle_count(), p.objects.iter().count());
    let page_offsets = [0, 1, 2, 3, 4, 5, 16, 17];
    let mut count = 0;
    for r in rs
        .into_iter()
        .filter(|r| families.contains(&field(r, "family", 10)))
    {
        let width = arch.ptr_size();
        let asize = if arch.is64() { 48 } else { 24 };
        let nsize = if arch.is64() { 16 } else { 8 };
        p.vm.protect(b, 40 * 4096, prot::READWRITE).unwrap();
        p.space.wr(b, &vec![0xA5; 40 * 4096]).unwrap();
        let ak = field(&r, "attributes", 10);
        let ok = field(&r, "output", 10);
        let nk = field(&r, "unicode", 10);
        let bk = field(&r, "buffer", 10);
        let aa = address(ak, 0, 12 * 4096 + 128, asize, b);
        let oa = address(ok, 2, 13 * 4096 + 128, width, b);
        let na = address(nk, 4, 14 * 4096 + 128, nsize, b);
        let ba = address(bk, 16, 20 * 4096 + 128, 32, b);
        let mut a = vec![0; asize as usize];
        a[..4].copy_from_slice(&(field(&r, "attributes-length", 10) as u32).to_le_bytes());
        let root = hs[field(&r, "root", 10) as usize];
        for (at, v) in [(width, root), (width * 2, na)] {
            a[at as usize..(at + width) as usize]
                .copy_from_slice(&v.to_le_bytes()[..width as usize]);
        }
        a[(width * 3) as usize..(width * 3 + 4) as usize]
            .copy_from_slice(&(field(&r, "flags", 16) as u32).to_le_bytes());
        store(p, b, aa, &a);
        let mut u = vec![0; nsize as usize];
        u[..2].copy_from_slice(&(field(&r, "length", 10) as u16).to_le_bytes());
        u[2..4].copy_from_slice(&(field(&r, "maximum", 10) as u16).to_le_bytes());
        let no = if arch.is64() { 8 } else { 4 };
        u[no..no + width as usize].copy_from_slice(&ba.to_le_bytes()[..width as usize]);
        store(p, b, na, &u);
        let bytes: Vec<_> = NAMES[field(&r, "name", 10) as usize]
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        store(p, b, ba, &bytes);
        for (mode, page) in [(ak, 0), (ok, 2), (nk, 4), (bk, 16)] {
            set_mode(p, b, mode, page);
        }
        let expected = field(&r, "status", 16) as u32;
        assert_eq!(
            call(p, &mut t, [oa, field(&r, "access", 16), aa]),
            expected,
            "arch={arch} row={r:?}"
        );
        let protections: Vec<_> = r["protection"]
            .trim_end_matches(',')
            .split(',')
            .map(|v| u32::from_str_radix(v, 16).unwrap())
            .collect();
        for (offset, expected) in page_offsets.into_iter().zip(protections) {
            assert_eq!(
                p.vm.query(b + offset * 4096).unwrap().protect,
                expected,
                "arch={arch} page={offset} row={r:?}"
            );
        }
        p.vm.protect(b, 40 * 4096, prot::READWRITE).unwrap();
        if field(&r, "observed", 10) == 1 {
            let actual = p.space.ptr(oa, width).unwrap();
            let mut expected_bytes = hex(r["output-bytes"]);
            if expected == 0 {
                assert_eq!(field(&r, "birth-count", 10), 1);
                let meta: Vec<_> = r["births"].trim_end_matches(',').split(':').collect();
                assert_eq!(
                    p.objects.access(actual),
                    Some(u32::from_str_radix(meta[2], 16).unwrap())
                );
                assert_eq!(p.objects.flags(actual), Some(meta[3].parse().unwrap()));
                let Some(Object::ImageSection(section)) = p.objects.get(actual) else {
                    panic!("section row={r:?}")
                };
                assert_eq!(section.path, units(meta[9]));
                if meta[4] == "00000000" {
                    assert_eq!(
                        section.attributes,
                        u32::from_str_radix(meta[7], 16).unwrap()
                    );
                    assert_eq!(section.size, u64::from_str_radix(meta[8], 16).unwrap());
                } else {
                    assert_eq!(meta[4], "C0000022");
                    assert_eq!(
                        meta[5],
                        if arch == WinArch::X86 {
                            "4294967288"
                        } else {
                            "0"
                        }
                    );
                    assert_eq!(meta[7], "00000000");
                    assert_eq!(meta[8], "0");
                }
                expected_bytes[..width as usize]
                    .copy_from_slice(&actual.to_le_bytes()[..width as usize]);
                p.objects.close(actual).unwrap();
            } else {
                assert_eq!(actual, field(&r, "result", 16));
                assert_eq!(field(&r, "birth-count", 10), 0);
            }
            assert_eq!(
                p.space.bytes(oa, expected_bytes.len()).unwrap(),
                expected_bytes,
                "arch={arch} row={r:?}"
            );
        }
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            baseline,
            "arch={arch} row={r:?}"
        );
        count += 1;
    }
    for i in [1, 2, 3, 4, 5, 9, 10, 11, 12] {
        p.objects.close(hs[i]).unwrap();
    }
    assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    count
}
fn replay_all(families: &[u64], expected: usize) {
    let mut total = 0;
    for (arch, text) in [
        (
            WinArch::Arm64,
            corpus!("native-section-open-probe-v3-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-section-open-probe-v3-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-section-open-probe-v3-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-section-open-probe-v3-x86-laa.log"),
        ),
    ] {
        total += replay(text, arch, families);
    }
    assert_eq!(total, expected);
}
#[test]
fn native_section_open_replays_all_13752_access_names_roots_flags_and_counted_string_rows() {
    replay_all(&[0, 1, 2, 5], 13752);
}
#[test]
fn native_section_open_replays_all_8832_attributes_output_unicode_and_buffer_fault_rows() {
    replay_all(&[3, 4], 8832);
}
