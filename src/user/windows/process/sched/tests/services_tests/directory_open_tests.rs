//! Independent build29683 object-manager corpus; no native calls in replay.
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{CapturedEntry, Namespace, SelectedDirectory};
use std::collections::HashMap;
use std::sync::Arc;
#[path = "directory_open_boundary_tests.rs"]
mod boundary;
#[cfg(windows)]
#[path = "directory_open_leaf_tests.rs"]
mod leaf;
#[path = "directory_open_name_probe_tests.rs"]
mod name_probe;
#[path = "directory_session_partial_tests.rs"]
mod partial_session;
#[path = "directory_open_reference_tests.rs"]
mod reference;
#[path = "directory_session_tests.rs"]
mod session_directories;
const SERVICE: u32 = 0x58;
macro_rules! corpus {
    ($f:literal) => {
        include_str!(concat!(
            "../../../../../../../docs/specifications/windows/native-object-directory-open/",
            $f
        ))
    };
}
fn rows<'a>(text: &'a str, prefix: &str) -> Vec<HashMap<&'a str, &'a str>> {
    text.lines()
        .filter(|l| l.starts_with(prefix))
        .map(|l| {
            l.split_whitespace()
                .filter_map(|s| s.split_once('='))
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
fn profiles(family: &str) -> [(WinArch, &'static str); 4] {
    let a = WinArch::Arm64;
    let x = WinArch::X64;
    let w = WinArch::X86;
    match family {
        "matrix" => [
            (a, corpus!("native-object-directory-open-matrix-arm64.log")),
            (x, corpus!("native-object-directory-open-matrix-x64.log")),
            (w, corpus!("native-object-directory-open-matrix-x86.log")),
            (
                w,
                corpus!("native-object-directory-open-matrix-x86-laa.log"),
            ),
        ],
        "boundaries" => [
            (
                a,
                corpus!("native-object-directory-open-boundaries-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-boundaries-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-boundaries-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-boundaries-x86-laa.log"),
            ),
        ],
        "format" => [
            (a, corpus!("native-object-directory-open-format-arm64.log")),
            (x, corpus!("native-object-directory-open-format-x64.log")),
            (w, corpus!("native-object-directory-open-format-x86.log")),
            (
                w,
                corpus!("native-object-directory-open-format-x86-laa.log"),
            ),
        ],
        "reference" => [
            (
                a,
                corpus!("native-object-directory-open-reference-arm64.log"),
            ),
            (x, corpus!("native-object-directory-open-reference-x64.log")),
            (w, corpus!("native-object-directory-open-reference-x86.log")),
            (
                w,
                corpus!("native-object-directory-open-reference-x86-laa.log"),
            ),
        ],
        "duplicate-boundaries" => [
            (
                a,
                corpus!("native-object-directory-open-duplicate-boundaries-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-duplicate-boundaries-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-boundaries-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-boundaries-x86-laa.log"),
            ),
        ],
        "privilege" => [
            (
                a,
                corpus!("native-object-directory-open-privilege-arm64.log"),
            ),
            (x, corpus!("native-object-directory-open-privilege-x64.log")),
            (w, corpus!("native-object-directory-open-privilege-x86.log")),
            (
                w,
                corpus!("native-object-directory-open-privilege-x86-laa.log"),
            ),
        ],
        "flag-boundaries" => [
            (
                a,
                corpus!("native-object-directory-open-flag-boundaries-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-flag-boundaries-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-flag-boundaries-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-flag-boundaries-x86-laa.log"),
            ),
        ],
        "duplicate-policy" => [
            (
                a,
                corpus!("native-object-directory-open-duplicate-policy-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-duplicate-policy-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-policy-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-policy-x86-laa.log"),
            ),
        ],
        "name-probe" => [
            (
                a,
                corpus!("native-object-directory-open-name-probe-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-name-probe-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-name-probe-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-name-probe-x86-laa.log"),
            ),
        ],
        "duplicate-protected-boundaries" => [
            (
                a,
                corpus!("native-object-directory-open-duplicate-protected-boundaries-arm64.log"),
            ),
            (
                x,
                corpus!("native-object-directory-open-duplicate-protected-boundaries-x64.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-protected-boundaries-x86.log"),
            ),
            (
                w,
                corpus!("native-object-directory-open-duplicate-protected-boundaries-x86-laa.log"),
            ),
        ],
        _ => panic!("unknown corpus"),
    }
}
fn namespace() -> Namespace {
    namespace_for_system_security(STATUS_PRIVILEGE_NOT_HELD)
}
fn namespace_for_system_security(system_security_status: u32) -> Namespace {
    let text = corpus!("native-object-directory-open-snapshot-arm64.log");
    let records = rows(text, "directory ");
    let entries = rows(text, "entry ");
    let links = rows(text, "link ");
    let selected = records
        .into_iter()
        .map(|r| {
            let ordinal = r["ordinal"];
            let basic = hex(r["data"]);
            SelectedDirectory {
                path: units(r["path"]),
                maximum_access: u32::from_le_bytes(basic[4..8].try_into().unwrap()),
                force_case_insensitive: true,
                system_security_status,
                entries: entries
                    .iter()
                    .filter(|e| e["directory"] == ordinal)
                    .map(|e| CapturedEntry {
                        section: None,
                        link_access: None,
                        name: units(e["name"]),
                        kind: units(e["type"]),
                        target: links
                            .iter()
                            .find(|l| l["directory"] == ordinal && l["name"] == e["name"])
                            .map(|l| units(l["target"])),
                    })
                    .collect(),
            }
        })
        .collect();
    let upcase: Arc<[u16]> = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect::<Vec<_>>()
        .into();
    let mut namespace = Namespace::selected(upcase, selected).unwrap();
    let subject = rows(
        corpus!("native-object-directory-open-name-probe-arm64.log"),
        "subject ",
    );
    assert_eq!(subject.len(), 1);
    namespace
        .select_wow_system_root(&units(subject[0]["root-data"]))
        .unwrap();
    namespace
}
fn setup(arch: WinArch, pages: u64) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtOpenDirectoryObject", SERVICE);
    let p = process.state_mut();
    p.object_namespace = namespace();
    let b =
        p.vm.allocate(
            None,
            pages * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    (process, t, b)
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
fn descriptor(p: &Proc, at: u64, buffer: u64, length: u16, maximum: u16) {
    p.space
        .wr(at, &vec![0; if p.arch.is64() { 16 } else { 8 }])
        .unwrap();
    p.space.w16(at, length).unwrap();
    p.space.w16(at + 2, maximum).unwrap();
    p.space
        .wptr(
            at + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            buffer,
        )
        .unwrap();
}
fn attributes(p: &Proc, at: u64, name: u64, root: u64, flags: u32, length: u32) {
    let width = p.arch.ptr_size();
    p.space
        .wr(at, &vec![0; if p.arch.is64() { 48 } else { 24 }])
        .unwrap();
    p.space.w32(at, length).unwrap();
    p.space.wptr(at + width, width, root).unwrap();
    p.space.wptr(at + width * 2, width, name).unwrap();
    p.space.w32(at + width * 3, flags).unwrap();
}
fn opened(p: &mut Proc, t: &mut Thread, b: u64, path: &str, access: u32) -> u64 {
    let text: Vec<_> = path.encode_utf16().collect();
    p.space.put_wunits(b + 128, &text).unwrap();
    descriptor(
        p,
        b + 64,
        b + 128,
        (text.len() * 2) as u16,
        (text.len() * 2 + 2) as u16,
    );
    attributes(
        p,
        b + 16,
        b + 64,
        0,
        0x40,
        if p.arch.is64() { 48 } else { 24 },
    );
    assert_eq!(call(p, t, [b, access.into(), b + 16]), 0);
    p.space.ptr(b, p.arch.ptr_size()).unwrap()
}
fn resource(p: &Proc, h: u64, r: &HashMap<&str, &str>) {
    assert_eq!(p.objects.get(h).unwrap().type_name(), "Directory");
    let b = hex(r["basic-data"]);
    assert_eq!(
        p.objects.access(h),
        Some(u32::from_le_bytes(b[4..8].try_into().unwrap()))
    );
    assert_eq!(
        p.objects.flags(h),
        Some(field(r, "handle-flags", 10) as u32)
    );
    assert_eq!(p.objects.access(h).unwrap() & 0x100000, 0);
    assert_eq!(field(r, "wait", 16), STATUS_ACCESS_DENIED as u64);
}
#[test]
fn native_directory_open_replays_all_3868_lengths_names_rights_roots_and_aliases() {
    const NAMES: [&str; 14] = [
        "\\KnownDlls",
        "\\KnownDlls32",
        "\\knowndlls",
        "KnownDlls",
        "\\",
        "",
        "\\KnownDlls\\",
        "\\KnownDlls\\\\x",
        "\\KnownDlls\\rax-absent-20261012",
        "\\rax-absent-20261012\\x",
        "\\KnownDlls\\KnownDllPath",
        "\\KnownDlls\\ntdll.dll",
        "KnownDllPath",
        "ntdll.dll",
    ];
    let mut total = 0;
    for (arch, text) in profiles("matrix") {
        let records = rows(text, "case=");
        assert_eq!(records.len(), 967);
        assert!(text.contains("complete cases=967"));
        let (mut process, mut t, b) = setup(arch, 20);
        let p = process.state_mut();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for r in records {
            p.space.wr(b, &vec![0; 20 * PAGE_SIZE as usize]).unwrap();
            let rk = field(&r, "root", 10);
            let mut owned_root = None;
            let root = match rk {
                1 | 3 => {
                    let h = opened(p, &mut t, b + 18 * PAGE_SIZE, "\\KnownDlls", 3);
                    if rk == 3 {
                        p.objects.close(h).unwrap();
                    } else {
                        owned_root = Some(h);
                    }
                    h
                }
                2 => {
                    let h = p.objects.insert(Object::Event {
                        manual: false,
                        signaled: 0,
                    }) as u64;
                    owned_root = Some(h);
                    h
                }
                4 => arch.ptr(u64::MAX),
                5 => arch.ptr(u64::MAX - 1),
                6 => 1,
                _ => 0,
            };
            let input = b + 64;
            let name = b + 128;
            let buffer = b + PAGE_SIZE;
            let units: Vec<_> = NAMES[field(&r, "name", 10) as usize]
                .encode_utf16()
                .collect();
            p.space.put_wunits(buffer, &units).unwrap();
            let mode = field(&r, "mode", 10);
            descriptor(
                p,
                name,
                if mode == 3 { 0 } else { buffer },
                field(&r, "name-length", 10) as u16,
                field(&r, "maximum", 10) as u16,
            );
            attributes(
                p,
                input,
                if mode == 2 { 0 } else { name },
                root,
                field(&r, "flags", 16) as u32,
                field(&r, "attributes-length", 10) as u32,
            );
            let before_attrs = p
                .space
                .bytes(input, if arch.is64() { 48 } else { 24 })
                .unwrap();
            let before_name = p
                .space
                .bytes(name, if arch.is64() { 16 } else { 8 })
                .unwrap();
            let poison = arch.ptr(0xA5A5_A5A5_A5A5_A5A5);
            p.space.wptr(b, arch.ptr_size(), poison).unwrap();
            p.space
                .wptr(
                    b + arch.ptr_size(),
                    arch.ptr_size(),
                    arch.ptr(0xB6B6_B6B6_B6B6_B6B6),
                )
                .unwrap();
            let out = match mode {
                4 => 0,
                5 => input,
                6 => name,
                _ => b,
            };
            let expected = field(&r, "status", 16) as u32;
            assert_eq!(
                call(
                    p,
                    &mut t,
                    [
                        out,
                        field(&r, "access", 16),
                        if mode == 1 { 0 } else { input }
                    ]
                ),
                expected,
                "row={r:?}"
            );
            if expected == 0 {
                let h = p.space.ptr(out, arch.ptr_size()).unwrap();
                resource(p, h, &r);
                p.objects.close(h).unwrap();
            } else if out != 0 {
                let native = if mode == 5 {
                    hex(r["attributes-after"])
                } else if mode == 6 {
                    hex(r["unicode-after"])
                } else {
                    field(&r, "output", 16).to_le_bytes().to_vec()
                };
                let want = if arch.is64() {
                    u64::from_le_bytes(native[..8].try_into().unwrap())
                } else {
                    u32::from_le_bytes(native[..4].try_into().unwrap()) as u64
                };
                let native_before = if mode == 5 {
                    hex(r["attributes-before"])
                } else if mode == 6 {
                    hex(r["unicode-before"])
                } else {
                    poison.to_le_bytes().to_vec()
                };
                if native[..arch.ptr_size() as usize] == native_before[..arch.ptr_size() as usize] {
                    assert_eq!(
                        p.space.bytes(out, arch.ptr_size() as usize).unwrap(),
                        if mode == 5 {
                            before_attrs[..arch.ptr_size() as usize].to_vec()
                        } else if mode == 6 {
                            before_name[..arch.ptr_size() as usize].to_vec()
                        } else {
                            poison.to_le_bytes()[..arch.ptr_size() as usize].to_vec()
                        }
                    );
                } else {
                    assert_eq!(
                        p.space.ptr(out, arch.ptr_size()).unwrap(),
                        want,
                        "row={r:?}"
                    );
                }
            }
            for (at, before, alias) in [
                (input, before_attrs, mode == 5),
                (name, before_name, mode == 6),
            ] {
                let after = p.space.bytes(at, before.len()).unwrap();
                let offset = if alias { arch.ptr_size() as usize } else { 0 };
                assert_eq!(&after[offset..], &before[offset..]);
            }
            assert_eq!(
                p.space.ptr(b + arch.ptr_size(), arch.ptr_size()).unwrap(),
                arch.ptr(0xB6B6_B6B6_B6B6_B6B6)
            );
            if let Some(h) = owned_root {
                p.objects.close(h).unwrap();
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 3868);
}
#[test]
fn native_directory_open_replays_all_3048_utf16_security_qos_and_reparse_rows() {
    const PATHS: [&str; 15] = [
        "\\KnownDlls",
        "\\KnownDlls\\KnownDllPath",
        "\\KnownDlls\\ntdll.dll",
        "\\KnownDlls\\ntdll.dll\\x",
        "\\KnownDlls\\KnownDllPath\\x",
        "\\KnownDlls\\",
        "\\KnownDlls\\\\x",
        "\\\\KnownDlls",
        "\\.\\KnownDlls",
        "\\KnownDlls/ntdll.dll",
        "\\KnownDlls\\..",
        "\\KnownDlls\\.",
        "\\",
        "\\rax-absent-20261012\\x",
        "\\knowndlls",
    ];
    let mut total = 0;
    for (arch, text) in profiles("format") {
        let rs = rows(text, "case=");
        assert_eq!(rs.len(), 762);
        assert!(text.contains("complete cases=762"));
        let (mut process, mut t, b) = setup(arch, 20);
        let p = process.state_mut();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for r in rs {
            p.space.wr(b, &vec![0; 20 * PAGE_SIZE as usize]).unwrap();
            let input = b + 64;
            let name = b + 128 + field(&r, "unicode-offset", 10);
            let buffer = b + PAGE_SIZE + field(&r, "buffer-offset", 10);
            let text: Vec<_> = PATHS[field(&r, "path", 10) as usize]
                .encode_utf16()
                .collect();
            p.space.put_wunits(buffer, &text).unwrap();
            descriptor(p, name, buffer, field(&r, "length", 10) as u16, 0);
            attributes(
                p,
                input,
                name,
                0,
                field(&r, "flags", 16) as u32,
                if arch.is64() { 48 } else { 24 },
            );
            let security = match field(&r, "security", 10) {
                0 => 0,
                1 => 1,
                _ => b + 256,
            };
            let qos = match field(&r, "qos", 10) {
                0 => 0,
                1 => 1,
                _ => b + 512,
            };
            p.space.w32(b + 512, 12).unwrap();
            p.space.w32(b + 516, 2).unwrap();
            p.space
                .wptr(
                    input + if arch.is64() { 32 } else { 16 },
                    arch.ptr_size(),
                    security,
                )
                .unwrap();
            p.space
                .wptr(
                    input + if arch.is64() { 40 } else { 20 },
                    arch.ptr_size(),
                    qos,
                )
                .unwrap();
            let poison = arch.ptr(0xA5A5_A5A5_A5A5_A5A5);
            p.space.wptr(b, arch.ptr_size(), poison).unwrap();
            let expected = field(&r, "status", 16) as u32;
            assert_eq!(
                call(p, &mut t, [b, field(&r, "access", 16), input]),
                expected,
                "row={r:?}"
            );
            assert_eq!(
                crate::user::windows::nt::status_to_error(expected),
                field(&r, "dos", 10) as u32,
                "row={r:?}"
            );
            let h = p.space.ptr(b, arch.ptr_size()).unwrap();
            if expected == 0 {
                assert_eq!(p.objects.get(h).unwrap().type_name(), "Directory");
                p.objects.close(h).unwrap();
            } else {
                assert_eq!(h, field(&r, "output", 16), "row={r:?}");
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 3048);
}
#[test]
fn directory_handles_share_identity_preserve_metadata_after_catalog_drop_and_release() {
    for arch in WinArch::ALL {
        let (mut process, mut t, b) = setup(arch, 3);
        let p = process.state_mut();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let a = opened(p, &mut t, b, "\\KnownDlls", 1);
        let d = opened(p, &mut t, b, "\\knowndlls", 2);
        assert_eq!(p.objects.id(a), p.objects.id(d));
        let Some(Object::Directory(dir)) = p.objects.get(a) else {
            panic!("directory")
        };
        let weak = Arc::downgrade(dir);
        assert_eq!(dir.path, "\\KnownDlls".encode_utf16().collect::<Vec<_>>());
        p.object_namespace = Namespace::default();
        p.objects.close(a | 3).unwrap();
        assert!(weak.upgrade().is_some());
        p.objects.close(d).unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            baseline
        );
    }
}

#[test]
fn native_directory_open_replays_all_288_captured_subject_privilege_rows() {
    const PATHS: [&str; 3] = ["\\", "\\KnownDlls", "\\KnownDlls32"];
    let mut total = 0;
    for (arch, text) in profiles("privilege") {
        let rs = rows(text, "case=");
        assert_eq!(rs.len(), 72);
        assert!(
            text.contains(
                "complete cases=72 token-restored=1 primary-unchanged=1 thread-restored=1"
            )
        );
        let (mut process, mut t, b) = setup(arch, 3);
        let p = process.state_mut();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for r in rs {
            // Each phase represents a distinct captured host subject. No guest
            // token API or replay-time host privilege mutation is implied.
            p.object_namespace = namespace_for_system_security(if field(&r, "phase", 10) == 1 {
                0
            } else {
                STATUS_PRIVILEGE_NOT_HELD
            });
            let name: Vec<_> = PATHS[field(&r, "path", 10) as usize]
                .encode_utf16()
                .collect();
            p.space.put_wunits(b + 128, &name).unwrap();
            descriptor(
                p,
                b + 64,
                b + 128,
                (name.len() * 2) as u16,
                (name.len() * 2) as u16,
            );
            attributes(
                p,
                b + 16,
                b + 64,
                0,
                0x40,
                if arch.is64() { 48 } else { 24 },
            );
            p.space
                .wptr(b, arch.ptr_size(), arch.ptr(0xA5A5_A5A5_A5A5_A5A5))
                .unwrap();
            let expected = field(&r, "status", 16) as u32;
            assert_eq!(
                call(p, &mut t, [b, field(&r, "access", 16), b + 16]),
                expected,
                "row={r:?}"
            );
            assert_eq!(
                crate::user::windows::nt::status_to_error(expected) as u64,
                field(&r, "dos", 10),
                "row={r:?}"
            );
            let h = p.space.ptr(b, arch.ptr_size()).unwrap();
            if expected == 0 {
                assert_eq!(p.objects.access(h), Some(field(&r, "grant", 16) as u32));
                p.objects.close(h).unwrap();
            } else {
                assert_eq!(h, 0);
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 288);
}

#[path = "directory_link_tests.rs"]
mod object_reparse;
