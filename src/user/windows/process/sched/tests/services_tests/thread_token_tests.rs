//! Original native absent-token captures; present-token rows are contrast oracles.
use super::*;
use crate::user::windows::nt::{error::ERROR_NO_TOKEN, status::*};
use std::collections::HashMap;
#[cfg(windows)]
#[path = "thread_token_leaf_tests.rs"]
mod installed;

#[path = "thread_token_tests/open_ex_29708.rs"]
mod open_ex_29708;

const CAPTURES: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-open-probe-v5-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-open-probe-v5-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-open-probe-v5-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-open-probe-v5-x86-laa.log"
        ),
    ),
];
const PSEUDOS: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-pseudo-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-pseudo-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-pseudo-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-pseudo-x86-laa.log"
        ),
    ),
];
fn fields(line: &str) -> HashMap<&str, &str> {
    line.split_whitespace()
        .filter_map(|x| x.split_once('='))
        .collect()
}
fn number(f: &HashMap<&str, &str>, key: &str, radix: u32) -> u64 {
    u64::from_str_radix(f[key], radix).unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtOpenThreadToken", 0x24);
    let base = process
        .state_mut()
        .vm
        .allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0;
    (process, t, base)
}
fn enter(p: &mut Proc, t: &mut Thread, service: u32, args: [u64; 4]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            for (i, v) in args.into_iter().enumerate() {
                t.cpu.set_gpr(i, v);
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, service as u64);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, v) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2, 8, 9][i], v);
            }
        }
        WinArch::X86 => {
            t.cpu.set_gpr(0, service as u64);
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, v) in args.into_iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, v as u32).unwrap();
            }
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, service))
    };
    if result == Outcome::Continue {
        assert!(t.frames.is_empty());
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert_eq!(t.cpu.pc(), 0x1234_0004);
    }
    t.cpu.set_sp(sp);
    result
}
fn call(p: &mut Proc, t: &mut Thread, args: [u64; 4]) -> u32 {
    assert_eq!(enter(p, t, 0x24, args), Outcome::Continue);
    t.cpu.gpr(0) as u32
}
#[test]
fn native_thread_token_replays_all_6192_absent_token_rows_with_measured_copy_guards_and_no_birth() {
    let mut total = 0;
    for (arch, log) in CAPTURES {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let mut targets = vec![arch.ptr(u64::MAX - 1), 0, arch.ptr(u64::MAX), 0x1234];
        for grant in [0, 0x40, 0x800, 0x840, 0x1fffff, 0x20, 0x100000] {
            targets.push(p.objects.open_access(t.obj, false, grant).unwrap().into());
        }
        targets.push(
            p.objects
                .insert(Object::Event {
                    manual: true,
                    signaled: 0,
                })
                .into(),
        );
        let proc = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        targets.push(p.objects.open_access(proc, false, 0x200).unwrap().into());
        targets.push(targets[8] | 3);
        let other = p.objects.create(Object::Thread {
            tid: 0x44,
            exit_code: None,
        });
        for grant in [0x1fffff, 0x40, 0x800, 0] {
            targets.push(p.objects.open_access(other, false, grant).unwrap().into());
        }
        targets.push(
            p.objects
                .insert(Object::Thread {
                    tid: 0x48,
                    exit_code: Some(66),
                })
                .into(),
        );
        // The extended mature producer explicitly passed zero-extended 32-bit
        // negative values on native64; the separate pseudo producer covers
        // the distinct full-width signed handles as well.
        for n in 3..=7 {
            targets.push(u64::from(0u32.wrapping_sub(n)));
        }
        assert_eq!(targets.len(), 24);
        let handles = p.objects.handle_count();
        let mut count = 0;
        for line in log.lines().filter(|x| x.starts_with("case=")) {
            let f = fields(line);
            if f["state"] != "0" {
                continue;
            }
            assert_eq!(number(&f, "width", 10), arch.ptr_size());
            assert_eq!(number(&f, "exception", 16), 0);
            assert_eq!(f["exact-token-and-input-handles"], "1");
            assert_eq!(f["births"], "0");
            p.vm.protect(base, 8192, prot::READWRITE).unwrap();
            p.space.wr(base, &vec![0xa5; 8192]).unwrap();
            let mode = number(&f, "buffer", 10);
            let out = match mode {
                0 => base + 128,
                1 => 0,
                2 => 1,
                3 => base + 129,
                4 => base + 132,
                5 => base + 136,
                6..=9 => base + 4096,
                10..=13 => base + 4092,
                14 => base + 4096 - arch.ptr_size(),
                15 => arch.ptr(u64::MAX) - 7,
                16 => base + 4094,
                17 => base + 4095,
                _ => panic!("buffer selector"),
            };
            let flags = match mode {
                6 | 12 => prot::READONLY,
                7 | 10 => prot::NOACCESS,
                8 | 11 => prot::READWRITE | prot::GUARD,
                9 | 13 => prot::READONLY | prot::GUARD,
                _ => prot::READWRITE,
            };
            p.vm.protect(base + 4096, 4096, flags).unwrap();
            let status = call(
                p,
                &mut t,
                [
                    targets[number(&f, "thread", 10) as usize],
                    number(&f, "access", 16),
                    number(&f, "as-self", 10),
                    out,
                ],
            );
            assert_eq!(status, number(&f, "status", 16) as u32, "{arch} {line}");
            for (page, flag) in f["protection"].trim_end_matches(',').split(',').enumerate() {
                assert_eq!(
                    p.vm.query(base + page as u64 * 4096).unwrap().protect,
                    u32::from_str_radix(flag, 16).unwrap(),
                    "{arch} {line}"
                );
            }
            p.vm.protect(base, 8192, prot::READWRITE).unwrap();
            for (name, at) in [("bytes0", 112), ("bytes1", 4064)] {
                assert_eq!(
                    p.space.bytes(base + at, 64).unwrap(),
                    bytes(f[name]),
                    "{arch} {line}"
                );
            }
            assert_eq!(p.objects.handle_count(), handles);
            count += 1;
            total += 1;
        }
        assert_eq!(count, 1548);
    }
    assert_eq!(total, 6192);
}
#[test]
fn native_thread_token_negative_pseudo_handles_and_rtl_translation_match_all_native_profiles() {
    let mut total = 0;
    for (arch, log) in PSEUDOS {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        let header = fields(log.lines().next().unwrap());
        assert_eq!(number(&header, "width", 10), arch.ptr_size());
        assert_eq!(
            crate::user::windows::nt::status_to_error(STATUS_NO_TOKEN),
            number(&header, "rtl-status-no-token-error", 10) as u32
        );
        assert_eq!(
            crate::user::windows::nt::status_to_error(STATUS_NO_TOKEN),
            ERROR_NO_TOKEN
        );
        let mut count = 0;
        for line in log.lines().filter(|x| x.starts_with("case=")) {
            let f = fields(line);
            if f["state"] != "0" {
                continue;
            }
            p.space.wr(out, &vec![0xa5; 16]).unwrap();
            let status = call(
                p,
                &mut t,
                [
                    number(&f, "input-thread", 16),
                    0x2001c,
                    number(&f, "as-self", 10),
                    out,
                ],
            );
            assert_eq!(status, number(&f, "status", 16) as u32, "{arch} {line}");
            let mut expected = vec![0xa5; 16];
            expected[..arch.ptr_size() as usize].copy_from_slice(
                &number(&f, "output-after", 16).to_le_bytes()[..arch.ptr_size() as usize],
            );
            assert_eq!(p.space.bytes(out, 16).unwrap(), expected);
            count += 1;
            total += 1;
        }
        assert_eq!(count, 20);
    }
    assert_eq!(total, 80);
}
#[test]
fn native_thread_token_profile_refuses_unimplemented_impersonation_attachment_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtSetInformationThread", 0x0d);
        let p = process.state_mut();
        let outcome = enter(
            p,
            &mut t,
            0x0d,
            [arch.ptr(u64::MAX - 1), 5, 0, arch.ptr_size()],
        );
        let Outcome::Fail(message) = outcome else {
            panic!("unsupported token attachment admitted: {outcome:?}")
        };
        assert!(
            message.contains("NtSetInformationThread class 5"),
            "{message}"
        );
    }
}

const BOUNDARIES: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-boundary-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-boundary-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-boundary-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-thread-token-open/native-thread-token-boundary-x86-laa.log"
        ),
    ),
];
#[test]
fn native_thread_token_cross_page_copy_faults_match_all_96_original_rows() {
    let mut total = 0;
    for (arch, log) in BOUNDARIES {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let mut count = 0;
        for line in log.lines().filter(|x| x.starts_with("case=")) {
            let f = fields(line);
            assert_eq!(number(&f, "case", 10), count);
            assert_eq!(number(&f, "width", 10), arch.ptr_size());
            assert_eq!(number(&f, "exception", 16), 0);
            p.vm.protect(base, 8192, prot::READWRITE).unwrap();
            p.space.wr(base, &vec![0xa5; 8192]).unwrap();
            let flags = [
                prot::READONLY,
                prot::NOACCESS,
                prot::READWRITE | prot::GUARD,
                prot::READONLY | prot::GUARD,
            ][number(&f, "page", 10) as usize];
            p.vm.protect(base + 4096, 4096, flags).unwrap();
            let thread = if number(&f, "thread", 10) == 0 {
                arch.ptr(u64::MAX - 1)
            } else {
                0
            };
            let status = call(
                p,
                &mut t,
                [thread, 0x2001c, 0, base + number(&f, "offset", 10)],
            );
            assert_eq!(status, number(&f, "status", 16) as u32, "{arch} {line}");
            assert_eq!(
                p.vm.query(base + 4096).unwrap().protect,
                number(&f, "protection", 16) as u32,
                "{arch} {line}"
            );
            p.vm.protect(base, 8192, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.bytes(base + 4088, 16).unwrap(),
                bytes(f["bytes"]),
                "{arch} {line}"
            );
            count += 1;
            total += 1;
        }
        assert_eq!(count, 24);
    }
    assert_eq!(total, 96);
}
