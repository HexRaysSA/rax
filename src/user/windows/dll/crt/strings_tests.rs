use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, Item, Value};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::process::{Thread, WindowsConfig, WindowsProcess};

fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::new("crt-strings-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let t = p.threads.remove(&tid).unwrap();
    (process, t)
}

fn api(name: &str) -> &'static Api {
    STRING_EXPORTS
        .iter()
        .chain(UCRT_STRING_EXPORTS)
        .find_map(|e| match &e.item {
            Item::Func(a) if a.name == name => Some(a),
            _ => None,
        })
        .unwrap()
}

fn invoke(c: &mut Ctx, name: &str, values: &[u64]) -> ApiResult {
    c.api = api(name);
    assert_eq!(c.api.conv, Cdecl);
    for (i, &value) in values.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => {
                c.p.space
                    .w32(c.entry_sp + 4 + 4 * i as u64, value as u32)
                    .unwrap()
            }
            WinArch::X64 => c.t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::Arm64 => c.t.cpu.set_gpr(i, value),
        }
    }
    (c.api.imp)(c)
}

fn int(result: ApiResult) -> u64 {
    match result.unwrap() {
        Flow::Ret(Value::Int(v)) => v,
        _ => panic!("expected integer result"),
    }
}

fn fault(result: ApiResult) -> MemFault {
    match result {
        Err(ApiErr::Fault(f)) => f,
        _ => panic!("expected checked guest fault"),
    }
}

fn area(c: &mut Ctx, bytes: u64) -> u64 {
    c.p.vm
        .allocate(None, bytes, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

fn run(mut check: impl FnMut(&mut Ctx)) {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p: process.state_mut(),
            t: &mut t,
            api: api("strlen"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        c.set_last_error(0x1234).unwrap();
        check(&mut c);
        assert_eq!(c.last_error().unwrap(), 0x1234);
    }
}

#[test]
fn lengths_end_page_nul_and_bounded_unterminated_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let narrow = a + PAGE_SIZE - 4;
        c.mem().wr(narrow, b"abc\0").unwrap();
        assert_eq!(int(invoke(c, "strlen", &[narrow])), 3);
        assert_eq!(int(invoke(c, "strnlen", &[narrow, 2])), 2);
        assert_eq!(int(invoke(c, "strnlen", &[narrow, 100])), 3);
        let wide = a + PAGE_SIZE - 6;
        c.mem().put_wunits(wide, &[0xD800, 0xDC00, 0]).unwrap();
        assert_eq!(int(invoke(c, "wcslen", &[wide])), 2);
        assert_eq!(int(invoke(c, "wcsnlen", &[wide, 1])), 1);
        assert_eq!(int(invoke(c, "wcsnlen", &[wide, 100])), 2);
    });
}

#[test]
fn unbounded_missing_terminator_faults_without_truncated_success_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        c.mem().wr(a + PAGE_SIZE - 2, &[1, 1]).unwrap();
        assert_eq!(
            fault(invoke(c, "strlen", &[a + PAGE_SIZE - 2])).addr,
            a + PAGE_SIZE
        );
        assert_eq!(
            fault(invoke(c, "wcslen", &[a + PAGE_SIZE - 2])).addr,
            a + PAGE_SIZE
        );
        assert_eq!(int(invoke(c, "strnlen", &[a + PAGE_SIZE - 2, 2])), 2);
        assert_eq!(int(invoke(c, "wcsnlen", &[a + PAGE_SIZE - 2, 1])), 1);
    });
}

#[test]
fn ordinal_unsigned_compare_stops_at_nul_or_difference_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, PAGE_SIZE);
        c.mem().wr(a, &[0xFF, 0]).unwrap();
        c.mem().wr(b, &[0x7F, 0]).unwrap();
        assert!((int(invoke(c, "strcmp", &[a, b])) as i32) > 0);
        assert!((int(invoke(c, "strncmp", &[b, a, 1])) as i32) < 0);
        c.mem().put_wunits(a, &[0xD800, 0]).unwrap();
        c.mem().put_wunits(b, &[0x7FFF, 0]).unwrap();
        assert!((int(invoke(c, "wcscmp", &[a, b])) as i32) > 0);
        assert!((int(invoke(c, "wcsncmp", &[b, a, 1])) as i32) < 0);
        let end = a + PAGE_SIZE - 2;
        c.mem().put_wunits(end, &[0]).unwrap();
        let max = c.arch().ptr(u64::MAX);
        assert_eq!(int(invoke(c, "wcsncmp", &[end, end, max])), 0);
        c.mem().w8(end + 1, 0).unwrap();
        assert_eq!(int(invoke(c, "strncmp", &[end + 1, end + 1, max])), 0);
    });
}

#[test]
fn copy_padding_and_exact_count_without_extra_nul_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, PAGE_SIZE);
        c.mem().put_cstr(a, b"abc").unwrap();
        assert_eq!(int(invoke(c, "strcpy", &[b, a])), b);
        assert_eq!(c.mem().bytes(b, 4).unwrap(), b"abc\0");
        c.mem().wr(b, &[0x77; 6]).unwrap();
        assert_eq!(int(invoke(c, "strncpy", &[b, a, 3])), b);
        assert_eq!(c.mem().bytes(b, 4).unwrap(), b"abc\x77");
        assert_eq!(int(invoke(c, "strncpy", &[b, a, 6])), b);
        assert_eq!(c.mem().bytes(b, 6).unwrap(), b"abc\0\0\0");
        c.mem().put_wunits(a, &[0xD800, 0, 0xDC00]).unwrap();
        assert_eq!(int(invoke(c, "wcscpy", &[b, a])), b);
        assert_eq!(c.mem().wunits(b, 2).unwrap(), [0xD800, 0]);
        c.mem().put_wunits(b, &[0x7777; 4]).unwrap();
        assert_eq!(int(invoke(c, "wcsncpy", &[b, a, 1])), b);
        assert_eq!(c.mem().wunits(b, 2).unwrap(), [0xD800, 0x7777]);
        assert_eq!(int(invoke(c, "wcsncpy", &[b, a, 4])), b);
        assert_eq!(c.mem().wunits(b, 4).unwrap(), [0xD800, 0, 0, 0]);
    });
}

#[test]
fn append_bounded_source_and_terminator_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, PAGE_SIZE);
        c.mem().put_cstr(a, b"ab").unwrap();
        c.mem().put_cstr(b, b"cdef").unwrap();
        assert_eq!(int(invoke(c, "strncat", &[a, b, 2])), a);
        assert_eq!(c.mem().bytes(a, 5).unwrap(), b"abcd\0");
        assert_eq!(int(invoke(c, "strcat", &[a, b])), a);
        assert_eq!(c.mem().bytes(a, 9).unwrap(), b"abcdcdef\0");
        c.mem().put_wunits(a, &[0xD800, 0]).unwrap();
        c.mem().put_wunits(b, &[0xDC00, 0xFFFF, 0]).unwrap();
        assert_eq!(int(invoke(c, "wcsncat", &[a, b, 1])), a);
        assert_eq!(c.mem().wunits(a, 3).unwrap(), [0xD800, 0xDC00, 0]);
        assert_eq!(int(invoke(c, "wcscat", &[a, b])), a);
        assert_eq!(
            c.mem().wunits(a, 5).unwrap(),
            [0xD800, 0xDC00, 0xDC00, 0xFFFF, 0]
        );
    });
}

#[test]
fn character_and_substring_search_includes_terminator_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, PAGE_SIZE);
        c.mem().put_cstr(a, b"ababa").unwrap();
        c.mem().put_cstr(b, b"aba").unwrap();
        assert_eq!(int(invoke(c, "strchr", &[a, b'b' as u64])), a + 1);
        assert_eq!(int(invoke(c, "strrchr", &[a, b'a' as u64])), a + 4);
        assert_eq!(int(invoke(c, "strchr", &[a, 0])), a + 5);
        assert_eq!(int(invoke(c, "strrchr", &[a, 0])), a + 5);
        assert_eq!(int(invoke(c, "strstr", &[a, b])), a);
        c.mem().put_cstr(b, b"bab").unwrap();
        assert_eq!(int(invoke(c, "strstr", &[a, b])), a + 1);
        c.mem().put_cstr(b, b"ac").unwrap();
        assert_eq!(int(invoke(c, "strstr", &[a, b])), 0);
        c.mem().put_wunits(a, &[0xD800, 0xDC00, 0xD800, 0]).unwrap();
        c.mem().put_wunits(b, &[0xDC00, 0xD800, 0]).unwrap();
        assert_eq!(int(invoke(c, "wcschr", &[a, 0xD800])), a);
        assert_eq!(int(invoke(c, "wcsrchr", &[a, 0xD800])), a + 4);
        assert_eq!(int(invoke(c, "wcschr", &[a, 0])), a + 6);
        assert_eq!(int(invoke(c, "wcsrchr", &[a, 0])), a + 6);
        assert_eq!(int(invoke(c, "wcsstr", &[a, b])), a + 2);
        c.mem().put_wunits(b, &[0xFFFF, 0]).unwrap();
        assert_eq!(int(invoke(c, "wcsstr", &[a, b])), 0);
    });
}

#[test]
fn zero_bound_and_empty_needle_are_explicit_no_dereference_profiles_all_abis() {
    run(|c| {
        let max = c.arch().ptr(u64::MAX);
        for name in ["strnlen", "wcsnlen", "strncmp", "wcsncmp"] {
            let args = if name.ends_with("len") {
                vec![max, 0]
            } else {
                vec![max, 0, 0]
            };
            assert_eq!(int(invoke(c, name, &args)), 0);
        }
        // Microsoft strncpy's invalid-parameter paragraph conflicts with its
        // char* return contract. This zero-count behavior is the RAX profile.
        for name in ["strncpy", "wcsncpy"] {
            assert_eq!(int(invoke(c, name, &[max, 0, 0])), max);
        }
        let a = area(c, PAGE_SIZE);
        c.mem().w16(a, 0).unwrap();
        for name in ["strstr", "wcsstr"] {
            assert_eq!(int(invoke(c, name, &[max, a])), max);
        }
        c.mem().put_cstr(a, b"abc").unwrap();
        assert_eq!(int(invoke(c, "strncat", &[a, max, 0])), a);
        assert_eq!(c.mem().bytes(a, 4).unwrap(), b"abc\0");
        c.mem().put_wunits(a, &[0xD800, 0]).unwrap();
        assert_eq!(int(invoke(c, "wcsncat", &[a, max, 0])), a);
        assert_eq!(c.mem().wunits(a, 2).unwrap(), [0xD800, 0]);
    });
}

#[test]
fn late_string_fault_leaves_only_streamed_prefix_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, 2 * PAGE_SIZE);
        c.mem().put_cstr(a, b"abcd").unwrap();
        c.p.vm
            .protect(b + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        let dest = b + PAGE_SIZE - 2;
        let f = fault(invoke(c, "strcpy", &[dest, a]));
        assert!(f.write);
        assert_eq!(f.addr, b + PAGE_SIZE);
        assert_eq!(c.mem().bytes(dest, 4).unwrap(), [b'a', b'b', 0, 0]);
        c.mem().put_wunits(a, &[0xD800, 0xDC00, 0]).unwrap();
        let f = fault(invoke(c, "wcscpy", &[dest, a]));
        assert!(f.write);
        assert_eq!(c.mem().u16(dest).unwrap(), 0xD800);
        let max = c.arch().ptr(u64::MAX);
        let f = fault(invoke(c, "strncpy", &[dest, a, max]));
        assert!(f.write);
    });
}

#[test]
fn hostile_null_guard_and_guest_width_overflow_remain_faults_all_abis() {
    run(|c| {
        assert_eq!(fault(invoke(c, "strlen", &[0])).addr, 0);
        assert_eq!(fault(invoke(c, "wcslen", &[0])).addr, 0);
        let a = area(c, PAGE_SIZE);
        c.mem().wr(a, b"ab\0").unwrap();
        c.p.vm
            .protect(a, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        let f = fault(invoke(c, "strlen", &[a]));
        assert!(!f.write);
        assert_eq!(f.addr, a);
        assert_ne!(c.p.vm.query(a).unwrap().protect & prot::GUARD, 0);
        let max = c.arch().ptr(u64::MAX);
        assert!(!fault(invoke(c, "wcslen", &[max])).write);
        assert!(matches!(
            address(c, max, 1, 1, true),
            Err(ApiErr::Fault(MemFault { write: true, .. }))
        ));
        assert!(matches!(
            string_len(c, a, 0, None),
            Err(ApiErr::Internal(_))
        ));
    });
}

#[test]
fn long_scanner_has_no_legacy_64k_cutoff_all_abis() {
    run(|c| {
        let a = area(c, 0x11000);
        let chunk = [b'x'; 256];
        for offset in (0..0x10001).step_by(256) {
            c.mem().wr(a + offset, &chunk).unwrap();
        }
        c.mem().w8(a + 0x10001, 0).unwrap();
        assert_eq!(int(invoke(c, "strlen", &[a])), 0x10001);
    });
}
