use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, Item, Value};
use crate::user::windows::memory::{mem, prot};
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
    let mut config = WindowsConfig::new("crt-memory-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let t = p.threads.remove(&tid).unwrap();
    (process, t)
}

fn api(name: &str) -> &'static Api {
    MEMORY_EXPORTS
        .iter()
        .chain(WIDE_HELPER_APIS)
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
            api: api("memcpy"),
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
fn buffer_copy_fill_and_comparison_all_abis() {
    run(|c| {
        let a = area(c, 3 * PAGE_SIZE);
        let b = area(c, 3 * PAGE_SIZE);
        let data: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
        c.mem().wr(a + PAGE_SIZE - 7, &data).unwrap();
        assert_eq!(
            int(invoke(
                c,
                "memcpy",
                &[b + PAGE_SIZE - 11, a + PAGE_SIZE - 7, 513]
            )),
            b + PAGE_SIZE - 11
        );
        assert_eq!(c.mem().bytes(b + PAGE_SIZE - 11, 513).unwrap(), data);
        assert_eq!(
            int(invoke(
                c,
                "memcmp",
                &[b + PAGE_SIZE - 11, a + PAGE_SIZE - 7, 513]
            )),
            0
        );
        assert_eq!(int(invoke(c, "memset", &[b, 0x1AB, 513])), b);
        assert_eq!(c.mem().bytes(b, 513).unwrap(), vec![0xAB; 513]);
        assert_eq!(int(invoke(c, "memchr", &[b, 0xFFFFFFAB, 513])), b);
        assert_eq!(int(invoke(c, "memchr", &[b, 0xAA, 513])), 0);
    });
}

#[test]
fn memmove_overlap_in_both_directions_and_identical_all_abis() {
    run(|c| {
        let a = area(c, 3 * PAGE_SIZE);
        let data: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
        let at = a + PAGE_SIZE - 400;
        for (to, from) in [(at + 3, at), (at, at + 3), (at, at)] {
            c.mem().wr(at, &data).unwrap();
            let expected = c.mem().bytes(from, 600).unwrap();
            assert_eq!(int(invoke(c, "memmove", &[to, from, 600])), to);
            assert_eq!(c.mem().bytes(to, 600).unwrap(), expected);
        }
    });
}

#[test]
fn wide_buffers_preserve_raw_units_and_unsigned_order_all_abis() {
    run(|c| {
        let a = area(c, 2 * PAGE_SIZE);
        let b = area(c, 2 * PAGE_SIZE);
        let data = [0xD800, 0xFFFF, 0xDC00, 0, 0x1234];
        c.mem().put_wunits(a + PAGE_SIZE - 3, &data).unwrap();
        assert_eq!(
            int(invoke(
                c,
                "wmemcpy",
                &[b + PAGE_SIZE - 1, a + PAGE_SIZE - 3, 5]
            )),
            b + PAGE_SIZE - 1
        );
        assert_eq!(c.mem().wunits(b + PAGE_SIZE - 1, 5).unwrap(), data);
        assert_eq!(
            int(invoke(
                c,
                "wmemcmp",
                &[b + PAGE_SIZE - 1, a + PAGE_SIZE - 3, 5]
            )),
            0
        );
        assert_eq!(
            int(invoke(c, "wmemchr", &[b + PAGE_SIZE - 1, 0xFFFF, 5])),
            b + PAGE_SIZE + 1
        );
        assert_eq!(int(invoke(c, "wmemset", &[b, 0x1234D800, 3])), b);
        assert_eq!(c.mem().wunits(b, 3).unwrap(), [0xD800; 3]);
        c.mem().w16(a, 0x7FFF).unwrap();
        assert!((int(invoke(c, "wmemcmp", &[b, a, 1])) as i32) > 0);
        c.mem().put_wunits(a, &data).unwrap();
        assert_eq!(int(invoke(c, "wmemmove", &[a + 2, a, 5])), a + 2);
        assert_eq!(c.mem().wunits(a + 2, 5).unwrap(), data);
        assert_eq!(int(invoke(c, "wmemmove", &[a, a + 2, 5])), a);
        assert_eq!(c.mem().wunits(a, 5).unwrap(), data);
    });
}

#[test]
fn zero_count_no_dereference_is_explicit_personality_profile_all_abis() {
    run(|c| {
        let max = c.arch().ptr(u64::MAX);
        for name in ["memcpy", "memmove", "wmemcpy", "wmemmove"] {
            assert_eq!(int(invoke(c, name, &[max, 0, 0])), max);
        }
        for name in ["memset", "wmemset"] {
            assert_eq!(int(invoke(c, name, &[max, 0, 0])), max);
        }
        for name in ["memcmp", "wmemcmp", "memchr", "wmemchr"] {
            assert_eq!(int(invoke(c, name, &[max, 0, 0])), 0);
        }
    });
}

#[test]
fn source_and_destination_faults_precede_buffer_writes_all_abis() {
    run(|c| {
        let a = area(c, 2 * PAGE_SIZE);
        let b = area(c, 2 * PAGE_SIZE);
        c.mem().wr(a, &[7; 20]).unwrap();
        c.mem().wr(b, &[9; 20]).unwrap();
        c.p.vm
            .protect(a + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let f = fault(invoke(c, "memcpy", &[b, a + PAGE_SIZE - 10, 20]));
        assert!(!f.write);
        assert_eq!(f.addr, a + PAGE_SIZE);
        assert_eq!(c.mem().bytes(b, 20).unwrap(), [9; 20]);
        c.p.vm.protect(b, PAGE_SIZE, prot::READONLY).unwrap();
        let f = fault(invoke(c, "memmove", &[b, a, 20]));
        assert!(f.write);
        assert_eq!(c.mem().bytes(b, 20).unwrap(), [9; 20]);
        assert!(fault(invoke(c, "memset", &[b, 1, 20])).write);
        c.p.vm
            .protect(a, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        let f = fault(invoke(c, "memcpy", &[b + PAGE_SIZE, a, 1]));
        assert!(!f.write);
        assert_eq!(f.addr, a);
        // Guard consumption belongs to the common HLE dispatcher, not to CRT.
        assert_ne!(c.p.vm.query(a).unwrap().protect & prot::GUARD, 0);
    });
}

#[test]
fn guest_width_overflow_and_size_max_fail_without_allocating_count_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let max = c.arch().ptr(u64::MAX);
        assert!(!fault(invoke(c, "memcpy", &[a, max - 1, 4])).write);
        assert!(fault(invoke(c, "memset", &[max - 1, 0, 4])).write);
        assert!(!fault(invoke(c, "memcpy", &[a, a, max])).write);
        assert!(!fault(invoke(c, "wmemcpy", &[a, a, max])).write);
        assert!(fault(invoke(c, "wmemset", &[a, 0, max])).write);
    });
}

#[test]
fn unsigned_byte_compare_and_search_stop_before_unneeded_fault_all_abis() {
    run(|c| {
        let a = area(c, PAGE_SIZE);
        let b = area(c, PAGE_SIZE);
        let left = a + PAGE_SIZE - 1;
        let right = b + PAGE_SIZE - 1;
        c.mem().w8(left, 0xFF).unwrap();
        c.mem().w8(right, 0x7F).unwrap();
        let max = c.arch().ptr(u64::MAX);
        assert!((int(invoke(c, "memcmp", &[left, right, max])) as i32) > 0);
        assert_eq!(int(invoke(c, "memchr", &[left, 0xFF, max])), left);
        assert!(!fault(invoke(c, "memchr", &[left, 0, 2])).write);
    });
}
