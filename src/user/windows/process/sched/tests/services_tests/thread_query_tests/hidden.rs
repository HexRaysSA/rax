//! Independent native class17 copy, rights, alias and lifetime replay.
use super::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD};

fn rows(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/arm64-hide-query-v2.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/x64-hide-query-v2.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/x86-hide-query-v2.txt"
        )),
    }
}

fn location(p: &mut Proc, base: u64, mode: u64, delta: u64) -> u64 {
    if mode == 1 {
        return 0;
    }
    if mode == 2 {
        return 1;
    }
    let protections = [
        prot::READONLY,
        prot::NOACCESS,
        prot::READWRITE | prot::GUARD,
        prot::READONLY | prot::GUARD,
    ];
    match mode {
        3..=6 => {
            p.vm.protect(base, 4096, protections[(mode - 3) as usize])
                .unwrap();
        }
        8..=11 => {
            p.vm.protect(base + 4096, 4096, protections[(mode - 8) as usize])
                .unwrap();
        }
        0 | 7 => {}
        _ => panic!("unrecognized native location mode"),
    }
    base + 4096 - if mode >= 7 { 1 } else { 16 } + delta
}

#[test]
fn native_thread_hidden_state_replays_2304_live_exited_rights_copy_and_guard_cases() {
    let mut total = 0;
    for arch in WinArch::ALL {
        let (mut process, mut current, _) = setup(arch);
        let p = process.state_mut();
        let out_base =
            p.vm.allocate(None, 24576, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let ret_base = out_base + 12288;
        let mut last_flags = 0;
        let mut worker = 0;
        let mut retired = false;
        let mut handles = [0; 12];
        let mut cases = 0;
        for line in rows(arch).lines().filter(|v| v.starts_with("case ")) {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 18);
            let row: Vec<_> = words[1..16]
                .iter()
                .map(|v| u64::from_str_radix(v, 16).unwrap())
                .collect();
            let [
                index,
                flags,
                life,
                kind,
                length,
                out_mode,
                ret_mode,
                out_delta,
                ret_delta,
                status,
                exception,
                op0,
                op1,
                rp0,
                rp1,
            ] = row[..]
            else {
                unreachable!()
            };
            assert_eq!(index, cases);
            assert_eq!(exception, 0);
            if flags != last_flags {
                if last_flags != 0 {
                    for h in &handles[..4] {
                        p.objects.close(*h).unwrap();
                    }
                }
                worker = thread::create_sized(p, 0x1234_5000, 0, 0, 0, 0, flags as u32).unwrap();
                let object = p.threads[&worker].obj;
                let real = u64::from(p.objects.open(object, false));
                let zero = u64::from(p.objects.open_access(object, false, 0).unwrap());
                let query = u64::from(p.objects.open_access(object, false, 0x40).unwrap());
                let limited = u64::from(p.objects.open_access(object, false, 0x800).unwrap());
                let closed = u64::from(p.objects.open(object, false));
                p.objects.close(closed).unwrap();
                handles = [
                    real,
                    zero,
                    query,
                    limited,
                    arch.ptr(CURRENT_THREAD),
                    arch.ptr(CURRENT_PROCESS),
                    0,
                    0x1234_5678,
                    closed,
                    real | 1,
                    real | 2,
                    real | 3,
                ];
                retired = false;
                last_flags = flags;
            }
            if life == 1 && !retired {
                let t = p.threads.remove(&worker).unwrap();
                thread::destroy(p, t, 0x37);
                retired = true;
            }
            for (base, byte) in [(out_base, 0xcc), (ret_base, 0xdd)] {
                p.vm.protect(base, 12288, prot::READWRITE).unwrap();
                p.space.wr(base, &vec![byte; 12288]).unwrap();
            }
            let out = location(p, out_base, out_mode, out_delta);
            let ret = if ret_mode >= 20 {
                out.checked_add_signed([0, 1, -1, 4][(ret_mode - 20) as usize])
                    .unwrap()
            } else {
                location(p, ret_base, ret_mode, ret_delta)
            };
            let label = format!("{arch}/{index}/flags{flags:#x}/life{life}");
            assert_eq!(
                call(
                    p,
                    &mut current,
                    [handles[kind as usize], 17, out, length, ret]
                ),
                status as u32,
                "{label}"
            );
            let actual = [out_base, out_base + 4096, ret_base, ret_base + 4096]
                .map(|v| u64::from(p.vm.query(v).unwrap().protect));
            assert_eq!(actual, [op0, op1, rp0, rp1], "{label}/guards");
            p.vm.protect(out_base, 12288, prot::READWRITE).unwrap();
            p.vm.protect(ret_base, 12288, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.bytes(out_base + 4096 - 32, 64).unwrap(),
                hex(words[16]),
                "{label}/output"
            );
            assert_eq!(
                p.space.bytes(ret_base + 4096 - 32, 64).unwrap(),
                hex(words[17]),
                "{label}/returned"
            );
            cases += 1;
        }
        for h in &handles[..4] {
            p.objects.close(*h).unwrap();
        }
        assert_eq!(cases, 768);
        total += cases;
    }
    assert_eq!(total, 2304);
}
