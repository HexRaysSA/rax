//! Extended-alert observations are independent native calls, not generated expectations.
use super::*;

fn corpus_ex(arch: WinArch, kind: u8) -> &'static str {
    match (arch, kind) {
        (WinArch::Arm64, 0) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/arm64-native-ex-v1.txt"
        )),
        (WinArch::X64, 0) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x64-native-ex-v1.txt"
        )),
        (WinArch::X86, 0) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x86-native-ex-v1.txt"
        )),
        (WinArch::Arm64, 1) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/arm64-native-ex-blocked-v2.txt"
        )),
        (WinArch::X64, 1) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x64-native-ex-blocked-v2.txt"
        )),
        (WinArch::X86, 1) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x86-native-ex-blocked-v2.txt"
        )),
        (WinArch::Arm64, 2) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/arm64-native-ex-held-v1.txt"
        )),
        (WinArch::X64, 2) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x64-native-ex-held-v1.txt"
        )),
        (WinArch::X86, 2) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x86-native-ex-held-v1.txt"
        )),
        _ => unreachable!(),
    }
}

fn parse(line: &str, count: usize) -> (Vec<u64>, Vec<u8>) {
    let parts: Vec<_> = line.split_whitespace().skip(1).collect();
    let values = parts[..count]
        .iter()
        .map(|v| u64::from_str_radix(v, 16).unwrap())
        .collect();
    let bytes = if parts.len() == count + 1 {
        let hex = parts[count];
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    } else {
        assert_eq!(parts.len(), count);
        Vec::new()
    };
    (values, bytes)
}

fn extended(p: &mut Proc, t: &mut Thread, tid: u64, hint: u64) -> u32 {
    status(p, t, "NtAlertThreadByThreadIdEx", &[tid, hint])
}

#[test]
fn extended_alert_replays_all_2880_native_pointer_lifetime_and_pending_rows() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let tid = u64::from(t.tid);
        let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
        let object = p.threads[&worker].obj;
        let handle = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
        let zero = data + 12288;
        let last_error = t.teb + offsets(arch).teb_last_error;
        let mut index = 0;
        for line in corpus_ex(arch, 0).lines() {
            if line.starts_with("worker ") {
                let row = fields(line);
                let mut other = p.threads.remove(&worker).unwrap();
                for i in 0..8 {
                    assert_eq!(u64::from(poll(p, &mut other, zero)), row[1 + i]);
                }
                thread::destroy(p, other, row[0] as u32);
            } else if line.starts_with("case ") {
                let (row, snapshot) = parse(line, 15);
                assert_eq!(row[0], index);
                let label = format!("{arch}/extended/{index}");
                assert_eq!(poll(p, &mut t, zero), 0x102);
                p.vm.protect(data, 12288, prot::READWRITE).unwrap();
                p.space.wr(data, &[0; 12288]).unwrap();
                let (mode, delta) = (row[4], row[5]);
                let hint = match mode {
                    0 => 0,
                    2 => 1,
                    9 => arch.ptr(u64::MAX),
                    _ => data + 4096 - if mode == 7 || mode == 8 { 1 } else { 16 } + delta,
                };
                if (3..=6).contains(&mode) {
                    p.vm.protect(
                        data,
                        4096,
                        [
                            prot::READONLY,
                            prot::NOACCESS,
                            prot::READWRITE | prot::GUARD,
                            prot::READONLY | prot::GUARD,
                        ][(mode - 3) as usize],
                    )
                    .unwrap();
                }
                if mode == 8 {
                    p.vm.protect(data + 4096, 4096, prot::NOACCESS).unwrap();
                }
                let target = match row[2] {
                    0 => tid,
                    1 => u64::from(worker),
                    2 => 0,
                    3 => u64::from(p.pid),
                    4 => tid | 1,
                    5 => u64::from(worker) | 1,
                    _ => unreachable!(),
                };
                if row[3] != 0 {
                    assert_eq!(u64::from(alert(p, &mut t, tid)), row[6]);
                }
                p.space.w32(last_error, 0x7654_3210).unwrap();
                assert_eq!(
                    u64::from(extended(p, &mut t, target, hint)),
                    row[7],
                    "{label}/status"
                );
                assert_eq!(row[8], 0);
                assert_eq!(u64::from(p.space.u32(last_error).unwrap()), row[9]);
                for page in 0..2 {
                    assert_eq!(
                        u64::from(p.vm.query(data + page * 4096).unwrap().protect),
                        row[10 + page as usize],
                        "{label}/guard{page}"
                    );
                }
                p.vm.protect(data, 12288, prot::READWRITE).unwrap();
                assert_eq!(
                    p.space.bytes(data + 4096 - 24, 64).unwrap(),
                    snapshot,
                    "{label}/lock storage"
                );
                for i in 0..3 {
                    assert_eq!(
                        u64::from(poll(p, &mut t, zero)),
                        row[12 + i],
                        "{label}/drain{i}"
                    );
                }
                index += 1;
                seen += 1;
            }
        }
        assert_eq!(index, 960);
        p.objects.close(handle).unwrap();
        assert!(p.objects.obj(object).is_none());
    }
    assert_eq!(seen, 2880);
}

#[test]
fn extended_alert_replays_72_native_blocked_hint_rows() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        for line in corpus_ex(arch, 1)
            .lines()
            .filter(|v| v.starts_with("blocked "))
        {
            let (row, snapshot) = parse(line, 12);
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            p.space.wr(data, &[0; 12288]).unwrap();
            let address = match row[0] {
                0 => 0,
                1 => 1,
                2 => data + 128,
                _ => unreachable!(),
            };
            let hint = match row[1] {
                0 => 0,
                1 => data + 128,
                2 => data + 256,
                3 => 1,
                4 => arch.ptr(u64::MAX),
                5..=7 => data + 4096 - 16,
                _ => unreachable!(),
            };
            if row[1] >= 5 {
                p.vm.protect(
                    data,
                    4096,
                    [
                        prot::READWRITE | prot::GUARD,
                        prot::READONLY,
                        prot::NOACCESS,
                    ][(row[1] - 5) as usize],
                )
                .unwrap();
            }
            let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
            let mut target = p.threads.remove(&worker).unwrap();
            assert_eq!(
                call(p, &mut target, "NtWaitForAlertByThreadId", &[address, 0]),
                Outcome::Park
            );
            let wait = waiting(&target);
            p.threads.insert(worker, target);
            let last_error = t.teb + offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7654_3210).unwrap();
            assert_eq!(
                u64::from(extended(p, &mut t, u64::from(worker), hint)),
                row[2]
            );
            assert_eq!(row[3], 0);
            assert_eq!(u64::from(p.space.u32(last_error).unwrap()), row[4]);
            target = p.threads.remove(&worker).unwrap();
            let result = sync::poll(p, worker, &wait, Instant::now(), true)
                .unwrap()
                .unwrap();
            assert_eq!(result, row[5]);
            assert_eq!(row[6], 0);
            assert_eq!(row[7], 5);
            assert_eq!(row[8], if arch == WinArch::X86 { 6 } else { 37 });
            complete(p, &mut target, &wait, result);
            for page in 0..2 {
                assert_eq!(
                    u64::from(p.vm.query(data + page * 4096).unwrap().protect),
                    row[10 + page as usize]
                );
            }
            p.vm.protect(data, 12288, prot::READWRITE).unwrap();
            assert_eq!(p.space.bytes(data + 4096 - 24, 64).unwrap(), snapshot);
            thread::destroy(p, target, 0x38);
            seen += 1;
        }
    }
    assert_eq!(seen, 72);
}

#[test]
fn extended_alert_replays_36_native_held_lock_rows() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        for line in corpus_ex(arch, 2)
            .lines()
            .filter(|v| v.starts_with("held "))
        {
            let (row, _) = parse(line, 14);
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            let width = arch.ptr_size();
            p.space.wptr(data + 128, width, row[10]).unwrap();
            p.space.wptr(data + 256, width, row[12]).unwrap();
            let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
            let mut target = p.threads.remove(&worker).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut target,
                    "NtWaitForAlertByThreadId",
                    &[if row[1] == 0 { 0 } else { data + 128 }, 0]
                ),
                Outcome::Park
            );
            let wait = waiting(&target);
            p.threads.insert(worker, target);
            let hint = match row[2] {
                0 => 0,
                1 => data + 128,
                2 => data + 256,
                _ => unreachable!(),
            };
            let last_error = t.teb + offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7654_3210).unwrap();
            assert_eq!(
                u64::from(extended(p, &mut t, u64::from(worker), hint)),
                row[3]
            );
            assert_eq!(row[4], 0);
            assert_eq!(u64::from(p.space.u32(last_error).unwrap()), row[5]);
            target = p.threads.remove(&worker).unwrap();
            let result = sync::poll(p, worker, &wait, Instant::now(), false)
                .unwrap()
                .unwrap();
            assert_eq!(result, row[6]);
            assert_eq!(row[7], 0);
            assert_eq!(row[8], 5);
            assert_eq!(row[9], if arch == WinArch::X86 { 6 } else { 37 });
            complete(p, &mut target, &wait, result);
            assert_eq!(p.space.ptr(data + 128, width).unwrap(), row[11]);
            assert_eq!(p.space.ptr(data + 256, width).unwrap(), row[13]);
            thread::destroy(p, target, 0x38);
            seen += 1;
        }
    }
    assert_eq!(seen, 36);
}

#[test]
fn extended_alert_builtin_and_raw_share_append_only_two_argument_entry_all_abis() {
    use crate::user::windows::hle::{Arg, Conv, Item};
    for arch in WinArch::ALL {
        let dll = crate::user::windows::dll::find("ntdll.dll").unwrap();
        let family = dll
            .exports
            .iter()
            .find(|table| {
                table
                    .iter()
                    .any(|entry| entry.name == "NtAlertThreadByThreadId")
            })
            .unwrap();
        let exports: Vec<_> = family.iter().filter(|v| v.archs.has(arch)).collect();
        assert_eq!(exports.len(), 3);
        assert_eq!(
            exports
                .iter()
                .rev()
                .take(3)
                .map(|v| v.name)
                .collect::<Vec<_>>(),
            [
                "NtAlertThreadByThreadIdEx",
                "NtWaitForAlertByThreadId",
                "NtAlertThreadByThreadId"
            ]
        );
        let Item::Func(api) = &exports.last().unwrap().item else {
            panic!("extended alert is not a function");
        };
        assert_eq!(api.args, &[Arg::Ptr, Arg::Ptr]);
        assert_eq!(api.conv, Conv::Stdcall);
        let native = crate::user::windows::dll::nt_service(api.name, arch).unwrap();
        assert_eq!(api.name, native.name);
        assert_eq!(api.args, native.args);
        assert_eq!(api.conv, native.conv);
        assert!(std::ptr::fn_addr_eq(api.imp, native.imp));
    }
}
