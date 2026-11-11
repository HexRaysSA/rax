//! Independent class26 capture replay, including destination publication and guards.
use super::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

fn corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/arm64-boundary-native-v2.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x64-boundary-native-v2.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x86-boundary-native-v2.txt"
        )),
    }
}

fn order_corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/arm64-order-native-v3.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x64-order-native-v3.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x86-order-native-v3.txt"
        )),
    }
}

fn short_corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/arm64-short-native-v4.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x64-short-native-v4.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x86-short-native-v4.txt"
        )),
    }
}
fn overflow_corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/arm64-overflow-native-v5.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x64-overflow-native-v5.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-teb/x86-overflow-native-v5.txt"
        )),
    }
}

fn location(base: u64, mode: u64, delta: u64) -> u64 {
    match mode {
        1 => 0,
        2 => 1,
        _ => base + 4096 - if mode >= 7 { 1 } else { 32 } + delta,
    }
}

fn protection(p: &mut Proc, base: u64, mode: u64) {
    let values = [
        prot::READONLY,
        prot::NOACCESS,
        prot::READWRITE | prot::GUARD,
        prot::READONLY | prot::GUARD,
    ];
    if (3..=6).contains(&mode) {
        p.vm.protect(base, 4096, values[(mode - 3) as usize])
            .unwrap();
    } else if (8..=11).contains(&mode) {
        p.vm.protect(base + 4096, 4096, values[(mode - 8) as usize])
            .unwrap();
    }
}

fn replay(corpus: fn(WinArch) -> &'static str, expected: u64) {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut current, _) = setup(arch);
        let p = process.state_mut();
        let bases: Vec<_> = (0..3)
            .map(|_| {
                p.vm.allocate(None, 12288, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0
            })
            .collect();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        p.threads.get_mut(&tid).unwrap().suspend = 1;
        let object = p.threads[&tid].obj;
        let teb = p.threads[&tid].teb;
        let mut handles = [0; 18];
        handles[0] = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
        for (i, rights) in [0, 8, 0x10, 0x18, 0x40, 0x58].into_iter().enumerate() {
            handles[i + 1] = u64::from(p.objects.open_access(object, false, rights).unwrap());
        }
        handles[7] = arch.ptr(CURRENT_THREAD);
        handles[8] = arch.ptr(CURRENT_PROCESS);
        handles[10] = 0x1234_5678;
        // The observer closes this slot before opening the 0x800 alias. The
        // kernel immediately recycles it; this is a live reduced-rights alias,
        // not an invalid-handle observation. Model its observed identity.
        handles[15] = u64::from(p.objects.open_access(object, false, 0x800).unwrap());
        handles[11] = handles[15];
        for tag in 1..=3 {
            handles[11 + tag] = handles[0] | tag as u64;
        }
        let event = p.objects.create(Object::Event {
            manual: false,
            signaled: 0,
        });
        for (i, rights) in [0, 1].into_iter().enumerate() {
            handles[16 + i] = u64::from(p.objects.open_access(event, false, rights).unwrap());
        }
        let mut retired = false;
        let width = arch.ptr_size() as usize;
        let mut count = 0;
        for line in corpus(arch)
            .lines()
            .filter(|line| line.starts_with("case "))
        {
            let fields: Vec<_> = line.split_whitespace().skip(1).collect();
            assert_eq!(fields.len(), 25);
            let row: Vec<_> = fields[..20]
                .iter()
                .map(|v| u64::from_str_radix(v, 16).unwrap())
                .collect();
            assert_eq!(row[0], count);
            assert_eq!(row[13], 0, "native query caught all faults as status");
            let label = format!("{arch}/case{count}/{:?}", &row[..14]);
            if row[2] == 1 && !retired {
                let target = p.threads.remove(&tid).unwrap();
                thread::destroy(p, target, 0x37);
                retired = true;
            }
            for (base, byte) in bases.iter().zip([0xa5, 0xcc, 0xdd]) {
                p.vm.protect(*base, 12288, prot::READWRITE).unwrap();
                p.space.wr(*base, &vec![byte; 12288]).unwrap();
            }
            let record = location(bases[0], row[6], row[9]);
            let output = if row[7] >= 20 {
                bases[0] + 4096 - 32 + (row[7] - 20) * 4
            } else {
                location(bases[1], row[7], row[10])
            };
            let returned = if row[8] >= 20 {
                bases[usize::from(row[8] >= 24)] + 4096 - 32 + (row[8] - 20) % 4 * 4
            } else {
                location(bases[2], row[8], row[11])
            };
            if !matches!(row[6], 1 | 2) {
                p.space.wptr(record, width as u64, output).unwrap();
                p.space.w32(record + width as u64, row[3] as u32).unwrap();
                p.space
                    .w32(record + width as u64 + 4, row[4] as u32)
                    .unwrap();
            }
            let before = p.space.bytes(bases[0] + 4096 - 48, 64).unwrap();
            // Native TEBs contain host addresses/IDs. Seed their captured source
            // bytes only for a reached successful copy, then restore the owned
            // guest TEB before teardown. This tests the exact native bytes and
            // frontier without importing host handles into the object model.
            let source = if row[1] == 7 { current.teb } else { teb } + row[3];
            let saved = if row[12] == 0 {
                let saved = p.space.bytes(source, 64).unwrap();
                p.space.wr(source, &hex(fields[24])).unwrap();
                Some(saved)
            } else {
                None
            };
            for i in 0..3 {
                if row[6 + i] < 20 {
                    protection(p, bases[i], row[6 + i]);
                }
            }
            let status = call(
                p,
                &mut current,
                [handles[row[1] as usize], 26, record, row[5], returned],
            );
            assert_eq!(u64::from(status), row[12], "{label}/status");
            if let Some(saved) = saved {
                p.space.wr(source, &saved).unwrap();
            }
            for (i, base) in bases.iter().enumerate() {
                for page in 0..2 {
                    assert_eq!(
                        u64::from(p.vm.query(*base + page * 4096).unwrap().protect),
                        row[14 + i * 2 + page as usize],
                        "{label}/guard{i}/{page}"
                    );
                }
                p.vm.protect(*base, 12288, prot::READWRITE).unwrap();
            }
            let native_before = hex(fields[20]);
            let mut expected_record = hex(fields[21]);
            // Relocate only untouched descriptor-pointer bytes. Successful
            // alias copies and ReturnLength stores have independently captured
            // values and must remain literal, even if one byte coincides.
            if !matches!(row[6], 1 | 2) {
                let pointer_start = (record - (bases[0] + 4096 - 48)) as usize;
                for at in pointer_start..pointer_start + width {
                    let address = bases[0] + 4096 - 48 + at as u64;
                    let overwritten = status == 0
                        && ((row[7] >= 20 && (output..output + row[4]).contains(&address))
                            || (row[8] >= 20
                                && row[8] < 24
                                && (returned..returned + 4).contains(&address)));
                    if !overwritten {
                        assert_eq!(
                            expected_record[at], native_before[at],
                            "{label}/pointer preserved"
                        );
                        expected_record[at] = before[at];
                    }
                }
            }
            for (i, expected) in [expected_record, hex(fields[22]), hex(fields[23])]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    p.space.bytes(bases[i] + 4096 - 48, expected.len()).unwrap(),
                    expected,
                    "{label}/buffer{i}"
                );
            }
            count += 1;
            seen += 1;
        }
        assert_eq!(count, expected);
        if !retired {
            let t = p.threads.remove(&tid).unwrap();
            thread::destroy(p, t, 0x37);
        }
        for i in [0, 1, 2, 3, 4, 5, 6, 15, 16, 17] {
            p.objects.close(handles[i]).unwrap();
        }
        assert!(p.objects.obj(object).is_none());
    }
    assert_eq!(seen, expected * 3);
}

#[test]
fn native_thread_teb_replays_2934_bounds_rights_lifetime_alias_and_guard_cases() {
    replay(corpus, 978);
}

#[test]
fn native_thread_teb_replays_4842_combined_fault_and_range_precedence_cases() {
    replay(order_corpus, 1614);
}

#[test]
fn native_thread_teb_replays_2880_short_descriptor_alignment_precedence_cases() {
    replay(short_corpus, 960);
}

#[test]
fn native_thread_teb_replays_891_wow64_offset_conversion_overflow_cases() {
    replay(overflow_corpus, 297);
}
