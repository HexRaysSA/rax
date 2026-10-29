//! Native timeout faults, handle priority, guard effects and signal consumption.
use super::event_tests::setup;
use super::native_wait_tests::invoke;
use super::*;
use crate::host::time::Instant;
use crate::user::windows::hle::dispatch;
use crate::user::windows::object_namespace::reparse_tests;
use crate::user::windows::sync;

macro_rules! rows {
    ($profile:literal) => {
        include_str!(concat!(
            "../../../../../../../docs/specifications/windows/native-single-wait/replay/single-",
            $profile,
            ".tsv"
        ))
    };
}

fn prepare(p: &mut Proc, base: u64, mode: u32) -> u64 {
    p.vm.protect(base, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
    p.space.wr(base, &vec![0; 2 * PAGE_SIZE as usize]).unwrap();
    if (4..=7).contains(&mode) {
        p.vm.protect(
            base + PAGE_SIZE,
            PAGE_SIZE,
            [
                prot::READONLY,
                prot::NOACCESS,
                prot::READWRITE | prot::GUARD,
                prot::READONLY | prot::GUARD,
            ][(mode - 4) as usize],
        )
        .unwrap();
    }
    match mode {
        0 => base + 32,
        1 => base + 33,
        2 => base + PAGE_SIZE - 4,
        3 => base + PAGE_SIZE - 1,
        4..=7 => base + PAGE_SIZE,
        8 => 0,
        9 => 1,
        _ => unreachable!(),
    }
}

fn object(p: &mut Proc, kind: u32) -> (u64, Option<u32>, Vec<u64>) {
    let value = match kind {
        0 | 1 | 4 => Object::Event {
            manual: kind != 0,
            signaled: 1,
        },
        2 => Object::Mutex {
            owner: None,
            count: 0,
            abandoned: false,
        },
        3 => Object::Semaphore { count: 1, max: 3 },
        5 => {
            let name: Vec<_> = "\\BaseNamedObjects".encode_utf16().collect();
            let directory = p.object_namespace.lookup(None, &name, 0).unwrap();
            let handle = u64::from(p.objects.open_directory(directory, false, 1).unwrap());
            return (handle, None, vec![handle]);
        }
        6 => return (0x1234, None, Vec::new()),
        7 => return (0, None, Vec::new()),
        _ => unreachable!(),
    };
    let id = p.objects.create(value);
    let full = u64::from(
        p.objects
            .open_access(id, false, if kind == 2 { 0x1F0001 } else { 0x1F0003 })
            .unwrap(),
    );
    if kind == 4 {
        let zero = u64::from(p.objects.open_access(id, false, 0).unwrap());
        (zero, Some(id), vec![zero, full])
    } else {
        (full, Some(id), vec![full])
    }
}

fn state(p: &Proc, t: &Thread, id: Option<u32>) -> String {
    let Some(id) = id else { return "none".into() };
    let mut bytes = [0xA5; 16];
    match p.objects.obj(id).unwrap() {
        Object::Event { manual, signaled } => {
            bytes[..4].copy_from_slice(&u32::from(!manual).to_le_bytes());
            bytes[4..8].copy_from_slice(&signaled.to_le_bytes());
        }
        Object::Mutex {
            owner,
            count,
            abandoned,
        } => {
            bytes[..4].copy_from_slice(&1u32.wrapping_sub(*count).to_le_bytes());
            bytes[4] = u8::from(*owner == Some(t.tid));
            bytes[5] = u8::from(*abandoned);
        }
        Object::Semaphore { count, max } => {
            bytes[..4].copy_from_slice(&count.to_le_bytes());
            bytes[4..8].copy_from_slice(&max.to_le_bytes());
        }
        _ => unreachable!(),
    }
    let mut result = "00000000/00000008/".to_owned();
    for byte in bytes {
        result.push_str(&format!("{byte:02X}"));
    }
    result
}

#[test]
fn native_single_wait_replays_all_2240_fault_access_guard_and_object_state_rows() {
    for (arch, profile, rows) in [
        (WinArch::Arm64, "arm64", rows!("arm64")),
        (WinArch::X64, "x64", rows!("x64")),
        (WinArch::X86, "x86", rows!("x86")),
        (WinArch::X86, "x86-laa", rows!("x86-laa")),
    ] {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        p.object_namespace = reparse_tests::sample(0);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let mut cases = 0;
        for line in rows.lines() {
            let row: Vec<_> = line.split('\t').collect();
            assert_eq!(row.len(), 8);
            assert_eq!(row[0].parse::<usize>().unwrap(), cases);
            let (handle, id, close) = object(p, row[1].parse().unwrap());
            let timeout = prepare(p, data, row[3].parse().unwrap());
            assert_eq!(state(p, &t, id), row[6]);
            let sp = t.cpu.sp();
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    handle,
                    u32::from_str_radix(row[2], 16).unwrap(),
                    timeout
                ),
                Outcome::Continue,
                "{profile} case{cases}"
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from_str_radix(row[4], 16).unwrap(),
                "{profile} case{cases}"
            );
            assert_eq!(
                p.vm.query(data + PAGE_SIZE).unwrap().protect,
                u32::from_str_radix(row[5], 16).unwrap()
            );
            assert_eq!(state(p, &t, id), row[7], "{profile} case{cases}");
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert!(t.frames.is_empty());
            t.cpu.set_sp(sp);
            for handle in close {
                p.objects.close(handle).unwrap();
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            cases += 1;
        }
        assert_eq!(cases, 560);
    }
}

macro_rules! apc_rows {
    ($profile:literal) => {
        include_str!(concat!(
            "../../../../../../../docs/specifications/windows/native-single-wait/replay/object-apc-",
            $profile,
            ".tsv"
        ))
    };
}

#[test]
fn native_single_wait_replays_all_336_object_access_apc_and_recursion_rows() {
    for (arch, profile, rows) in [
        (WinArch::Arm64, "arm64", apc_rows!("arm64")),
        (WinArch::X64, "x64", apc_rows!("x64")),
        (WinArch::X86, "x86", apc_rows!("x86")),
        (WinArch::X86, "x86-laa", apc_rows!("x86-laa")),
    ] {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        p.object_namespace = reparse_tests::sample(0);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        p.space.w64(data, 0).unwrap();
        let mut cases = 0;
        for line in rows.lines() {
            let row: Vec<_> = line.split('\t').collect();
            assert_eq!(row.len(), 7);
            assert_eq!(row[0].parse::<usize>().unwrap(), cases);
            let kind: u32 = row[1].parse().unwrap();
            let actual_kind = match kind {
                8 => 2,
                9 => 3,
                10 => 0,
                11 => 1,
                other => other,
            };
            let (handle, id, close) = object(p, actual_kind);
            let sp = t.cpu.sp();
            if (8..=10).contains(&kind) {
                assert_eq!(invoke(p, &mut t, handle, 0, data), Outcome::Continue);
                assert_eq!(t.cpu.gpr(0), 0);
                t.cpu.set_sp(sp);
            } else if kind == 11 {
                let Some(Object::Event { signaled, .. }) = id.and_then(|id| p.objects.obj_mut(id))
                else {
                    unreachable!()
                };
                *signaled = 0;
            }
            assert_eq!(state(p, &t, id), row[4], "{profile} case{cases}");
            assert!(t.apcs.is_empty());
            t.apcs.push_back((0x50000, 0x1111).into());
            let result = invoke(
                p,
                &mut t,
                handle,
                u32::from_str_radix(row[2], 16).unwrap(),
                data,
            );
            let delivered = row[6] == "1";
            if delivered {
                assert_eq!(result, Outcome::Park, "{profile} case{cases}");
                let ThreadState::Waiting(wait) = &t.state else {
                    unreachable!()
                };
                let wait = wait.clone();
                let status = sync::poll(p, t.tid, &wait, Instant::now(), true)
                    .unwrap()
                    .unwrap();
                assert_eq!(status, sync::WAIT_IO_COMPLETION);
                sync::on_cancel(p, t.tid, &wait).unwrap();
                t.state = ThreadState::Ready;
                assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
                assert_eq!(t.frames.len(), 2);
                assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
                assert_eq!(t.wait_status.take(), Some(status));
                assert_eq!(
                    dispatch::wait_complete(p, &mut t, status),
                    Outcome::Continue
                );
                assert!(t.apcs.is_empty());
            } else {
                assert_eq!(result, Outcome::Continue, "{profile} case{cases}");
                assert_eq!(
                    t.apcs.len(),
                    1,
                    "invalid/denied and nonalertable calls leave the APC queued"
                );
                t.apcs.clear();
            }
            assert_eq!(
                t.cpu.gpr(0),
                u64::from_str_radix(row[3], 16).unwrap(),
                "{profile} case{cases}"
            );
            assert_eq!(state(p, &t, id), row[5], "{profile} case{cases}");
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert!(t.frames.is_empty());
            t.cpu.set_sp(sp);
            for handle in close {
                p.objects.close(handle).unwrap();
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            cases += 1;
        }
        assert_eq!(cases, 84);
    }
}
