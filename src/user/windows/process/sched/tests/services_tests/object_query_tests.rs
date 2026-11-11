//! Replay independent native query results through the actual service transport.
use super::file_open_tests::Harness;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::{Mem, prot};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::Proc;

fn rows(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-object-handle-flags/arm64-native-v1.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-object-handle-flags/x64-native-v1.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-object-handle-flags/x86-native-v1.txt"
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
        _ => panic!("unknown native location mode {mode}"),
    }
    base + 4096 - if mode >= 7 { 1 } else { 16 } + delta
}

fn decode_bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len(), 128);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn native_object_handle_flags_replay_all_852_status_copy_guard_and_alias_cases() {
    let mut total = 0;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let p = h.process.state_mut();
        let event = p.objects.create(Object::Event {
            manual: false,
            signaled: 0,
        });
        let real = u64::from(p.objects.open(event, false));
        let zero_access = u64::from(p.objects.open_access(event, false, 0).unwrap());
        let process = p
            .objects
            .iter()
            .find_map(|(id, object)| {
                matches!(object, Object::Process { pid, .. } if *pid == p.pid).then_some(id)
            })
            .unwrap();
        let thread = p
            .objects
            .iter()
            .find_map(|(id, object)| matches!(object, Object::Thread { .. }).then_some(id))
            .unwrap();
        let process_handle = u64::from(p.objects.open(process, false));
        let thread_handle = u64::from(p.objects.open(thread, false));
        let closed = u64::from(p.objects.open(event, false));
        p.objects.close(closed).unwrap();
        let handles = [
            real,
            zero_access,
            process_handle,
            thread_handle,
            closed,
            0,
            0x1234_5678,
            arch.ptr(CURRENT_PROCESS),
            arch.ptr(CURRENT_THREAD),
            arch.ptr(u64::MAX - 2),
            arch.ptr(u64::MAX - 3),
            arch.ptr(u64::MAX - 4),
            arch.ptr(u64::MAX - 5),
            real | 1,
            real | 2,
            real | 3,
        ];
        let count = p.objects.handle_count();
        let out_base = h.base;
        let ret_base = out_base + 3 * 4096;
        let mut cases = 0;
        for line in rows(arch).lines().filter(|line| line.starts_with("case ")) {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 18);
            let row: Vec<_> = words[1..16]
                .iter()
                .map(|s| u64::from_str_radix(s, 16).unwrap())
                .collect();
            let [
                index,
                kind,
                flags,
                class,
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
            assert_eq!(exception, 0, "native query must return an NTSTATUS");
            let p = h.process.state_mut();
            for (base, byte) in [(out_base, 0xcc), (ret_base, 0xdd)] {
                p.vm.protect(base, 12288, prot::READWRITE).unwrap();
                p.space.wr(base, &vec![byte; 12288]).unwrap();
            }
            assert!(p.objects.set_flags(real, 3, flags as u32));
            let out = location(p, out_base, out_mode, out_delta);
            let ret = if ret_mode >= 20 {
                out.checked_add_signed([0, 1, -1, 4][(ret_mode - 20) as usize])
                    .unwrap()
            } else {
                location(p, ret_base, ret_mode, ret_delta)
            };
            let label = format!("{arch}/case{index}");
            assert_eq!(
                h.invoke_api(
                    "NtQueryObject",
                    &[handles[kind as usize], class, out, length, ret]
                ),
                status as u32,
                "{label}"
            );
            let p = h.process.state_mut();
            let protections = [out_base, out_base + 4096, ret_base, ret_base + 4096]
                .map(|base| u64::from(p.vm.query(base).unwrap().protect));
            assert_eq!(
                protections,
                [op0, op1, rp0, rp1],
                "{label}/guard visitation"
            );
            p.vm.protect(out_base, 12288, prot::READWRITE).unwrap();
            p.vm.protect(ret_base, 12288, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.bytes(out_base + 4096 - 32, 64).unwrap(),
                decode_bytes(words[16]),
                "{label}/output"
            );
            assert_eq!(
                p.space.bytes(ret_base + 4096 - 32, 64).unwrap(),
                decode_bytes(words[17]),
                "{label}/ReturnLength"
            );
            assert_eq!(
                p.objects.flags(real),
                Some(flags as u32),
                "{label}/read-only handle state"
            );
            assert_eq!(
                p.objects.flags(zero_access),
                Some(0),
                "{label}/per-handle flags"
            );
            assert_eq!(p.objects.access(zero_access), Some(0));
            assert_eq!(p.objects.handle_count(), count);
            cases += 1;
        }
        assert_eq!(cases, 284);
        assert!(h.process.state_mut().objects.set_flags(real, 3, 0));
        total += cases;
    }
    assert_eq!(total, 852);
}

#[test]
fn object_handle_query_builtin_and_raw_service_share_one_abi_and_preserve_last_error() {
    use super::{Outcome, dispatch, fixture};
    use crate::user::windows::hle::{Arg, Conv, Item};
    use crate::user::windows::{dll, layout};
    for arch in WinArch::ALL {
        let exports: Vec<_> = dll::find("ntdll.dll")
            .unwrap()
            .exports
            .iter()
            .flat_map(|family| family.iter())
            .filter(|e| e.archs.has(arch))
            .collect();
        let selected: Vec<_> = exports
            .iter()
            .enumerate()
            .filter(|(_, e)| e.name == "NtQueryObject")
            .collect();
        assert_eq!(selected.len(), 1);
        let prior = exports
            .iter()
            .position(|e| e.name == "NtFlushProcessWriteBuffers")
            .unwrap();
        assert_eq!(
            selected[0].0,
            prior + 1,
            "append without shifting prior exports"
        );
        let Item::Func(api) = &selected[0].1.item else {
            panic!("function export")
        };
        let raw = dll::nt_service("NtQueryObject", arch).unwrap();
        assert_eq!(raw.name, api.name);
        assert_eq!(raw.conv, api.conv);
        assert_eq!(raw.args, api.args);
        assert_eq!(api.conv, Conv::Stdcall);
        assert_eq!(api.args, [Arg::Ptr, Arg::I32, Arg::Ptr, Arg::I32, Arg::Ptr]);
        let (mut process, mut t) = fixture(arch, "NtQueryObject", 0x10);
        let p = process.state_mut();
        let handle = u64::from(p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        }));
        assert!(p.objects.set_flags(handle, 3, 3));
        let sp = t.cpu.sp();
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x5a17_0042).unwrap();
        let out = sp - 128;
        let returned = out + 16;
        p.space.wr(out, &[0xa5; 32]).unwrap();
        for (index, argument) in [handle, 4, out, 2, returned].into_iter().enumerate() {
            match arch {
                WinArch::X86 => p
                    .space
                    .w32(sp + 4 + index as u64 * 4, argument as u32)
                    .unwrap(),
                WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], argument),
                WinArch::X64 => p.space.w64(sp + 0x28, argument).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(index, argument),
            }
        }
        const RETURN: u64 = 0x1234_0004;
        if arch == WinArch::Arm64 {
            t.cpu.set_gpr(30, RETURN);
        } else {
            p.space.wptr(sp, arch.ptr_size(), RETURN).unwrap();
        }
        assert_eq!(
            dispatch::enter(p, &mut t, api, 0x1234_0000),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(t.cpu.pc(), RETURN);
        assert_eq!(
            t.cpu.sp(),
            sp + if arch == WinArch::Arm64 {
                0
            } else if arch == WinArch::X86 {
                24
            } else {
                8
            }
        );
        assert_eq!(p.space.u16(out).unwrap(), 0x0101);
        assert_eq!(p.space.u32(returned).unwrap(), 2);
        assert_eq!(p.space.u32(last_error).unwrap(), 0x5a17_0042);
        assert!(t.frames.is_empty());
    }
}
