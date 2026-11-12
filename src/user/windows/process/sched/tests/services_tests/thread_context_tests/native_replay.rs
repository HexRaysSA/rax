use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::objects::Object;

pub(super) fn corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-context/arm64-native-v21.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-context/x86-native-v21.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-context/x64-native-v21.txt"
        )),
    }
}

pub(super) fn select_native(p: &mut Proc, tid: u32) {
    p.threads.get_mut(&tid).unwrap().attached = true;
    if p.arch == WinArch::X64 {
        let mut native = crate::user::windows::process::native_start::tests::runtime(None);
        native.object_namespace.native_machine = Some(0xaa64);
        native.version.major = 10;
        native.version.build = 29704;
        p.native = Some(native);
        let cpu = &mut p.threads.get_mut(&tid).unwrap().cpu;
        cpu.set_sp(cpu.sp() & !15);
    }
}

#[test]
fn native_thread_context_replays_native_readable_spans_and_alignment() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        select_native(p, tid);
        let object = p.threads[&tid].obj;
        let handle = u64::from(p.objects.open_access(object, false, 24).unwrap());
        let saved = RegContext::capture(&p.threads[&tid].cpu);
        let mut spans = 0;
        let mut alignments = 0;
        for line in corpus(arch).lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            if !matches!(values[2], "00000002" | "00000004") {
                continue;
            }
            let row: Vec<_> = values[1..]
                .iter()
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            let span = row[1] == 4;
            let (operation, group, bytes) = (row[2], if span { row[3] } else { 0 }, row[4]);
            p.vm.protect(scratch, 3 * PAGE_SIZE, prot::READWRITE)
                .unwrap();
            p.space
                .wr(scratch, &vec![0; 3 * PAGE_SIZE as usize])
                .unwrap();
            let address = if span {
                scratch + PAGE_SIZE - u64::from(bytes)
            } else {
                scratch + u64::from(row[3])
            };
            let mut input = saved.clone();
            input.set_flags(RegContext::arch_flag(arch) | group);
            input.write(&p.space, address).unwrap();
            if span {
                p.vm.protect(scratch + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            let name = if operation == 0 {
                "NtGetContextThread"
            } else {
                "NtSetContextThread"
            };
            let expected = row[if span { 5 } else { 4 }];
            let last_error = current.teb + offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7654_3210).unwrap();
            assert_eq!(
                status(p, &mut current, name, &[handle, address]),
                expected,
                "{arch}/{name}/row{}",
                row[0]
            );
            assert_eq!(row[if span { 6 } else { 5 }], 0);
            assert_eq!(
                p.space.u32(last_error).unwrap(),
                row[if span { 7 } else { 6 }]
            );
            if span {
                spans += 1;
            } else {
                alignments += 1;
            }
        }
        assert_eq!(spans, 612);
        assert_eq!(alignments, 32);
        p.vm.protect(scratch, 3 * PAGE_SIZE, prot::READWRITE)
            .unwrap();
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_replays_2160_native_access_type_protection_rows() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let object = p.threads[&tid].obj;
        let mut handles = [0u64; 12];
        for (n, access) in [0, 8, 16, 24, 0x800, 0x1fffff].into_iter().enumerate() {
            handles[n] = u64::from(p.objects.open_access(object, false, access).unwrap());
        }
        let event = p.objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        handles[6] = u64::from(p.objects.open(event, false));
        handles[7] = arch.ptr(u64::MAX - 1);
        handles[8] = arch.ptr(u64::MAX);
        handles[10] = 3;
        handles[11] = u64::from(p.objects.open(object, false));
        p.objects.close(handles[11]).unwrap();
        select_native(p, tid);
        let original = RegContext::capture(&p.threads[&tid].cpu);
        let mut input = original.clone();
        input.set_flags(RegContext::arch_flag(arch));
        let mut count = 0;
        for line in corpus(arch).lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            if values[2] != "00000003" {
                continue;
            }
            let row: Vec<_> = values[1..]
                .iter()
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            let (kind, tag, pointer_case, operation) = (row[2] as usize, row[4], row[5], row[6]);
            p.vm.protect(scratch, 3 * PAGE_SIZE, prot::READWRITE)
                .unwrap();
            p.space
                .wr(scratch, &vec![0xa5; 3 * PAGE_SIZE as usize])
                .unwrap();
            let address = match pointer_case {
                1 => 0,
                2 => 1,
                3 => scratch + 1,
                8 => scratch + PAGE_SIZE - RegContext::size(arch) as u64 + 16,
                9 => scratch + PAGE_SIZE - 64,
                _ => scratch,
            };
            if !matches!(pointer_case, 1 | 2) {
                input.write(&p.space, address).unwrap();
            }
            let protection = match pointer_case {
                4 => prot::NOACCESS,
                5 => prot::READONLY,
                6 => prot::READWRITE | prot::GUARD,
                7 => prot::READONLY | prot::GUARD,
                _ => prot::READWRITE,
            };
            p.vm.protect(scratch, PAGE_SIZE, protection).unwrap();
            if pointer_case >= 8 {
                p.vm.protect(scratch + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            let error = current.teb + offsets(arch).teb_last_error;
            p.space.w32(error, 0x7654_3210).unwrap();
            let name = if operation == 0 {
                "NtGetContextThread"
            } else {
                "NtSetContextThread"
            };
            assert_eq!(
                status(
                    p,
                    &mut current,
                    name,
                    &[handles[kind] | u64::from(tag), address]
                ),
                row[7],
                "{arch}/{name}/row{}",
                row[0]
            );
            assert_eq!(row[8], 0, "native exception is a separate outcome");
            assert_eq!(p.space.u32(error).unwrap(), row[9]);
            assert_eq!(
                p.vm.query(scratch).unwrap().protect,
                row[10],
                "{arch}/row{}",
                row[0]
            );
            assert_eq!(RegContext::capture(&p.threads[&tid].cpu), original);
            count += 1;
        }
        assert_eq!(count, 720);
        p.vm.protect(scratch, 3 * PAGE_SIZE, prot::READWRITE)
            .unwrap();
        for handle in &handles[..7] {
            p.objects.close(*handle).unwrap();
        }
    }
}
