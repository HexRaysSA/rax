use super::native_replay::{corpus, select_native};
use super::*;

#[test]
fn native_thread_context_replays_316_native_debug_register_cases() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        select_native(p, tid);
        let object = p.threads[&tid].obj;
        let handle = u64::from(p.objects.open_access(object, false, 24).unwrap());
        let original = p.threads[&tid].cpu.new_thread();
        let saved = RegContext::capture(&original);
        let (offset, size, flag) = match arch {
            WinArch::Arm64 => (792, 120, 8),
            WinArch::X86 => (4, 24, 16),
            WinArch::X64 => (72, 48, 16),
        };
        let width = arch.ptr_size() as usize;
        let mut count = 0;
        for line in corpus(arch).lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            if !matches!(values[2], "00000005" | "00000008" | "00000009" | "0000000a") {
                continue;
            }
            let row: Vec<_> = values[1..]
                .iter()
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            p.threads.get_mut(&tid).unwrap().cpu = original.new_thread();
            let mut bytes = saved.bytes().to_vec();
            bytes[offset..offset + size].fill(0);
            let mut put32 = |at: usize, value: u32| {
                bytes[offset + at..offset + at + 4].copy_from_slice(&value.to_le_bytes())
            };
            if row[1] == 5 {
                for at in (0..size).step_by(4) {
                    put32(at, row[2]);
                }
            } else if arch == WinArch::Arm64 {
                let value = u64::from(row[2])
                    | if row[1] == 9 {
                        u64::from(row[3]) << 32
                    } else {
                        0
                    };
                for n in 0..8 {
                    put32(n * 4, if row[1] == 9 { 1 } else { row[2] });
                    let address = if row[1] == 9 {
                        value
                    } else {
                        0x1234_5000 + n as u64 * 256
                    };
                    put32(32 + n * 8, address as u32);
                    put32(36 + n * 8, (address >> 32) as u32);
                }
                for n in 0..2 {
                    put32(96 + n * 4, if row[1] == 9 { 1 } else { row[2] });
                    let address = if row[1] == 9 {
                        value
                    } else {
                        0x1234_6000 + n as u64 * 256
                    };
                    put32(104 + n * 8, address as u32);
                    put32(108 + n * 8, (address >> 32) as u32);
                }
            } else {
                for n in 0..4 {
                    put32(
                        n * width,
                        if row[1] == 9 {
                            row[2]
                        } else {
                            0x1234_5000 + n as u32 * 256
                        },
                    );
                    if width == 8 && row[1] == 9 {
                        put32(n * width + 4, row[3]);
                    }
                }
                if row[1] == 8 {
                    put32(4 * width, 0x9abc_def0);
                    if width == 8 {
                        put32(4 * width + 4, 0x1234_5678);
                    }
                }
                put32(5 * width, if row[1] == 9 { 0x55 } else { row[2] });
            }
            let mut input = RegContext::from_bytes(arch, bytes);
            input.set_flags(RegContext::arch_flag(arch) | flag);
            input.write(&p.space, scratch).unwrap();
            let index = if row[1] == 9 { 4 } else { 3 };
            assert_eq!(
                status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
                row[index],
                "{arch}/set/row{}",
                row[0]
            );
            assert_eq!(row[index + 1], 0);
            let output = scratch + PAGE_SIZE;
            p.space.wr(output, &vec![0; 2048]).unwrap();
            p.space
                .w32(
                    output + if arch == WinArch::X64 { 48 } else { 0 },
                    RegContext::arch_flag(arch) | flag,
                )
                .unwrap();
            assert_eq!(
                status(p, &mut current, "NtGetContextThread", &[handle, output]),
                row[index + 3],
                "{arch}/get/row{}",
                row[0]
            );
            assert_eq!(row[index + 4], 0);
            assert_eq!(
                p.space
                    .u32(output + if arch == WinArch::X64 { 48 } else { 0 })
                    .unwrap(),
                row[index + 6]
            );
            for n in 0..size / 4 {
                assert_eq!(
                    p.space.u32(output + (offset + n * 4) as u64).unwrap(),
                    row[index + 7 + n],
                    "{arch}/debug DWORD{n}/row{}",
                    row[0]
                );
            }
            count += 1;
        }
        assert_eq!(count, if arch == WinArch::Arm64 { 52 } else { 132 });
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_replays_bidirectional_amd64_debug_context_aliases() {
    let arch = WinArch::X64;
    let (mut process, mut current, scratch) = setup(arch);
    let p = process.state_mut();
    let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
    select_native(p, tid);
    let handle = u64::from(
        p.objects
            .open_access(p.threads[&tid].obj, false, 24)
            .unwrap(),
    );
    p.space.wr(scratch, &vec![0; 1232]).unwrap();
    p.space.w32(scratch + 48, 0x0010_0010).unwrap();
    for (n, value) in [
        0x1234_5000,
        0x1234_5100,
        0x1234_5200,
        0x1234_5300,
        0x1234,
        0x55,
    ]
    .into_iter()
    .enumerate()
    {
        p.space.w64(scratch + 72 + n as u64 * 8, value).unwrap();
    }
    assert_eq!(
        status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
        0
    );
    let mut native = p.threads[&tid]
        .cpu
        .kernel_debug_context(WinArch::Arm64)
        .unwrap();
    for n in 0..8 {
        assert_eq!(
            u32::from_le_bytes(native[n * 4..n * 4 + 4].try_into().unwrap()),
            if n < 4 { 0x1e5 } else { 4 }
        );
    }
    assert_eq!(
        u64::from_le_bytes(native[64..72].try_into().unwrap()),
        0x1234
    );
    native[32..40].copy_from_slice(&0x2345_6000u64.to_le_bytes());
    native[64..72].copy_from_slice(&0xabcdu64.to_le_bytes());
    let limit = p.vm.high();
    p.threads
        .get_mut(&tid)
        .unwrap()
        .cpu
        .apply_kernel_debug_context(WinArch::Arm64, &native, limit)
        .unwrap();
    p.space.w32(scratch + 48, 0x0010_0010).unwrap();
    assert_eq!(
        status(p, &mut current, "NtGetContextThread", &[handle, scratch]),
        0
    );
    assert_eq!(p.space.u64(scratch + 72).unwrap(), 0x2345_6000);
    assert_eq!(p.space.u64(scratch + 104).unwrap(), 0xffff_affd);
    assert_eq!(p.space.u64(scratch + 112).unwrap(), 0x455);
    p.objects.close(handle).unwrap();
}
