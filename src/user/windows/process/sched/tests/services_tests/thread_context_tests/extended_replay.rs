use super::native_replay::{corpus, select_native};
use super::*;

fn frame(p: &mut Proc, address: u64, mask: u64) -> u64 {
    let arch = p.arch;
    assert_ne!(arch, WinArch::Arm64);
    let size = RegContext::size(arch) as u64;
    let offset = if arch == WinArch::X86 { 52 } else { 48 };
    p.space.wr(address, &vec![0; 2048]).unwrap();
    p.space
        .w32(
            address + if arch == WinArch::X64 { 48 } else { 0 },
            RegContext::arch_flag(arch) | 64,
        )
        .unwrap();
    let ex = address + size;
    p.space.w32(ex, (-(size as i32)) as u32).unwrap();
    p.space.w32(ex + 4, (size + offset + 320) as u32).unwrap();
    p.space.w32(ex + 8, (-(size as i32)) as u32).unwrap();
    p.space
        .w32(ex + 12, if arch == WinArch::X86 { 204 } else { 1232 })
        .unwrap();
    p.space.w32(ex + 16, offset as u32).unwrap();
    p.space.w32(ex + 20, 320).unwrap();
    let state = ex + offset;
    p.space.w64(state, mask).unwrap();
    state
}

#[test]
fn native_thread_context_replays_48_native_extended_chunk_metadata_cases() {
    for arch in [WinArch::X86, WinArch::X64] {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        select_native(p, tid);
        let handle = u64::from(
            p.objects
                .open_access(p.threads[&tid].obj, false, 24)
                .unwrap(),
        );
        let before = RegContext::capture(&p.threads[&tid].cpu);
        let mut count = 0;
        for line in corpus(arch).lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            if values[2] != "00000010" {
                continue;
            }
            let row: Vec<_> = values[1..]
                .iter()
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            frame(p, scratch, 0);
            p.space
                .w32(
                    scratch + RegContext::size(arch) as u64 + if row[2] == 0 { 16 } else { 20 },
                    row[3],
                )
                .unwrap();
            assert_eq!(
                status(p, &mut current, "NtGetContextThread", &[handle, scratch]),
                row[4],
                "{arch}/metadata field{}/value{:#x}",
                row[2],
                row[3]
            );
            assert_eq!(row[5], 0);
            assert_eq!(RegContext::capture(&p.threads[&tid].cpu), before);
            count += 1;
        }
        assert_eq!(count, 24);
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_ymm_selection_preserves_unselected_guest_registers() {
    // Architectural state and API readback only. Native WoW64 resume after a
    // nonzero YMM setter fails independently on the qualified host profile.
    for arch in [WinArch::X86, WinArch::X64] {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        select_native(p, tid);
        let handle = u64::from(
            p.objects
                .open_access(p.threads[&tid].obj, false, 24)
                .unwrap(),
        );
        let marker = [[0x1122_3344_5566_7788, 0x8877_6655_4433_2211]; 16];
        p.threads
            .get_mut(&tid)
            .unwrap()
            .cpu
            .x86_mut()
            .unwrap()
            .vcpu_mut()
            .user_regs_mut()
            .ymm_high = marker;
        let control = RegContext::capture(&p.threads[&tid].cpu);
        let state = frame(p, scratch, 4);
        p.space.wr(state + 64, &[0x3c; 256]).unwrap();
        assert_eq!(
            status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
            0
        );
        assert_eq!(RegContext::capture(&p.threads[&tid].cpu), control);
        let values = p.threads[&tid]
            .cpu
            .x86()
            .unwrap()
            .vcpu()
            .user_regs()
            .ymm_high;
        let count = if arch == WinArch::X86 { 8 } else { 16 };
        assert_eq!(&values[..count], &[[0x3c3c_3c3c_3c3c_3c3c; 2]; 16][..count]);
        assert_eq!(&values[count..], &marker[count..]);
        frame(p, scratch, 4);
        p.space.wr(state + 64, &[0xa5; 256]).unwrap();
        assert_eq!(
            status(p, &mut current, "NtGetContextThread", &[handle, scratch]),
            0
        );
        assert_eq!(p.space.u64(state).unwrap(), 4);
        assert_eq!(
            p.space.bytes(state + 64, count * 16).unwrap(),
            vec![0x3c; count * 16]
        );
        assert_eq!(
            p.space
                .bytes(state + 64 + (count * 16) as u64, 256 - count * 16)
                .unwrap(),
            vec![0xa5; 256 - count * 16]
        );
        let unchanged = values;
        frame(p, scratch, 0);
        p.space.wr(state + 64, &[0; 256]).unwrap();
        assert_eq!(
            status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
            0
        );
        assert_eq!(
            p.threads[&tid]
                .cpu
                .x86()
                .unwrap()
                .vcpu()
                .user_regs()
                .ymm_high,
            unchanged
        );
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_legacy_fp_preserves_native_context_vector_aliases() {
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
    let mut marker = [[0x1122_3344_5566_7788, 0x8877_6655_4433_2211]; 16];
    let native_vector = 0x6162_6364_6566_6768_7172_7374_7576_7778;
    let cpu = &mut p.threads.get_mut(&tid).unwrap().cpu;
    cpu.x86_mut().unwrap().vcpu_mut().user_regs_mut().ymm_high = marker;
    let mut native = cpu.arm64_kernel_context().unwrap();
    native.set_flags(0x0040_0004);
    native.set_v(31, native_vector);
    cpu.apply_kernel_context(&native).unwrap();
    marker[15] = [native_vector as u64, (native_vector >> 64) as u64];
    assert_eq!(cpu.kernel_ymm_high().unwrap(), marker);
    let mut legacy = RegContext::capture(cpu);
    legacy.set_flags(0x0010_0008);
    legacy.write(&p.space, scratch).unwrap();
    assert_eq!(
        status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
        0
    );
    let cpu = &p.threads[&tid].cpu;
    assert_eq!(cpu.kernel_ymm_high().unwrap(), marker);
    assert_eq!(cpu.arm64_kernel_context().unwrap().v(31), native_vector);
    let state = frame(p, scratch, 4);
    p.space.wr(state + 64, &[0x5a; 256]).unwrap();
    assert_eq!(
        status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
        0
    );
    let cpu = &p.threads[&tid].cpu;
    assert_eq!(
        cpu.kernel_ymm_high().unwrap(),
        [[0x5a5a_5a5a_5a5a_5a5a; 2]; 16]
    );
    assert_eq!(
        cpu.arm64_kernel_context().unwrap().v(31),
        0x5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a
    );
    p.objects.close(handle).unwrap();
}

#[test]
fn native_thread_context_partial_updates_keep_owned_target_and_caller_execution_modes() {
    for native_mode in [false, true] {
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
        let cpu = &mut p.threads.get_mut(&tid).unwrap().cpu;
        if native_mode {
            let mut native = cpu.arm64_kernel_context().unwrap();
            native.set_flags(0x0040_0001);
            cpu.apply_kernel_context(&native).unwrap();
        }
        let instruction_arch = if native_mode {
            WinArch::Arm64
        } else {
            WinArch::X64
        };
        for group in [2, 8, 16, 64] {
            if group == 64 {
                frame(p, scratch, 4);
            } else {
                let mut selected = RegContext::capture(&p.threads[&tid].cpu);
                selected.set_flags(0x0010_0000 | group);
                selected.write(&p.space, scratch).unwrap();
            }
            assert_eq!(
                status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
                0,
                "target group{group:#x}"
            );
            assert_eq!(
                p.threads[&tid].cpu.instruction_arch(),
                instruction_arch,
                "target group{group:#x}"
            );
        }
        for group in [2, 8, 16, 64] {
            if group == 64 {
                frame(p, scratch, 4);
            } else {
                let mut selected = RegContext::capture(&current.cpu);
                selected.set_flags(0x0010_0000 | group);
                selected.write(&p.space, scratch).unwrap();
            }
            assert_eq!(
                status(
                    p,
                    &mut current,
                    "NtSetContextThread",
                    &[u64::MAX - 1, scratch]
                ),
                0,
                "caller group{group:#x}"
            );
            assert_eq!(
                current.cpu.instruction_arch(),
                WinArch::X64,
                "caller group{group:#x}"
            );
        }
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_self_resume_commits_fp_and_extended_vectors_together() {
    let arch = WinArch::X64;
    let (mut process, mut current, scratch) = setup(arch);
    let p = process.state_mut();
    let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
    select_native(p, tid);
    current.cpu.set_sp(current.cpu.sp() & !15);
    frame(p, scratch, 4);
    let mut legacy = RegContext::capture(&current.cpu);
    legacy.set_flags(0x0010_004b);
    legacy.set_pc(0x1234_0004);
    legacy.write(&p.space, scratch).unwrap();
    let state = scratch + 1280;
    p.space.wr(state + 64, &[0x6d; 256]).unwrap();
    assert_eq!(
        super::super::event_tests::call(
            p,
            &mut current,
            "NtSetContextThread",
            &[u64::MAX - 1, scratch]
        ),
        Outcome::Continue
    );
    assert_eq!(
        current.cpu.kernel_ymm_high().unwrap(),
        [[0x6d6d_6d6d_6d6d_6d6d; 2]; 16]
    );
    for n in 16..32 {
        assert_eq!(
            current.cpu.arm64_kernel_context().unwrap().v(n),
            0x6d6d_6d6d_6d6d_6d6d_6d6d_6d6d_6d6d_6d6d
        );
    }
}
