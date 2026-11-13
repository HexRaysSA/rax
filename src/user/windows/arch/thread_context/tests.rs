use super::*;

#[test]
fn native_amd64_instruction_breakpoint_executes_and_reports_the_native_debug_bank() {
    use crate::user::mm::{Mapping, PAGE_SIZE, Perms, SpaceConfig};
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: crate::user::cpu::x86_64::RESERVED_PHYS.to_vec(),
    })
    .unwrap();
    space
        .map(
            0x10000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::EXEC),
        )
        .unwrap();
    space.write_raw(0x10000, &[0x90, 0x90]).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_pc(0x10000);
    let mut debug = vec![0; 120];
    debug[..4].copy_from_slice(&0x1e5u32.to_le_bytes());
    debug[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
    cpu.apply_kernel_debug_context(WinArch::Arm64, &debug, 1 << 47)
        .unwrap();
    assert!(
        matches!(cpu.run(1), CpuStop::X86Event(event) if event.vector == 1 && event.return_rip == 0x10000)
    );
    assert_eq!(cpu.pc(), 0x10000);
    let status = cpu.kernel_debug_context(WinArch::Arm64).unwrap();
    assert_eq!(
        u64::from_le_bytes(status[64..72].try_into().unwrap()) & 15,
        1
    );
    debug[..4].fill(0);
    cpu.apply_kernel_debug_context(WinArch::Arm64, &debug, 1 << 47)
        .unwrap();
    assert!(matches!(cpu.run(1), CpuStop::Yield));
    assert_eq!(cpu.pc(), 0x10001);
}

#[test]
fn native_partial_context_restore_preserves_unselected_debug_banks() {
    use crate::user::windows::context::{CONTEXT_ARM64, RegContext};
    for selected in [0, 1, 2, 4, 16] {
        let space = super::super::tests::space();
        let mut cpu = WinCpu::new(WinArch::X64, &space);
        cpu.set_pc(0x10000);
        cpu.set_sp(0x20f00);
        let descriptor = crate::isa::x86_64::gdt_entry(0x40f3, 0x30000, 0xffff);
        assert!(
            cpu.x86_mut()
                .unwrap()
                .vcpu_mut()
                .set_user_gdt_entry(11, descriptor)
        );
        let mut debug = vec![0; 120];
        debug[..4].copy_from_slice(&0x1e5u32.to_le_bytes());
        debug[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
        cpu.apply_kernel_debug_context(WinArch::Arm64, &debug, 1 << 47)
            .unwrap();
        let native = cpu.kernel_debug_context(WinArch::Arm64).unwrap();
        let amd64 = cpu.kernel_debug_context(WinArch::X64).unwrap();
        let mut context = cpu.arm64_kernel_context().unwrap();
        context.set_flags(CONTEXT_ARM64 | selected);
        cpu.apply_kernel_context(&context).unwrap();
        assert_eq!(
            cpu.kernel_debug_context(WinArch::Arm64).unwrap(),
            native,
            "native group {selected:#x}"
        );
        assert_eq!(
            cpu.kernel_debug_context(WinArch::X64).unwrap(),
            amd64,
            "AMD64 group {selected:#x}"
        );
        let captured = RegContext::capture(&cpu);
        assert_eq!(&captured.bytes()[72..120], &amd64);
        assert_eq!(
            cpu.x86().unwrap().vcpu().user_gdt_entry(11),
            Some(descriptor)
        );
        let child = cpu.new_thread();
        let child_native = child.kernel_debug_context(WinArch::Arm64).unwrap();
        assert_eq!(
            &child_native[..96],
            &[0; 96],
            "new thread group {selected:#x}"
        );
        let child_amd64 = child.kernel_debug_context(WinArch::X64).unwrap();
        assert_eq!(&child_amd64[..32], &[0; 32]);
        assert_eq!(
            u64::from_le_bytes(child_amd64[40..48].try_into().unwrap()) & 0xff,
            0
        );
    }
}

#[test]
fn native_thread_context_vector_aliases_follow_real_amd64_and_arm64_instructions() {
    use crate::user::mm::{Mapping, PAGE_SIZE, Perms, SpaceConfig};
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: crate::user::cpu::x86_64::RESERVED_PHYS.to_vec(),
    })
    .unwrap();
    space
        .map(
            0x10000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::EXEC),
        )
        .unwrap();
    space
        .map(
            0x20000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    // Encodings independently emitted by LLVM MC; one AVX2 instruction and
    // one AArch64 SIMD instruction, without an emulated OS service call.
    space.write_raw(0x10000, &[0xc5, 0xfd, 0x76, 0xc0]).unwrap();
    space.write_raw(0x10100, &[0x50, 0xe7, 0x02, 0x4f]).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20f00);
    cpu.set_pc(0x10000);
    cpu.x86_mut().unwrap().vcpu_mut().set_xcr0(7).unwrap();
    let marker = [[0x1122_3344_5566_7788, 0x8877_6655_4433_2211]; 16];
    cpu.apply_kernel_ymm_high(marker).unwrap();
    cpu.enable_arm64ec().unwrap();
    assert!(matches!(cpu.run(1), CpuStop::Yield));
    assert_eq!(cpu.pc(), 0x10004);
    assert_eq!(cpu.arm64_kernel_context().unwrap().v(16), u128::MAX);
    let mut native = cpu.arm64_kernel_context().unwrap();
    native.set_flags(0x0040_0001);
    native.set_pc(0x10100);
    cpu.apply_kernel_context(&native).unwrap();
    assert!(matches!(cpu.run(1), CpuStop::Yield));
    let high = cpu.kernel_ymm_high().unwrap();
    assert_eq!(high[0], [0x5a5a_5a5a_5a5a_5a5a; 2]);
    assert_eq!(&high[1..], &marker[1..]);
    assert_eq!(cpu.x86().unwrap().vcpu().user_regs().xmm[0], [u64::MAX; 2]);
}
