use super::*;

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
