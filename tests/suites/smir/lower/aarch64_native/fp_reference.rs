//! Interpreter state for feature-checked raw native FP reference programs.
use super::*;

pub(super) fn raw_interp_run(
    insns: &[u32],
    setup: impl FnOnce(&mut Aarch64GuestRegs),
) -> Aarch64GuestRegs {
    let mut seed = Aarch64GuestRegs::default();
    setup(&mut seed);

    // Raw native-reference programs exercise FHM only after host feature checks.
    // Select the same guest capability explicitly rather than relying on defaults.
    let mut config = AArch64Config::default();
    config.features |= rax::isa::arm::common::features::ArmFeatures::FP16
        | rax::isa::arm::common::features::ArmFeatures::FHM;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x0100_0000)));
    cpu.set_jit_enabled(false);
    cpu.write_memory(PROG_BASE, &code_bytes_with_ret(insns))
        .unwrap();
    cpu.set_sp(seed.sp);
    for i in 0..30u8 {
        cpu.set_x(i, seed.x[i as usize]);
    }
    for i in 0..32u8 {
        let lo = seed.v[(2 * i) as usize] as u128;
        let hi = seed.v[(2 * i + 1) as usize] as u128;
        cpu.set_simd(i, lo | (hi << 64));
    }
    cpu.set_fpcr(seed.fpcr as u32).unwrap();
    cpu.set_fpsr(seed.fpsr as u32).unwrap();
    let nzcv = (seed.nzcv >> 28) & 0xf;
    cpu.set_nzcv(
        (nzcv & 0b1000) != 0,
        (nzcv & 0b0100) != 0,
        (nzcv & 0b0010) != 0,
        (nzcv & 0b0001) != 0,
    );
    drive_to_done(&mut cpu);

    let mut out = Aarch64GuestRegs::default();
    for i in 0..30u8 {
        out.x[i as usize] = cpu.get_x(i);
    }
    out.sp = cpu.get_sp();
    for i in 0..32u8 {
        let value = cpu.get_simd(i);
        out.v[(2 * i) as usize] = value as u64;
        out.v[(2 * i + 1) as usize] = (value >> 64) as u64;
    }
    out.fpcr = cpu.get_fpcr().unwrap() as u64;
    out.fpsr = cpu.get_fpsr().unwrap() as u64;
    out.nzcv = ((cpu.get_n() as u64) << 31)
        | ((cpu.get_z() as u64) << 30)
        | ((cpu.get_c() as u64) << 29)
        | ((cpu.get_v() as u64) << 28);
    out
}
