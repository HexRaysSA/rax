use super::*;
use crate::isa::riscv::{Isa, Memory, RiscVExit};

#[test]
fn rv32_raw_counter_high_halves_and_pending_irq_survive_core_restore() {
    fn memory() -> Box<dyn Memory> {
        Box::new(FlatMemory::new(0, 4096))
    }
    let mut source = RiscVCpu::new(RiscVConfig::rv32(Isa::rv64gc()), memory());
    source.pc = 0x100;
    source.cycle = 0x1234_ffff_ffff;
    source.time = 0x5678_ffff_ffff;
    source.instret = 0x9abc_ffff_ffff;
    source.mstatus = 1 << 3;
    source.mie = 1 << 7;
    source.mip = 1 << 7;
    source.mtvec = 0x200;
    let context = source.checkpoint_state();
    context.validate().unwrap();
    let mut restored = RiscVCpu::new(RiscVConfig::rv64gc(), memory());
    context.install(&mut restored);
    assert_eq!(restored.cfg, source.cfg);
    assert_eq!(restored.cycle, source.cycle);
    assert_eq!(restored.time, source.time);
    assert_eq!(restored.instret, source.instret);
    assert_eq!(source.step(), RiscVExit::Continue);
    assert_eq!(restored.step(), RiscVExit::Continue);
    assert_eq!(
        (restored.pc, restored.mepc, restored.mcause),
        (0x200, 0x100, 0x8000_0007)
    );
    assert_eq!(
        crate::codec::serialize(&restored.checkpoint_state()).unwrap(),
        crate::codec::serialize(&source.checkpoint_state()).unwrap()
    );
}

#[test]
fn vendor_csr_replacement_does_not_merge_stale_target_entries() {
    let mut config = RiscVConfig::rv32(Isa::rv_i());
    config.isa.xsoteria = true;
    let mut source = RiscVCpu::new(config, Box::new(FlatMemory::new(0, 0)));
    source.ext_csr.insert(0x7c0, 0x1234);
    let mut restored = RiscVCpu::new(config, Box::new(FlatMemory::new(0, 0)));
    restored.ext_csr.insert(0x7c1, 0x5678);
    source.checkpoint_state().install(&mut restored);
    assert_eq!(restored.csr_read(0x7c0).unwrap(), 0x1234);
    assert_eq!(restored.csr_read(0x7c1).unwrap(), 0);
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn native_jit_lr_sc_reservation_continues_after_core_restore_at_each_opt_level() {
    use crate::smir::optimize::OptLevel;
    fn hart() -> RiscVCpu {
        let mut mem = FlatMemory::new(0, 4096);
        mem.write(0x100, &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18])
            .unwrap();
        mem.write(0x800, &0x1234_5678u32.to_le_bytes()).unwrap();
        let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(mem));
        cpu.set_pc(0x100);
        cpu.set_x(10, 0x800);
        cpu
    }
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let mut source = hart();
        assert_eq!(source.step_jit(level), RiscVExit::Continue);
        assert!(
            source.jit_stats().native_executions > 0,
            "LR must execute native code"
        );
        let state = source.checkpoint_state();
        state.validate().unwrap();
        let mut restored = hart();
        assert_eq!(restored.step_jit(level), RiscVExit::Continue);
        assert!(restored.jit_stats().cache_entries > 0);
        state.install(&mut restored);
        assert_eq!(restored.jit_stats().cache_entries, 0);
        assert_eq!(restored.jit_stats().native_executions, 0);
        for cpu in [&mut source, &mut restored] {
            let before = cpu.jit_stats().native_executions;
            assert_eq!(cpu.step_jit(level), RiscVExit::Continue);
            assert!(
                cpu.jit_stats().native_executions > before,
                "SC must execute native code"
            );
            assert_eq!(cpu.x(11), 0);
            assert_eq!(cpu.instret(), 2);
        }
        assert_eq!(
            crate::codec::serialize(&source.checkpoint_state()).unwrap(),
            crate::codec::serialize(&restored.checkpoint_state()).unwrap()
        );
    }
}

#[test]
fn checkpoint_vector_and_vendor_counts_reject_before_elements() {
    let cpu = RiscVCpu::new(
        RiscVConfig::rv32(crate::isa::riscv::Isa::ti50()),
        Box::new(FlatMemory::new(0, 0)),
    );
    let image = cpu.checkpoint_state();
    let bytes = crate::codec::serialize(&image).unwrap();
    let vector_prefix = bytes.len() - 8 - image.v.len() - 8;
    for count in [(32 * VLENB as usize + 1) as u64, u64::MAX] {
        let mut bad = bytes[..vector_prefix + 8].to_vec();
        bad[vector_prefix..vector_prefix + 8].copy_from_slice(&count.to_le_bytes());
        let error = crate::codec::deserialize_strict::<CoreContext>(&bad)
            .unwrap_err()
            .to_string();
        assert!(error.contains("count exceeds bound"), "{error}");
    }
    for count in [65537u64, u64::MAX] {
        let mut bad = bytes.clone();
        let last = bad.len() - 8;
        bad[last..].copy_from_slice(&count.to_le_bytes());
        let error = crate::codec::deserialize_strict::<CoreContext>(&bad)
            .unwrap_err()
            .to_string();
        assert!(error.contains("count exceeds bound"), "{error}");
    }
}
