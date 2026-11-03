use rax::backend::emulator::riscv::RiscVVcpu;
use rax::isa::riscv::RiscVConfig;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn check(peer_store: bool) {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    for (index, word) in [0x1005_22afu32, 0x18c5_25af, 0x1050_0073]
        .iter()
        .enumerate()
    {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(index as u64 * 4))
            .unwrap();
    }
    mem.write_slice(&0x00c5_2023u32.to_le_bytes(), GuestAddress(0x100))
        .unwrap();
    let mut source = RiscVVcpu::new(0, mem.clone());
    let mut writer = RiscVVcpu::new_embedded(1, mem.clone(), RiscVConfig::rv64gc());
    for (cpu, pc, value) in [(&mut source, 0, 1), (&mut writer, 0x100, 0)] {
        let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = pc;
        state.regs.x[10] = 0x800;
        state.regs.x[12] = value;
        state.regs.tohost_addr = Some(0x800);
        cpu.set_state(&CpuState::RiscV(state)).unwrap();
    }
    assert!(source.step_insn().unwrap().is_none());
    if peer_store {
        assert!(writer.step_insn().unwrap().is_none());
    }
    let exit = source.step_insn().unwrap();
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x800)).unwrap(),
        if peer_store { 0 } else { 1 }
    );
    assert_eq!(source.instruction_count(), 2);
    if peer_store {
        assert!(exit.is_none());
    } else {
        assert!(matches!(exit, Some(VcpuExit::Shutdown)));
    }
    let raw = source.save_context().unwrap();
    let mut restored = RiscVVcpu::new(0, mem);
    restored.restore_context(&raw).unwrap();
    let exit = restored.step_insn().unwrap();
    if peer_store {
        assert!(exit.is_none());
        assert_eq!(restored.instruction_count(), 3);
    } else {
        assert!(matches!(exit, Some(VcpuExit::Hlt)));
        assert_eq!(restored.instruction_count(), 2);
    }
}

#[test]
fn successful_sc_to_htif_preserves_shutdown_without_extra_retirement() {
    check(false);
}
#[test]
fn failed_sc_to_htif_neither_writes_nor_publishes_shutdown() {
    check(true);
}
