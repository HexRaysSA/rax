use super::*;
use crate::backend::emulator::riscv::cpu::*;
use crate::isa::riscv::{Isa, RiscVConfig};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::VCpu;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

struct Identity;
impl FlatTranslation for Identity {
    fn translate(
        &self,
        address: u64,
        _access: crate::error::MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        Ok(address)
    }
}

fn fixture(mode: u8, config: RiscVConfig, code: &[u32]) -> RiscVVcpu {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    for (index, word) in code.iter().enumerate() {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(0x100 + index as u64 * 4))
            .unwrap();
    }
    mem.write_slice(&0x1234_5678u32.to_le_bytes(), GuestAddress(0x800))
        .unwrap();
    let mut cpu = match mode {
        0 => RiscVVcpu::new_with_config(3, mem, config),
        1 => RiscVVcpu::new_embedded(3, mem, config),
        2 => RiscVVcpu::new_user(3, mem, config, Arc::new(Identity)),
        _ => unreachable!(),
    };
    let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = 0x100;
    state.regs.x[10] = 0x800;
    cpu.set_state(&CpuState::RiscV(state)).unwrap();
    cpu
}

#[test]
fn rv32_rv64_system_embedded_and_process_reservations_resume_sc() {
    // LR.W t0,(a0); SC.W a1,t0,(a0), independently encoded by LLVM 23.
    let code = [0x1005_22af, 0x1855_25af];
    for config in [RiscVConfig::rv64gc(), RiscVConfig::rv32(Isa::rv64gc())] {
        for mode in 0..3 {
            let mut source = fixture(mode, config, &code);
            assert!(source.step_insn().unwrap().is_none());
            let raw = source.save_context().unwrap();
            let mut restored = fixture(mode, config, &code);
            restored.restore_context(&raw).unwrap();
            for cpu in [&mut source, &mut restored] {
                assert!(cpu.step_insn().unwrap().is_none());
                let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(
                    state.regs.x[11], 0,
                    "SC must retain the successful LR reservation"
                );
                assert_eq!(cpu.instruction_count(), 2);
            }
            assert_eq!(
                source.save_context().unwrap(),
                restored.save_context().unwrap()
            );
        }
    }
}

fn vector_source(stride: u64, count: u64) -> RiscVVcpu {
    // VSSE8.V v1,(a0),a1; ADDI t0,zero,42. LLVM encoding retained with evidence.
    let mut cpu = fixture(0, RiscVConfig::rv64gc(), &[0x0ab5_00a7, 0x02a0_0293]);
    let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.x[10] = super::super::UART_BASE;
    state.regs.x[11] = stride;
    state.regs.csrs.iter_mut().find(|x| x.0 == 0x300).unwrap().1 = 1 << 9;
    let vector = state.regs.vector.as_mut().unwrap();
    vector.vl = count;
    vector.vtype = 0;
    vector.v[16..20].copy_from_slice(b"ABCD");
    cpu.set_state(&CpuState::RiscV(state)).unwrap();
    cpu
}

#[test]
fn vector_uart_events_remain_ordered_across_context_without_extra_retirement() {
    let mut source = vector_source(0, 4);
    assert!(
        matches!(source.step_insn().unwrap(), Some(crate::vm::vcpu::VcpuExit::MmioWrite { data, .. }) if data == b"A")
    );
    let raw = source.save_context().unwrap();
    let mut restored = vector_source(0, 4);
    restored.restore_context(&raw).unwrap();
    for cpu in [&mut source, &mut restored] {
        for expected in b"BCD" {
            assert!(
                matches!(cpu.step_insn().unwrap(), Some(crate::vm::vcpu::VcpuExit::MmioWrite { data, .. }) if data == [*expected])
            );
            assert_eq!(cpu.instruction_count(), 1);
            assert_eq!(cpu.current_pc(), 0x104);
        }
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.instruction_count(), 2);
        let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.x[5], 42);
    }
    assert_eq!(
        source.save_context().unwrap(),
        restored.save_context().unwrap()
    );
}

#[test]
fn vector_store_fault_behind_uart_event_resumes_original_fault_and_halt() {
    let mut source = vector_source(0x100, 2);
    assert!(
        matches!(source.step_insn().unwrap(), Some(crate::vm::vcpu::VcpuExit::MmioWrite { data, .. }) if data == b"A")
    );
    let raw = source.save_context().unwrap();
    let mut restored = vector_source(0x100, 2);
    restored.restore_context(&raw).unwrap();
    for cpu in [&mut source, &mut restored] {
        let event = cpu.step_insn().unwrap();
        assert!(
            matches!(event, Some(crate::vm::vcpu::VcpuExit::Unknown(ref reason)) if reason.contains("cause=7") && reason.contains("tval=0x10000100")),
            "{event:?}"
        );
        assert_eq!(cpu.instruction_count(), 0);
        assert!(matches!(
            cpu.step_insn().unwrap(),
            Some(crate::vm::vcpu::VcpuExit::Hlt)
        ));
        let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.csrs.iter().find(|x| x.0 == 0x342).unwrap().1, 7);
    }
    let halted = restored.save_context().unwrap();
    let mut again = vector_source(0x100, 2);
    again.restore_context(&halted).unwrap();
    assert!(matches!(
        again.step_insn().unwrap(),
        Some(crate::vm::vcpu::VcpuExit::Hlt)
    ));
    assert_eq!(again.save_context().unwrap(), halted);
}

#[test]
fn failed_tohost_store_does_not_publish_shutdown() {
    let mut cpu = fixture(0, RiscVConfig::rv64gc(), &[0x0055_3023]); // SD t0,0(a0)
    let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.x[5] = 1;
    state.regs.x[10] = 0x8000;
    state.regs.tohost_addr = Some(0x8000);
    cpu.set_state(&CpuState::RiscV(state)).unwrap();
    assert!(
        matches!(cpu.step_insn().unwrap(), Some(crate::vm::vcpu::VcpuExit::Unknown(reason)) if reason.contains("cause=7"))
    );
    assert_eq!(cpu.instruction_count(), 0);
}

#[test]
fn process_ecall_event_and_counter_are_retained_and_consumed_once() {
    let mut source = fixture(2, RiscVConfig::rv64gc(), &[0x0000_0073, 0x02a0_0293]);
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(crate::vm::vcpu::VcpuExit::SystemCall)
    ));
    let raw = source.save_context().unwrap();
    let mut restored = fixture(2, RiscVConfig::rv64gc(), &[0x0000_0073, 0x02a0_0293]);
    restored.restore_context(&raw).unwrap();
    for cpu in [&mut source, &mut restored] {
        assert_eq!(cpu.take_user_trap(), Some(RvUserTrap::Ecall { pc: 0x100 }));
        assert_eq!(cpu.take_user_trap(), None);
        assert_eq!(cpu.instruction_count(), 1);
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.instruction_count(), 2);
    }
    assert_eq!(
        source.save_context().unwrap(),
        restored.save_context().unwrap()
    );
}

#[test]
fn profile_and_rv32_counter_high_halves_replace_target_configuration() {
    let config = RiscVConfig::rv32(Isa::rv_i());
    let mut source = fixture(1, config, &[0x0252_82b3]); // MUL t0,t0,t0: disabled M.
    let CpuState::RiscV(mut state) = source.get_state().unwrap() else {
        panic!()
    };
    for csr in [0xc00, 0xc01, 0xc02] {
        state.regs.csrs.iter_mut().find(|x| x.0 == csr).unwrap().1 = 0x1234_ffff_ffff;
    }
    source.set_state(&CpuState::RiscV(state)).unwrap();
    let raw = source.save_context().unwrap();
    let mut restored = fixture(1, RiscVConfig::rv64gc(), &[0x0252_82b3]);
    restored.restore_context(&raw).unwrap();
    assert_eq!(restored.riscv_configuration(), Some(config));
    assert_eq!(restored.instruction_count(), 0x1234_ffff_ffff);
    for cpu in [&mut source, &mut restored] {
        assert!(
            matches!(cpu.step_insn().unwrap(), Some(crate::vm::vcpu::VcpuExit::Unknown(reason)) if reason.contains("cause=2"))
        );
    }
    assert_eq!(
        source.save_context().unwrap(),
        restored.save_context().unwrap()
    );
}

#[test]
fn malformed_contexts_and_binding_changes_preserve_live_context() {
    let mut source = fixture(1, RiscVConfig::rv64gc(), &[0x1005_22af]);
    source.step_insn().unwrap();
    let raw = source.save_context().unwrap();
    let mut target = fixture(1, RiscVConfig::rv64gc(), &[0x02a0_0293]);
    let before = target.save_context().unwrap();
    for end in 0..raw.len() {
        assert!(target.restore_context(&raw[..end]).is_err(), "prefix {end}");
    }
    for offset in [0, 8] {
        let mut bad = raw.clone();
        bad[offset] ^= 0x80;
        assert!(target.restore_context(&bad).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(target.restore_context(&trailing).is_err());
    assert_eq!(target.save_context().unwrap(), before);
    for mode in [0, 2] {
        let mut other = fixture(mode, RiscVConfig::rv64gc(), &[]);
        let before = other.save_context().unwrap();
        assert!(other.restore_context(&raw).is_err());
        assert_eq!(other.save_context().unwrap(), before);
    }
}

#[test]
fn poisoned_adapter_locks_reject_before_any_context_field_changes() {
    for which in 0..3 {
        let mut source = fixture(2, RiscVConfig::rv64gc(), &[0x0000_0073]);
        source.step_insn().unwrap();
        let raw = source.save_context().unwrap();
        let mut target = fixture(2, RiscVConfig::rv64gc(), &[]);
        let before = target.save_context().unwrap();
        match which {
            0 => {
                let lock = target.pending.clone();
                let _ = std::thread::spawn(move || {
                    let _guard = lock.lock().unwrap();
                    panic!("owned poison fixture");
                })
                .join();
            }
            1 => {
                let lock = target.tohost_addr.clone();
                let _ = std::thread::spawn(move || {
                    let _guard = lock.lock().unwrap();
                    panic!("owned poison fixture");
                })
                .join();
            }
            2 => {
                let lock = target.user.as_ref().unwrap().last_fault.clone();
                let _ = std::thread::spawn(move || {
                    let _guard = lock.lock().unwrap();
                    panic!("owned poison fixture");
                })
                .join();
            }
            _ => unreachable!(),
        }
        assert!(target.restore_context(&raw).is_err());
        target.pending.clear_poison();
        target.tohost_addr.clear_poison();
        target.user.as_ref().unwrap().last_fault.clear_poison();
        assert_eq!(target.save_context().unwrap(), before);
    }
}
