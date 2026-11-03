//! Public-backend operand-boundary and producer-identity controls.
use rax::backend::emulator::riscv::RiscVVcpu;
use rax::error::{GuestMemoryFault, MemoryAccessKind};
use rax::isa::riscv::RiscVConfig;
use rax::vm::memory::FlatTranslation;
use rax::vm::vcpu::{CpuState, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

struct Identity;
impl FlatTranslation for Identity {
    fn translate(&self, address: u64, _: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        Ok(address)
    }
}
fn hart(id: u32, mode: u8, memory: Arc<GuestMemoryMmap>) -> RiscVVcpu {
    match mode {
        0 => RiscVVcpu::new_with_config(id, memory, RiscVConfig::rv64gc()),
        1 => RiscVVcpu::new_embedded(id, memory, RiscVConfig::rv64gc()),
        2 => RiscVVcpu::new_user(id, memory, RiscVConfig::rv64gc(), Arc::new(Identity)),
        _ => unreachable!(),
    }
}
#[test]
fn final_aligned_word_and_doubleword_use_only_the_admitted_page() {
    for mode in 0..3 {
        for size in [4, 8] {
            let memory =
                Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
            let words = if size == 4 {
                [0x1005_22afu32, 0x1855_25af]
            } else {
                [0x1005_32afu32, 0x1855_35af]
            };
            for (i, word) in words.into_iter().enumerate() {
                memory
                    .write_slice(&word.to_le_bytes(), GuestAddress(0x100 + i as u64 * 4))
                    .unwrap();
            }
            let address = 4096 - size;
            memory
                .write_slice(
                    &0xfedc_ba98_7654_3210u64.to_le_bytes()[..size as usize],
                    GuestAddress(address),
                )
                .unwrap();
            let mut cpu = hart(3, mode, memory);
            let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = 0x100;
            state.regs.x[10] = address;
            cpu.set_state(&CpuState::RiscV(state)).unwrap();
            assert!(cpu.step_insn().unwrap().is_none());
            assert!(cpu.step_insn().unwrap().is_none());
            let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(
                state.regs.x[11], 0,
                "mode={mode},size={size},address={address}"
            );
            assert_eq!(cpu.instruction_count(), 2);
        }
    }
}
#[test]
fn wrong_hart_identity_rejects_the_version_two_record_before_target_mutation() {
    for mode in 0..3 {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let source = hart(3, mode, memory.clone());
        let mut target = hart(4, mode, memory);
        let record = source.save_context().unwrap();
        assert_eq!(&record[..8], b"RAXRV002");
        let before = target.save_context().unwrap();
        let error = target.restore_context(&record).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("hart identity differs from target"),
            "{error}"
        );
        assert_eq!(target.save_context().unwrap(), before);
    }
}
