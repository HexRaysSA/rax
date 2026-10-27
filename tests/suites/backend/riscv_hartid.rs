//! Configured RISC-V hart identity across guest reads, reset and import.
use rax::backend::emulator::riscv::RiscVVcpu;
use rax::isa::riscv::{FlatMemory, Isa, RiscVConfig, RiscVCpu};
use rax::vm::vcpu::{CpuState, RetirementStop, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const ENTRY: u64 = 0x1000;
fn config(rv32: bool) -> RiscVConfig {
    if rv32 {
        RiscVConfig::rv32(Isa::rv64gc())
    } else {
        RiscVConfig::rv64gc()
    }
}
fn core(rv32: bool, id: u64) -> RiscVCpu {
    RiscVCpu::new_with_hart_id(config(rv32), Box::new(FlatMemory::new(0, 0x4000)), id)
}
fn machine_with_instruction(rv32: bool, id: u32, devices: bool, instruction: u32) -> RiscVVcpu {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    m.write_slice(&instruction.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    let mut cpu = if devices {
        RiscVVcpu::new_with_config(id, m, config(rv32))
    } else {
        RiscVVcpu::new_embedded(id, m, config(rv32))
    };
    cpu.set_current_pc(ENTRY).unwrap();
    cpu
}
fn machine(rv32: bool, id: u32, devices: bool) -> RiscVVcpu {
    machine_with_instruction(rv32, id, devices, 0xf14022f3)
}
fn read(cpu: &mut RiscVVcpu) -> u64 {
    let r = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 1);
    assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
    let CpuState::RiscV(s) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(s.regs.pc, ENTRY + 4);
    s.regs.x[5]
}
#[test]
fn existing_core_constructor_retains_hart_zero() {
    let c = RiscVCpu::new(config(false), Box::new(FlatMemory::new(0, 0x4000)));
    assert_eq!(c.csr_read(0xf14).unwrap(), 0);
}
#[test]
fn explicit_rv64_identity_preserves_all_bits() {
    for id in [0, 1, 255, u64::from(u32::MAX), u64::MAX] {
        assert_eq!(core(false, id).csr_read(0xf14).unwrap(), id);
    }
}
#[test]
fn explicit_rv32_identity_has_mxlen_width() {
    for id in [0, 1, 255, 0x1_0000_0001, u64::MAX] {
        assert_eq!(core(true, id).csr_read(0xf14).unwrap(), id & 0xffff_ffff);
    }
}
#[test]
fn warm_reset_retains_identity() {
    for rv32 in [false, true] {
        let mut c = core(rv32, 0x12345678);
        c.set_x(1, 99);
        c.reset(ENTRY);
        assert_eq!(c.csr_read(0xf14).unwrap(), 0x12345678);
        assert_eq!(c.x(1), 0);
    }
}
#[test]
fn guest_csr_write_cannot_replace_hardware_identity() {
    for rv32 in [false, true] {
        let mut cpu = machine_with_instruction(rv32, 0x12345678, false, 0xf1431073);
        let run = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(run.retired, 0);
        assert!(
            matches!(
                run.stop,
                RetirementStop::Exit(rax::vm::vcpu::VcpuExit::Unknown(_))
            ),
            "{:?}",
            run.stop
        );
        let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            state.regs.csrs.iter().find(|(n, _)| *n == 0xf14).unwrap().1,
            0x12345678
        );
        for (number, expected) in [(0x342, 2), (0x341, ENTRY), (0x343, 0xf1431073)] {
            assert_eq!(
                state
                    .regs
                    .csrs
                    .iter()
                    .find(|(n, _)| *n == number)
                    .unwrap()
                    .1,
                expected
            );
        }
    }
}
#[test]
fn importing_readonly_csr_does_not_replace_configured_identity() {
    for rv32 in [false, true] {
        let mut c = core(rv32, 77);
        c.import_csrs(&[(0xf14, 0), (0x340, 91)]);
        assert_eq!(c.csr_read(0xf14).unwrap(), 77);
        assert_eq!(c.csr_read(0x340).unwrap(), 91);
    }
}
#[test]
fn both_adapter_constructors_expose_requested_id_to_real_guest_csrr() {
    for rv32 in [false, true] {
        for devices in [false, true] {
            for id in [0, 1, 2, 3, 255, u32::MAX] {
                let mut cpu = machine(rv32, id, devices);
                assert_eq!(cpu.id(), id);
                assert_eq!(read(&mut cpu), u64::from(id));
            }
        }
    }
}
#[test]
fn backend_state_import_keeps_readonly_configured_identity() {
    for rv32 in [false, true] {
        let mut cpu = machine(rv32, 17, false);
        let mut saved = cpu.get_state().unwrap();
        let CpuState::RiscV(s) = &mut saved else {
            panic!()
        };
        s.regs
            .csrs
            .iter_mut()
            .find(|(number, _)| *number == 0xf14)
            .unwrap()
            .1 = 0;
        cpu.set_state(&saved).unwrap();
        assert_eq!(read(&mut cpu), 17);
    }
}
#[test]
fn one_two_and_four_distinct_objects_expose_distinct_hart_ids() {
    for rv32 in [false, true] {
        for count in [1, 2, 4] {
            let values: Vec<_> = (0..count)
                .map(|id| read(&mut machine(rv32, id, false)))
                .collect();
            assert_eq!(values, (0..u64::from(count)).collect::<Vec<_>>());
        }
    }
}
struct Identity;
impl rax::vm::memory::FlatTranslation for Identity {
    fn translate(
        &self,
        address: u64,
        _: rax::error::MemoryAccessKind,
    ) -> std::result::Result<u64, rax::error::GuestMemoryFault> {
        Ok(address)
    }
}
#[test]
fn user_adapter_keeps_configured_identity_and_machine_csr_privilege() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory
        .write_slice(&0xf14022f3u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    let mut cpu = RiscVVcpu::new_user(9, memory, config(false), Arc::new(Identity));
    cpu.set_current_pc(ENTRY).unwrap();
    let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        state.regs.csrs.iter().find(|(n, _)| *n == 0xf14).unwrap().1,
        9
    );
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 0);
    assert!(
        matches!(
            result.stop,
            RetirementStop::Fault(rax::error::Error::GuestEvent { vector: 2 })
        ),
        "{:?}",
        result.stop
    );
}
pub fn emit_reference(path: &std::path::Path) {
    let mut bytes = Vec::new();
    for rv32 in [false, true] {
        for devices in [false, true] {
            for id in [0, 1, 2, 3, 255, u32::MAX] {
                let mut c = machine(rv32, id, devices);
                let value = read(&mut c);
                for word in [
                    u64::from(rv32),
                    u64::from(devices),
                    u64::from(id),
                    value,
                    c.current_pc(),
                    c.instruction_count(),
                ] {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
            }
        }
    }
    std::fs::write(path, bytes).unwrap();
}
