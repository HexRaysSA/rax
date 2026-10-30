//! Exact budget boundaries over actual stepping backends and adversarial exits.
#[cfg(test)]
#[path = "retirement_budget/register_updates.rs"]
mod register_updates;

use rax::backend::emulator::{
    aarch32::Aarch32Vcpu, aarch64::Aarch64Vcpu, cortex_m::CortexMVcpu, riscv::RiscVVcpu,
};
use rax::config::{Endianness, HexagonIsa};
#[cfg(test)]
use rax::error::{Error, Result};
use rax::isa::{
    ebpf::{EbpfConfig, EbpfVcpu, SbpfVersion},
    hexagon::HexagonVcpu,
    riscv::RiscVConfig,
    x86_64::X86_64Vcpu,
};
use rax::vm::vcpu::{CpuState, Registers, RetirementStop, SystemRegisters, VCpu};
#[cfg(test)]
use rax::vm::vcpu::{DEFAULT_RETIREMENT_QUANTUM, VcpuExit};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const CODE: u64 = 0x1000;
const UNITS: usize = 4096;
fn instruction(kind: u8) -> &'static [u8] {
    match kind {
        0 => &[0x90],
        1 => &[0x1f, 0x20, 0x03, 0xd5],
        2 => &[0, 0xf0, 0x20, 0xe3],
        3 => &[0, 0xbf],
        4 => &[0x13, 0, 0, 0],
        5 => &[0, 0xc0, 0, 0x7f],
        6..=11 => &[7, 0, 0, 0, 0, 0, 0, 0],
        _ => panic!(),
    }
}
fn machine(kind: u8) -> (Box<dyn VCpu>, Arc<GuestMemoryMmap>) {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap());
    memory
        .write_slice(&instruction(kind).repeat(UNITS), GuestAddress(CODE))
        .unwrap();
    let mut cpu: Box<dyn VCpu> = match kind {
        0 => {
            let mut c = X86_64Vcpu::new(0, memory.clone());
            c.set_state(&CpuState::x86_64(
                Registers {
                    rip: CODE,
                    rflags: 2,
                    ..Default::default()
                },
                SystemRegisters::default(),
            ))
            .unwrap();
            Box::new(c)
        }
        1 => Box::new(Aarch64Vcpu::new_micro(0, memory.clone())),
        2 => Box::new(Aarch32Vcpu::new(0, memory.clone())),
        3 => Box::new(CortexMVcpu::new(0, memory.clone())),
        4 => Box::new(RiscVVcpu::new_embedded(
            0,
            memory.clone(),
            RiscVConfig::rv64gc(),
        )),
        5 => Box::new(HexagonVcpu::new(
            0,
            memory.clone(),
            HexagonIsa::default(),
            Endianness::Little,
        )),
        6..=11 => {
            let config = if kind == 6 {
                EbpfConfig::default()
            } else {
                EbpfConfig::solana(
                    [
                        SbpfVersion::V0,
                        SbpfVersion::V1,
                        SbpfVersion::V2,
                        SbpfVersion::V3,
                        SbpfVersion::V4,
                    ][(kind - 7) as usize],
                )
            };
            Box::new(EbpfVcpu::new(0, memory.clone(), config))
        }
        _ => panic!(),
    };
    cpu.set_current_pc(CODE).unwrap();
    (cpu, memory)
}
#[test]
fn every_emulated_plane_obeys_zero_one_and_quantum_boundaries() {
    assert_eq!(DEFAULT_RETIREMENT_QUANTUM, 1000);
    for kind in 0..12 {
        let (mut cpu, _) = machine(kind);
        let mut total = 0;
        for budget in [0, 1, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert_eq!(r.retired, budget, "plane{kind}");
            assert!(
                matches!(r.stop, RetirementStop::BudgetExhausted),
                "plane{kind}:{:?}",
                r.stop
            );
            total += budget;
            assert_eq!(cpu.instruction_count(), total, "plane{kind}");
            assert_eq!(
                cpu.current_pc(),
                CODE + total * instruction(kind).len() as u64,
                "plane{kind}"
            );
        }
    }
}
#[test]
fn x86_halt_at_last_unit_is_an_exit_and_remains_halted() {
    let (mut cpu, mem) = machine(0);
    mem.write_slice(&[0xf4], GuestAddress(CODE + 999)).unwrap();
    let r = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 1000);
    assert!(matches!(r.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    let r = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(r.stop, RetirementStop::Exit(VcpuExit::Hlt)));
}
#[test]
fn x86_io_is_preserved_at_the_budget_boundary() {
    let (mut cpu, mem) = machine(0);
    mem.write_slice(&[0xe6, 0x80], GuestAddress(CODE + 999))
        .unwrap();
    let r = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 1000);
    assert!(matches!(
        r.stop,
        RetirementStop::Exit(VcpuExit::IoOut { port: 0x80, .. })
    ));
    assert_eq!(cpu.current_pc(), CODE + 1001);
}
#[test]
fn ebpf_fault_charges_meter_but_not_retirement_and_keeps_prior_progress() {
    for kind in 6..12 {
        let (mut cpu, mem) = machine(kind);
        mem.write_slice(&[0xff; 8], GuestAddress(CODE + 3 * 8))
            .unwrap();
        let r = cpu.run_retirement_budget(1000).unwrap();
        assert_eq!(r.retired, 3, "plane{kind}");
        assert!(
            matches!(r.stop, RetirementStop::Fault(_)),
            "plane{kind}:{:?}",
            r.stop
        );
        assert_eq!(
            cpu.instruction_count(),
            4,
            "existing charged meter remains observable"
        );
    }
}
#[test]
fn ebpf_program_exit_remains_distinct_from_exhaustion() {
    for kind in 6..12 {
        let (mut cpu, mem) = machine(kind);
        mem.write_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0], GuestAddress(CODE + 7 * 8))
            .unwrap();
        let r = cpu.run_retirement_budget(8).unwrap();
        assert_eq!(r.retired, 8);
        assert!(matches!(r.stop, RetirementStop::Exit(VcpuExit::Shutdown)));
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum Action {
    Retire,
    Transition,
    Exit(bool),
    Fail(bool),
    Jump(u64),
}
#[cfg(test)]
struct Script {
    count: u64,
    calls: usize,
    actions: Vec<Action>,
    stepping: bool,
}
#[cfg(test)]
impl Script {
    fn new(actions: Vec<Action>) -> Self {
        Self {
            count: 0,
            calls: 0,
            actions,
            stepping: true,
        }
    }
}
#[cfg(test)]
impl VCpu for Script {
    fn run(&mut self) -> Result<VcpuExit> {
        panic!("unbounded run must never be used")
    }
    fn get_state(&self) -> Result<CpuState> {
        Ok(CpuState::x86_64(Default::default(), Default::default()))
    }
    fn set_state(&mut self, _: &CpuState) -> Result<()> {
        Ok(())
    }
    fn complete_io_in(&mut self, _: &[u8]) {}
    fn id(&self) -> u32 {
        0
    }
    fn supports_stepping(&self) -> bool {
        self.stepping
    }
    fn instruction_count(&self) -> u64 {
        self.count
    }
    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        let a = self.actions[self.calls];
        self.calls += 1;
        match a {
            Action::Retire => {
                self.count = self.count.wrapping_add(1);
                Ok(None)
            }
            Action::Transition => Ok(None),
            Action::Exit(charge) => {
                self.count += u64::from(charge);
                Ok(Some(VcpuExit::MmioRead {
                    addr: 0x1234,
                    size: 4,
                }))
            }
            Action::Fail(charge) => {
                self.count += u64::from(charge);
                Err(Error::Emulator("sentinel".into()))
            }
            Action::Jump(n) => {
                self.count = self.count.wrapping_add(n);
                Ok(None)
            }
        }
    }
}
#[test]
fn zero_budget_does_not_enter_or_probe_backend() {
    let mut c = Script::new(vec![]);
    c.stepping = false;
    let r = c.run_retirement_budget(0).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
    assert_eq!(c.calls, 0);
}
#[test]
fn unsupported_backend_rejects_before_execution() {
    let mut c = Script::new(vec![]);
    c.stepping = false;
    assert!(c.run_retirement_budget(1).is_err());
    assert_eq!(c.calls, 0);
}
#[test]
fn zero_retirement_transition_returns_control_without_spinning() {
    let mut c = Script::new(vec![Action::Retire, Action::Transition]);
    let r = c.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 1);
    assert!(matches!(r.stop, RetirementStop::StateChange));
    assert_eq!(c.calls, 2);
}
#[test]
fn exits_preserve_retirement_and_payload_for_both_charge_states() {
    for charge in [false, true] {
        let mut c = Script::new(vec![Action::Retire, Action::Exit(charge)]);
        let r = c.run_retirement_budget(1000).unwrap();
        assert_eq!(r.retired, 1 + u64::from(charge));
        assert!(matches!(
            r.stop,
            RetirementStop::Exit(VcpuExit::MmioRead {
                addr: 0x1234,
                size: 4
            })
        ));
        assert_eq!(c.calls, 2);
    }
}
#[test]
fn fault_preserves_prior_retirements_for_both_meter_charge_states() {
    for charge in [false, true] {
        let mut c = Script::new(vec![Action::Retire, Action::Fail(charge)]);
        let r = c.run_retirement_budget(1000).unwrap();
        assert_eq!(r.retired, 1);
        match r.stop {
            RetirementStop::Fault(Error::Emulator(s)) => assert_eq!(s, "sentinel"),
            other => panic!("{other:?}"),
        };
        assert_eq!(c.calls, 2);
    }
}
#[test]
fn wrapping_counter_is_admitted_without_losing_one_retirement() {
    let mut c = Script::new(vec![Action::Retire]);
    c.count = u64::MAX;
    let r = c.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 1);
    assert_eq!(c.count, 0);
    assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
}
#[test]
fn broken_step_counter_is_reported_as_a_contract_failure() {
    let mut c = Script::new(vec![Action::Jump(2)]);
    let r = c.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(r.stop, RetirementStop::Fault(_)));
    assert_eq!(c.calls, 1);
}
pub fn emit_reference(path: &std::path::Path) {
    let mut rows = Vec::new();
    for kind in 0..12 {
        let (mut cpu, _) = machine(kind);
        for budget in [0, 1, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            for n in [
                kind as u64,
                budget,
                r.retired,
                cpu.instruction_count(),
                cpu.current_pc(),
            ] {
                rows.extend_from_slice(&n.to_le_bytes());
            }
        }
    }
    std::fs::write(path, rows).unwrap();
}

#[test]
fn actual_riscv_interrupt_delivery_returns_without_retiring_handler_code() {
    let (mut cpu, _) = machine(4);
    let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.privilege = Some(3);
    state
        .regs
        .csrs
        .retain(|(number, _)| ![0x300, 0x304, 0x305, 0x344].contains(number));
    state
        .regs
        .csrs
        .extend([(0x300, 8), (0x304, 8), (0x305, CODE + 0x800), (0x344, 8)]);
    cpu.set_state(&CpuState::RiscV(state)).unwrap();
    let result = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(result.retired, 0);
    assert!(matches!(result.stop, RetirementStop::StateChange));
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(cpu.current_pc(), CODE + 0x800);
    let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(
        state.regs.csrs.iter().find(|(n, _)| *n == 0x341).unwrap().1,
        CODE
    );
    assert_eq!(
        state.regs.csrs.iter().find(|(n, _)| *n == 0x342).unwrap().1,
        (1u64 << 63) | 3
    );
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.current_pc(), CODE + 0x804);
}
