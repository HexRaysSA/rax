//! Per-step virtual time over real backends, charged faults and clock-reading steps.
use rax::backend::emulator::{
    aarch32::Aarch32Vcpu, aarch64::Aarch64Vcpu, cortex_m::CortexMVcpu, riscv::RiscVVcpu,
};
use rax::config::{Endianness, HexagonIsa};
use rax::error::{Error, Result};
use rax::isa::{
    ebpf::{EbpfConfig, EbpfVcpu, SbpfVersion},
    hexagon::HexagonVcpu,
    riscv::RiscVConfig,
    x86_64::X86_64Vcpu,
};
use rax::vm::vcpu::VcpuExit;
use rax::vm::vcpu::{CpuState, Registers, RetirementStop, SystemRegisters, VCpu};
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

use rax::vm::timing::{self, ClockMode, TimingContext};
fn retired_clock() -> Arc<TimingContext> {
    Arc::new(TimingContext::with_mode(ClockMode::Retired))
}
fn check_clock(c: &TimingContext, units: u64) {
    let state = c.checkpoint_state();
    assert_eq!(state.retired_units, units);
    assert_eq!(state.elapsed_nanos, units / 3);
    assert_eq!(state.subnanosecond_quanta, (units % 3) as u8);
}
#[test]
fn all_twelve_planes_publish_each_successful_budget() {
    for kind in 0..12 {
        let clock = retired_clock();
        let _binding = clock.enter();
        let (mut cpu, _) = machine(kind);
        let mut total = 0;
        for budget in [0, 1, 2, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            assert_eq!(r.retired, budget);
            total += budget;
            check_clock(&clock, total);
            assert_eq!(timing::tsc(), total);
        }
    }
}
#[test]
fn charged_ebpf_faults_do_not_advance_virtual_time() {
    for kind in 6..12 {
        let clock = retired_clock();
        let _binding = clock.enter();
        let (mut cpu, mem) = machine(kind);
        mem.write_slice(&[0xff; 8], GuestAddress(CODE + 3 * 8))
            .unwrap();
        let r = cpu.run_retirement_budget(1000).unwrap();
        assert!(matches!(r.stop, RetirementStop::Fault(_)));
        assert_eq!(r.retired, 3);
        assert_eq!(cpu.instruction_count(), 4);
        check_clock(&clock, 3);
    }
}
#[test]
fn retiring_io_and_halt_advance_once_halted_reentry_does_not() {
    for (opcode, len) in [(&[0xe6, 0x80][..], 2), (&[0xf4][..], 1)] {
        let clock = retired_clock();
        let _binding = clock.enter();
        let (mut cpu, mem) = machine(0);
        mem.write_slice(opcode, GuestAddress(CODE)).unwrap();
        let r = cpu.run_retirement_budget(1000).unwrap();
        assert_eq!(r.retired, 1);
        assert!(matches!(r.stop, RetirementStop::Exit(_)));
        check_clock(&clock, 1);
        assert_eq!(cpu.current_pc(), CODE + len);
        if opcode[0] == 0xf4 {
            assert_eq!(cpu.run_retirement_budget(1000).unwrap().retired, 0);
            check_clock(&clock, 1);
        }
    }
}
struct Observer {
    count: u64,
    seen: Vec<u64>,
    delta: u64,
    fail: bool,
    stepping: bool,
}
impl Observer {
    fn new() -> Self {
        Self {
            count: 0,
            seen: vec![],
            delta: 1,
            fail: false,
            stepping: true,
        }
    }
}
impl VCpu for Observer {
    fn run(&mut self) -> Result<VcpuExit> {
        panic!("unbounded fallback");
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
        self.seen.push(timing::tsc());
        self.count = self.count.wrapping_add(self.delta);
        if self.fail {
            Err(Error::Emulator("charged sentinel".into()))
        } else {
            Ok(None)
        }
    }
}
#[test]
fn next_step_observes_previous_retirement_within_one_quantum() {
    let clock = retired_clock();
    let _binding = clock.enter();
    let mut cpu = Observer::new();
    assert_eq!(cpu.run_retirement_budget(1000).unwrap().retired, 1000);
    assert_eq!(cpu.seen, (0..1000).collect::<Vec<u64>>());
    check_clock(&clock, 1000);
}
#[test]
fn state_change_and_invalid_delta_do_not_publish_retirement() {
    for delta in [0, 2, u64::MAX] {
        let clock = retired_clock();
        let _binding = clock.enter();
        let mut cpu = Observer::new();
        cpu.delta = delta;
        let r = cpu.run_retirement_budget(10).unwrap();
        assert_eq!(r.retired, 0);
        assert_eq!(cpu.seen.len(), 1);
        assert!(if delta == 0 {
            matches!(r.stop, RetirementStop::StateChange)
        } else {
            matches!(r.stop, RetirementStop::Fault(_))
        });
        check_clock(&clock, 0);
    }
}
#[test]
fn fault_zero_budget_and_unsupported_backend_leave_clock_unchanged() {
    let clock = retired_clock();
    let _binding = clock.enter();
    let mut cpu = Observer::new();
    cpu.fail = true;
    assert!(matches!(
        cpu.run_retirement_budget(10).unwrap().stop,
        RetirementStop::Fault(_)
    ));
    check_clock(&clock, 0);
    cpu.stepping = false;
    assert_eq!(cpu.run_retirement_budget(0).unwrap().retired, 0);
    assert!(cpu.run_retirement_budget(1).is_err());
    assert_eq!(cpu.seen.len(), 1);
    check_clock(&clock, 0);
}
#[test]
fn backend_counter_wrap_does_not_lose_clock_progress() {
    let clock = retired_clock();
    let _binding = clock.enter();
    let mut cpu = Observer::new();
    cpu.count = u64::MAX;
    assert_eq!(cpu.run_retirement_budget(2).unwrap().retired, 2);
    assert_eq!(cpu.count, 1);
    assert_eq!(cpu.seen, [0, 1]);
    check_clock(&clock, 2);
}
#[test]
fn nested_contexts_and_wall_binding_route_to_selected_clock() {
    let first = retired_clock();
    let second = retired_clock();
    let _first = first.enter();
    let mut cpu = Observer::new();
    cpu.run_retirement_budget(1).unwrap();
    {
        let _second = second.enter();
        cpu.run_retirement_budget(2).unwrap();
        {
            let wall = Arc::new(TimingContext::new());
            let _wall = wall.enter();
            cpu.run_retirement_budget(3).unwrap();
            assert_eq!(wall.checkpoint_state().retired_units, 0);
            assert_eq!(wall.checkpoint_state().subnanosecond_quanta, 0);
        }
        cpu.run_retirement_budget(1).unwrap();
    }
    cpu.run_retirement_budget(2).unwrap();
    check_clock(&first, 3);
    check_clock(&second, 3);
}
#[test]
fn direct_steps_keep_explicit_clock_ownership() {
    let clock = retired_clock();
    let _binding = clock.enter();
    let (mut cpu, _) = machine(0);
    cpu.step_insn().unwrap();
    check_clock(&clock, 0);
    cpu.run_retirement_budget(1).unwrap();
    check_clock(&clock, 1);
}
#[test]
fn saved_fraction_continues_at_next_successful_step() {
    let clock = retired_clock();
    let mut state = clock.checkpoint_state();
    state.elapsed_nanos = u64::MAX;
    state.retired_units = u64::MAX;
    state.subnanosecond_quanta = 2;
    clock.restore_checkpoint_state(&state).unwrap();
    let _binding = clock.enter();
    let mut cpu = Observer::new();
    cpu.run_retirement_budget(1).unwrap();
    let state = clock.checkpoint_state();
    assert_eq!(
        (
            state.elapsed_nanos,
            state.retired_units,
            state.subnanosecond_quanta
        ),
        (0, 0, 0)
    );
}
pub fn emit_reference(path: &std::path::Path) {
    let mut bytes = Vec::new();
    for kind in 0..12 {
        let clock = retired_clock();
        let _binding = clock.enter();
        let (mut cpu, _) = machine(kind);
        for budget in [0, 1, 2, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            let s = clock.checkpoint_state();
            for word in [
                u64::from(kind),
                budget,
                r.retired,
                cpu.current_pc(),
                s.retired_units,
                s.elapsed_nanos,
                u64::from(s.subnanosecond_quanta),
            ] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    let clock = retired_clock();
    let _binding = clock.enter();
    let mut cpu = Observer::new();
    cpu.run_retirement_budget(1000).unwrap();
    for word in cpu.seen {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    std::fs::write(path, bytes).unwrap();
}
