//! Actual retired firmware calls remain charged when host completion fails.
use super::*;
use crate::backend::emulator::aarch64::Aarch64Vcpu;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::{RetirementStop, VCpu};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const ENTRY: u64 = 0x100;
const AFFINITY_INFO32: u64 = 0x8400_0004;

fn machine(call: u32, prefix: usize) -> (Aarch64Vcpu, Arc<ArmCluster>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let mut program = vec![0xd503_201fu32; prefix]; // NOP
    program.extend([call, 0x9100_0529]); // firmware call; ADD X9,X9,#1
    let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    memory.write_slice(&bytes, GuestAddress(ENTRY)).unwrap();
    let cluster = Arc::new(ArmCluster::new(1, 0x4000).unwrap());
    let mut cpu = Aarch64Vcpu::new_in_cluster(0, memory, cluster.clone()).unwrap();
    let mut controls = cpu.cpu.pauth_controls();
    controls.scr_el3 = 1 | (1 << 10) | (1 << 8); // NS, A64 EL2, HCE
    controls.hcr_el2 = 1 << 31; // A64 EL1
    cpu.cpu.set_pauth_controls(controls).unwrap();
    cpu.cpu.set_pc(ENTRY);
    cpu.cpu.set_x(0, AFFINITY_INFO32);
    cpu.cpu.set_x(1, 0);
    cpu.cpu.set_x(2, 0);
    cpu.cpu.set_x(9, 7);
    (cpu, cluster)
}

fn fail_host_control(cluster: &ArmCluster) {
    // Inject a host failure after construction without changing guest inputs
    // or the existing cluster state. Catch the deliberately injected panic.
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = cluster.control.lock().unwrap();
            panic!("injected host cluster-control failure");
        })
        .is_err()
    );
    assert!(cluster.control.is_poisoned());
}

fn failed_call(call: u32) {
    for prefix in [0, 1, 3] {
        for observed in [0, u64::MAX] {
            for budget in [prefix as u64 + 1, 1000] {
                let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
                let _binding = clock.enter();
                let (mut cpu, cluster) = machine(call, prefix);
                cpu.insn_count
                    .store(observed, std::sync::atomic::Ordering::Relaxed);
                fail_host_control(&cluster);
                let result = cpu.run_retirement_budget(budget).unwrap();
                match result.stop {
                    RetirementStop::Fault(Error::Emulator(ref message)) => {
                        assert_eq!(message, "AArch64 cluster: control lock poisoned");
                    }
                    ref other => panic!("unexpected firmware disposition: {other:?}"),
                }
                let completed = prefix as u64 + 1;
                assert_eq!(cpu.cpu.instruction_count(), completed);
                assert_eq!(cpu.instruction_count(), observed.wrapping_add(completed));
                assert_eq!(cpu.current_pc(), ENTRY + completed * 4);
                assert_eq!(
                    cpu.cpu.get_x(0),
                    AFFINITY_INFO32,
                    "failed completion publishes no result"
                );
                assert_eq!(cpu.cpu.get_x(9), 7, "the next instruction did not execute");
                assert_eq!(
                    (result.retired, clock.checkpoint_state().retired_units),
                    (completed, completed),
                    "call={call:08x}, prefix={prefix}, observed={observed}: CPU retirement preceded the host error"
                );
                // Repair the injected host failure and continue at the next
                // instruction without replaying the firmware call.
                cluster.control.clear_poison();
                let next = cpu.run_retirement_budget(1).unwrap();
                assert!(matches!(next.stop, RetirementStop::BudgetExhausted));
                assert_eq!(next.retired, 1);
                assert_eq!(cpu.cpu.get_x(9), 8);
                assert_eq!(clock.checkpoint_state().retired_units, completed + 1);
            }
        }
    }
}

#[test]
fn hvc_host_completion_failure_preserves_completed_retirement_and_clock() {
    failed_call(0xd400_0002); // HVC #0
}

#[test]
fn smc_host_completion_failure_preserves_completed_retirement_and_clock() {
    failed_call(0xd400_0003); // SMC #0
}

#[test]
fn healthy_firmware_query_control_retires_before_the_following_instruction() {
    for call in [0xd400_0002, 0xd400_0003] {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        let (mut cpu, _) = machine(call, 1);
        let result = cpu.run_retirement_budget(2).unwrap();
        assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
        assert_eq!(result.retired, 2);
        assert_eq!(cpu.instruction_count(), 2);
        assert_eq!(clock.checkpoint_state().retired_units, 2);
        assert_eq!(cpu.cpu.get_x(0), 0, "CPU0 is ON");
        assert_eq!(cpu.cpu.get_x(9), 7);
    }
}

#[test]
fn zero_budget_does_not_execute_or_consult_failed_firmware_control() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _binding = clock.enter();
    let (mut cpu, cluster) = machine(0xd400_0002, 0);
    fail_host_control(&cluster);
    let result = cpu.run_retirement_budget(0).unwrap();
    assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    assert_eq!(result.retired, 0);
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(cpu.current_pc(), ENTRY);
    assert_eq!(clock.checkpoint_state().retired_units, 0);
    assert!(cluster.control.is_poisoned());
}
