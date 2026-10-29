//! Cross-PE event delivery through actual clustered software adapters.
use super::*;
use crate::backend::emulator::aarch64::Aarch64Vcpu;
use crate::isa::arm::aarch64::cpu::CoreCheckpoint;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::vm::vcpu::{RetirementStop, VCpu, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const ENTRY: u64 = 0x100;
const WFE: u32 = 0xd503_205f;

fn address(id: usize) -> u64 {
    ENTRY + id as u64 * 0x100
}

fn machines(
    count: u8,
    sender: usize,
    program: &[u8],
    pstate: u64,
) -> (Vec<Aarch64Vcpu>, Arc<ArmCluster>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    for id in 0..usize::from(count) {
        let bytes: Vec<_> = [WFE, WFE].into_iter().flat_map(u32::to_le_bytes).collect();
        memory
            .write_slice(&bytes, GuestAddress(address(id)))
            .unwrap();
    }
    memory
        .write_slice(program, GuestAddress(address(sender)))
        .unwrap();
    let cluster = Arc::new(ArmCluster::new(count, 0x8000).unwrap());
    let mut cpus = Vec::new();
    for id in 0..count {
        let mut cpu =
            Aarch64Vcpu::new_in_cluster(u32::from(id), memory.clone(), cluster.clone()).unwrap();
        if id == 0 {
            cpu.set_current_pc(address(0)).unwrap();
        } else {
            assert_eq!(
                cluster
                    .request_on(u64::from(id), address(id as usize), 0, 0x3c5)
                    .unwrap(),
                0
            );
            let requests = cluster.take_requests().unwrap();
            assert!(
                matches!(&requests[..], [crate::vm::vcpu::CpuPowerRequest::Start { cpu_id, .. }] if *cpu_id == u32::from(id))
            );
            cpu.start_aarch64_cpu(address(id as usize), 0, 0x3c5)
                .unwrap();
            cluster.complete_start(u32::from(id)).unwrap();
        }
        cpus.push(cpu);
    }
    let cpu = &mut cpus[sender];
    let mut controls = cpu.cpu.pauth_controls();
    controls.scr_el3 |= 1 | (1 << 10);
    controls.hcr_el2 |= 1 << 31;
    cpu.cpu.set_pauth_controls(controls).unwrap();
    cpu.cpu.set_pstate_bits(pstate).unwrap();
    (cpus, cluster)
}

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn assert_continues(cpu: &mut Aarch64Vcpu) {
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert!(
        matches!(result.stop, RetirementStop::BudgetExhausted),
        "{result:?}"
    );
}

fn assert_waits(cpu: &mut Aarch64Vcpu) {
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert!(
        matches!(result.stop, RetirementStop::Exit(VcpuExit::Hlt)),
        "{result:?}"
    );
}

#[test]
fn sev_sets_every_online_peer_latch_for_bsp_and_ap_senders() {
    for count in [2, 4] {
        for sender in [0, usize::from(count) - 1] {
            let (mut cpus, _) = machines(count, sender, &words(&[0xd503_209f, WFE, WFE]), 0x3c5);
            assert_continues(&mut cpus[sender]);
            for cpu in &mut cpus {
                assert_continues(cpu);
                assert_waits(cpu); // An event latch coalesces to one bit.
            }
        }
    }
}

#[test]
fn sevl_is_local_and_one_wfe_consumes_the_pending_latch() {
    for count in [2, 4] {
        for sender in [0, usize::from(count) - 1] {
            let (mut cpus, _) = machines(count, sender, &words(&[0xd503_20bf, WFE, WFE]), 0x3c5);
            assert_continues(&mut cpus[sender]);
            for (id, cpu) in cpus.iter_mut().enumerate() {
                if id == sender {
                    assert_continues(cpu);
                }
                assert_waits(cpu);
            }
        }
    }
}

fn failed_arm_predicate(local: bool) {
    let hint = if local { 0x0320_f005 } else { 0x0320_f004 }; // SEVL.EQ / SEV.EQ, Z=0
    let (mut cpus, _) = machines(2, 0, &words(&[hint, 0xe320_f002]), 0x10);
    assert_continues(&mut cpus[0]);
    assert_waits(&mut cpus[0]);
    assert_waits(&mut cpus[1]);
}

fn failed_thumb_predicate(local: bool) {
    let hint = if local { 0xbf50u16 } else { 0xbf40u16 };
    let bytes: Vec<_> = [0xbf08u16, hint, 0xbf20]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect(); // IT EQ; hint; WFE
    let (mut cpus, _) = machines(2, 0, &bytes, 0x30);
    assert_continues(&mut cpus[0]); // IT EQ
    assert_continues(&mut cpus[0]); // Failed condition still retires.
    assert_waits(&mut cpus[0]);
    assert_waits(&mut cpus[1]);
}

#[test]
fn failed_arm_sev_predicate_sets_no_event() {
    failed_arm_predicate(false);
}
#[test]
fn failed_arm_sevl_predicate_sets_no_event() {
    failed_arm_predicate(true);
}
#[test]
fn failed_thumb_it_sev_predicate_sets_no_event() {
    failed_thumb_predicate(false);
}
#[test]
fn failed_thumb_it_sevl_predicate_sets_no_event() {
    failed_thumb_predicate(true);
}

#[test]
fn legacy_core_and_cluster_encoding_control() {
    let (mut cpus, cluster) = machines(2, 0, &words(&[0xd503_20bf, WFE]), 0x3c5);
    assert_continues(&mut cpus[0]);
    let first = crate::codec::serialize(&CoreCheckpoint::capture(&cpus[0].cpu).unwrap()).unwrap();
    let second = crate::codec::serialize(&CoreCheckpoint::capture(&cpus[1].cpu).unwrap()).unwrap();
    let platform = crate::codec::serialize(&cluster.checkpoint().unwrap()).unwrap();
    assert!(!first.is_empty() && !second.is_empty() && !platform.is_empty());
    if let Some(directory) = std::env::var_os("RAX_EVENT_REFERENCE_OUTPUT") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        for (name, bytes) in [
            ("cpu0.bin", first),
            ("cpu1.bin", second),
            ("cluster.bin", platform),
        ] {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
    }
}

fn executed_sevl_is_local(program: &[u8], pstate: u64) {
    let (mut cpus, _) = machines(2, 0, program, pstate);
    assert_continues(&mut cpus[0]);
    assert_continues(&mut cpus[0]);
    assert_waits(&mut cpus[1]);
}

#[test]
fn executed_arm_sevl_sets_local_latch() {
    executed_sevl_is_local(&words(&[0xe320_f005, 0xe320_f002]), 0x10);
}

#[test]
fn executed_thumb16_sevl_sets_local_latch() {
    executed_sevl_is_local(&[0x50, 0xbf, 0x20, 0xbf], 0x30);
}

#[test]
fn executed_thumb32_sevl_sets_local_latch() {
    executed_sevl_is_local(&[0xaf, 0xf3, 0x05, 0x80, 0x20, 0xbf], 0x30);
}

fn failed_wide_thumb_predicate(local: bool) {
    let hint = if local { 0x05 } else { 0x04 };
    let bytes = [0x08, 0xbf, 0xaf, 0xf3, hint, 0x80, 0x20, 0xbf];
    let (mut cpus, _) = machines(2, 0, &bytes, 0x30);
    assert_continues(&mut cpus[0]);
    assert_continues(&mut cpus[0]);
    assert_waits(&mut cpus[0]);
    assert_waits(&mut cpus[1]);
}

#[test]
fn failed_thumb32_it_sev_predicate_sets_no_event() {
    failed_wide_thumb_predicate(false);
}

#[test]
fn failed_thumb32_it_sevl_predicate_sets_no_event() {
    failed_wide_thumb_predicate(true);
}

#[test]
fn executed_arm_and_thumb_sev_signals_every_peer() {
    let programs = [
        (words(&[0xe320_f004, 0xe320_f002]), 0x10),
        (vec![0x40, 0xbf, 0x20, 0xbf], 0x30),
        (vec![0xaf, 0xf3, 0x04, 0x80, 0x20, 0xbf], 0x30),
    ];
    for (program, pstate) in programs {
        for count in [2, 4] {
            for sender in [0, usize::from(count) - 1] {
                let (mut cpus, _) = machines(count, sender, &program, pstate);
                assert_continues(&mut cpus[sender]);
                for cpu in &mut cpus {
                    assert_continues(cpu);
                }
            }
        }
    }
}

#[test]
fn repeated_sev_coalesces_and_a_waiting_peer_consumes_a_new_signal() {
    let (mut cpus, _) = machines(2, 0, &words(&[0xd503_209f, 0xd503_209f]), 0x3c5);
    assert_continues(&mut cpus[0]);
    assert_continues(&mut cpus[0]);
    assert_continues(&mut cpus[1]);
    assert_waits(&mut cpus[1]);
    cpus[0].cpu.set_pc(address(0));
    assert_continues(&mut cpus[0]);
    // Install the instruction following the already-retired WFE.
    cpus[1]
        .cpu
        .write_memory(address(1) + 8, &0xd503_201fu32.to_le_bytes())
        .unwrap();
    assert_continues(&mut cpus[1]);
    assert!(!cpus[1].cpu.event_pending());
}

#[test]
fn poisoned_event_fanout_fails_before_local_peer_or_architectural_publication() {
    let programs = [
        (words(&[0xd503_209f]), 0x3c5, false),
        (words(&[0xe320_f004]), 0x10, false),
        (vec![0x40, 0xbf], 0x30, false),
        (vec![0xaf, 0xf3, 0x04, 0x80], 0x30, false),
        (vec![0x08, 0xbf, 0x40, 0xbf], 0x4000_0030, true),
        (vec![0x08, 0xbf, 0xaf, 0xf3, 0x04, 0x80], 0x4000_0030, true),
    ];
    for (program, pstate, it) in programs {
        let (mut cpus, cluster) = machines(2, 0, &program, pstate);
        if it {
            assert_continues(&mut cpus[0]);
        }
        let before = cpus[0].get_state().unwrap();
        let retired = cpus[0].instruction_count();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = cluster.control.lock().unwrap();
                panic!("deliberate event control poison");
            }))
            .is_err()
        );
        let result = cpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 0);
        assert!(
            matches!(&result.stop, RetirementStop::Exit(VcpuExit::Unknown(error)) if error.contains("control lock poisoned")),
            "{result:?}"
        );
        assert_eq!(cpus[0].instruction_count(), retired);
        let after = cpus[0].get_state().unwrap();
        assert_eq!(
            before.as_aarch64().unwrap().regs,
            after.as_aarch64().unwrap().regs
        );
        for cpu in &cpus {
            assert!(!cpu.cpu.event_pending());
        }
    }
}
