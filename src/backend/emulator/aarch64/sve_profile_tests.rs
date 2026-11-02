//! Scalable access controls and precise delivery through private backend records.
use super::super::Aarch64Vcpu;
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::{CpuState, RetirementStop, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const ENTRY: u64 = 0x100;
const PROFILES: [&str; 7] = [
    "local-el1-z0-f3",
    "sve2-el1",
    "sve3-el1",
    "local-el1-z3-f0",
    "sme-only-el1-not-streaming",
    "sme-only-local-sme",
    "absent-permitted-controls",
];

fn reference(name: &str) -> serde_json::Value {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-sve-access/oracle-cases.json"
    )))
    .unwrap();
    cases
        .into_iter()
        .find(|case| case["profile"]["name"] == name)
        .unwrap()
}

fn fixture(case: &serde_json::Value) -> Aarch64Vcpu {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    memory
        .write_slice(
            &(case["opcode"].as_u64().unwrap() as u32).to_le_bytes(),
            GuestAddress(ENTRY),
        )
        .unwrap();
    let target = case["target"].as_u64().unwrap();
    let handler = match target {
        1 => 0x1200,
        2 => 0x1c00,
        _ => 0x2400,
    };
    memory
        .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(handler))
        .unwrap(); // ADD X9,X9,#1
    let mut cpu = Aarch64Vcpu::new(0, memory);
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 0x3c5;
    state.regs.x[9] = 5;
    state.sregs.vbar_el1 = 0x1000;
    let execution = state.sregs.execution.as_mut().unwrap();
    let profile = &case["profile"];
    let mut features = ArmFeatures::from_bits_retain(execution.features);
    features.set(ArmFeatures::SVE, profile["present"].as_bool().unwrap());
    features.set(ArmFeatures::SME, profile["sme_only"].as_bool().unwrap());
    features.insert(ArmFeatures::VHE);
    execution.features = features.bits();
    let system = &mut execution.sysregs;
    system.el1.vbar = 0x1000;
    system.el2.vbar = 0x1800;
    system.el3.vbar = 0x2000;
    system.scr_el3 = 1 | (1 << 10);
    system.hcr_el2 = profile["hcr"].as_u64().unwrap();
    system.el1.cpacr = (profile["zen"].as_u64().unwrap() << 16)
        | (profile["fpen"].as_u64().unwrap() << 20)
        | (profile["smen"].as_u64().unwrap() << 24);
    for (op1, value) in [
        (4, profile["cptr2"].as_u64().unwrap()),
        (6, profile["cptr3"].as_u64().unwrap()),
    ] {
        system
            .impl_defined
            .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
    }
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    cpu
}

fn assert_delivery(cpu: &mut Aarch64Vcpu, case: &serde_json::Value) {
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 0, "{case}");
    assert!(
        matches!(result.stop, RetirementStop::StateChange),
        "{result:?}"
    );
    let state = cpu.get_state().unwrap();
    let state = state.as_aarch64().unwrap();
    let target = case["target"].as_u64().unwrap() as u8;
    assert_eq!((state.regs.pstate >> 2) & 3, u64::from(target));
    let bank = state.sregs.execution.as_ref().unwrap().sysregs.bank(target);
    assert_eq!(bank.elr, ENTRY);
    assert_eq!(bank.esr >> 26, case["ec"].as_u64().unwrap());
    assert_eq!(bank.esr & 7, case["iss"].as_u64().unwrap());
    assert_eq!(state.regs.x[9], 5);
    assert_eq!(cpu.instruction_count(), 0);
}

#[test]
fn restored_private_controls_preserve_denial_frontier_and_zero_retirement_clock() {
    for name in PROFILES {
        let case = reference(name);
        let mut source = fixture(&case);
        let public = source.get_state().unwrap();
        let private = source.capture_backend_context().unwrap().unwrap();
        assert!(private.data.starts_with(b"RAXA6405"));
        let mut target = fixture(&case);
        target
            .restore_checkpoint_context(&public, &Default::default(), Some(&private))
            .unwrap();
        assert_eq!(
            target.get_state().unwrap().as_aarch64().unwrap(),
            public.as_aarch64().unwrap()
        );
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        assert_delivery(&mut source, &case);
        assert_delivery(&mut target, &case);
        assert_eq!(
            target.get_state().unwrap().as_aarch64().unwrap(),
            source.get_state().unwrap().as_aarch64().unwrap()
        );
        assert_eq!(clock.checkpoint_state().retired_units, 0);
    }
}

#[test]
fn restored_delivered_fault_continues_at_handler_without_replaying_sve() {
    for name in PROFILES {
        let case = reference(name);
        let mut source = fixture(&case);
        assert_delivery(&mut source, &case);
        let public = source.get_state().unwrap();
        let private = source.capture_backend_context().unwrap().unwrap();
        let mut target = fixture(&case);
        target
            .restore_checkpoint_context(&public, &Default::default(), Some(&private))
            .unwrap();
        assert_eq!(target.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(source.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(target.instruction_count(), 1);
        assert_eq!(
            target.get_state().unwrap().as_aarch64().unwrap(),
            source.get_state().unwrap().as_aarch64().unwrap()
        );
        assert_eq!(
            target.get_state().unwrap().as_aarch64().unwrap().regs.x[9],
            6
        );
    }
}
