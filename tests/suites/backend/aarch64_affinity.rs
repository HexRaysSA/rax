//! Configured AArch64 PE affinity through actual guest MRS and state transfer.
use rax::backend::emulator::aarch64::Aarch64Vcpu;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::ArmCpu;
use rax::isa::arm::common::memory::FlatMemory;
use rax::vm::vcpu::{CpuState, RetirementStop, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const ENTRY: u64 = 0x1000;
const IDS: [u32; 8] = [0, 1, 255, 256, 0xffff, 0x00ff_ffff, 0x0100_0000, u32::MAX];
fn core(id: u32) -> AArch64Cpu {
    AArch64Cpu::new_with_cpu_id(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x4000)),
        id,
    )
}
fn identity(cpu: &AArch64Cpu) -> u64 {
    cpu.export_sregs().execution.unwrap().sysregs.mpidr_el1
}
fn expected(id: u32) -> u64 {
    let a = id.to_le_bytes();
    0x80000000
        | u64::from(a[0])
        | (u64::from(a[1]) << 8)
        | (u64::from(a[2]) << 16)
        | (u64::from(a[3]) << 32)
}
fn machine(id: u32, system: bool) -> Aarch64Vcpu {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    m.write_slice(&0xd53800a5u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    let mut c = if system {
        Aarch64Vcpu::new(id, m)
    } else {
        Aarch64Vcpu::new_micro(id, m)
    };
    c.set_current_pc(ENTRY).unwrap();
    c
}
fn read(c: &mut Aarch64Vcpu) -> u64 {
    let r = c.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 1);
    assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
    let CpuState::Aarch64(s) = c.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(s.regs.pc, ENTRY + 4);
    s.regs.x[5]
}
#[test]
fn original_constructor_retains_cpu_zero() {
    let c = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x4000)),
    );
    assert_eq!(identity(&c), 0x80000000);
}
#[test]
fn affinity_levels_preserve_every_input_byte() {
    for id in IDS {
        assert_eq!(identity(&core(id)), expected(id));
    }
}
#[test]
fn all_reserved_control_bits_are_clear() {
    for id in 0..=254 {
        assert_eq!(AArch64Cpu::mpidr_for_cpu_id(id), 0x80000000 | u64::from(id));
    }
    for id in IDS {
        let v = AArch64Cpu::mpidr_for_cpu_id(id);
        assert_eq!(v & !0x000000ff80ffffff, 0);
        assert_eq!(v & (1 << 31), 1 << 31);
    }
}
#[test]
fn full_width_seeded_ids_roundtrip_affinity() {
    let mut x = 0x12345678u32;
    for _ in 0..10000 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let a = AArch64Cpu::mpidr_for_cpu_id(x);
        assert_eq!(((a >> 32) as u32) << 24 | ((a as u32) & 0xffffff), x);
        assert_eq!(a, expected(x));
    }
}
#[test]
fn warm_reset_preserves_affinity_and_resets_gprs() {
    for id in IDS {
        let mut c = core(id);
        c.set_gpr(0, 77);
        c.reset();
        assert_eq!(identity(&c), expected(id));
        assert_eq!(c.get_gpr(0), 0);
    }
}
#[test]
fn complete_import_preserves_destination_readonly_identity() {
    for id in IDS {
        let mut c = core(id);
        let mut s = c.export_sregs();
        s.execution.as_mut().unwrap().sysregs.mpidr_el1 = u64::MAX;
        s.tpidr_el0 = 99;
        c.import_sregs(&s).unwrap();
        assert_eq!(identity(&c), expected(id));
        assert_eq!(c.export_sregs().tpidr_el0, 99);
    }
}
#[test]
fn partial_import_preserves_identity() {
    let mut c = core(0x12345678);
    let mut s = c.export_sregs();
    s.execution = None;
    c.import_sregs(&s).unwrap();
    assert_eq!(identity(&c), expected(0x12345678));
}
#[test]
fn both_adapter_paths_execute_guest_mrs_with_requested_affinity() {
    for system in [false, true] {
        for id in IDS {
            let mut c = machine(id, system);
            assert_eq!(c.id(), id);
            assert_eq!(read(&mut c), expected(id));
        }
    }
}
#[test]
fn backend_set_state_preserves_configured_identity() {
    for id in IDS {
        let mut c = machine(id, false);
        let mut s = c.get_state().unwrap();
        let CpuState::Aarch64(a) = &mut s else {
            panic!()
        };
        a.sregs.execution.as_mut().unwrap().sysregs.mpidr_el1 = 0;
        a.regs.x[7] = 99;
        c.set_state(&s).unwrap();
        assert_eq!(read(&mut c), expected(id));
        let CpuState::Aarch64(a) = c.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(a.regs.x[7], 99);
    }
}
#[test]
fn backend_update_preserves_configured_identity_and_count() {
    for id in IDS {
        let mut c = machine(id, false);
        assert_eq!(read(&mut c), expected(id));
        let mut s = c.get_state().unwrap();
        let CpuState::Aarch64(a) = &mut s else {
            panic!()
        };
        a.sregs.execution.as_mut().unwrap().sysregs.mpidr_el1 = 0;
        a.regs.pc = ENTRY;
        c.update_state(&s).unwrap();
        assert_eq!(c.instruction_count(), 1);
        assert_eq!(read(&mut c), expected(id));
        assert_eq!(c.instruction_count(), 2);
    }
}
#[test]
fn one_two_four_objects_have_distinct_guest_affinities() {
    for count in [1, 2, 4] {
        let v: Vec<_> = (0..count).map(|id| read(&mut machine(id, false))).collect();
        assert_eq!(v, (0..count).map(expected).collect::<Vec<_>>());
    }
}
pub fn emit_reference(path: &std::path::Path) {
    let mut b = Vec::new();
    for system in [false, true] {
        for id in IDS {
            let mut c = machine(id, system);
            let v = read(&mut c);
            for n in [
                u64::from(system),
                u64::from(id),
                v,
                c.current_pc(),
                c.instruction_count(),
            ] {
                b.extend_from_slice(&n.to_le_bytes());
            }
        }
    }
    std::fs::write(path, b).unwrap();
}
