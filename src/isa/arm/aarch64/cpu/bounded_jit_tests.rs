//! Pair-access aborts preserve registers and never replay an MMIO side effect.
use super::*;
use crate::isa::arm::common::memory::{FlatMemory, MemResult, MemoryError, MmioHandler};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Default)]
struct Observations {
    fail_second: AtomicBool,
    calls: Mutex<Vec<(bool, u64, usize)>>,
}

#[derive(Debug)]
struct Memory {
    ram: FlatMemory,
    observations: Arc<Observations>,
}

impl ArmMemory for Memory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        if (0x800..0x810).contains(&address) {
            self.observations
                .calls
                .lock()
                .unwrap()
                .push((false, address, bytes.len()));
            if address == 0x808 && self.observations.fail_second.load(Ordering::Relaxed) {
                return Err(MemoryError::BusError { addr: address });
            }
        }
        self.ram.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> MemResult<()> {
        if (0x800..0x810).contains(&address) {
            self.observations
                .calls
                .lock()
                .unwrap()
                .push((true, address, bytes.len()));
            if address == 0x808 && self.observations.fail_second.load(Ordering::Relaxed) {
                return Err(MemoryError::BusError { addr: address });
            }
        }
        self.ram.write(address, bytes)
    }
    fn mark_exclusive(&mut self, address: u64, size: u8) {
        self.ram.mark_exclusive(address, size);
    }
    fn check_exclusive(&mut self, address: u64, size: u8) -> bool {
        self.ram.check_exclusive(address, size)
    }
    fn clear_exclusive(&mut self) {
        self.ram.clear_exclusive();
    }
    fn requires_alignment(&self) -> bool {
        false
    }
    fn register_mmio(&mut self, base: u64, size: u64, handler: Box<dyn MmioHandler>) {
        self.ram.register_mmio(base, size, handler);
    }
    fn unregister_mmio(&mut self, base: u64) {
        self.ram.unregister_mmio(base);
    }
}

fn machine(word: u32) -> (AArch64Cpu, Arc<Observations>) {
    let observations = Arc::new(Observations::default());
    let mut ram = FlatMemory::new(0, 0x2000);
    ram.write_u32(0x100, word).unwrap();
    ram.write_u64(0x800, 0x1111_2222_3333_4444).unwrap();
    ram.write_u64(0x808, 0x5555_6666_7777_8888).unwrap();
    let mut cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(Memory {
            ram,
            observations: observations.clone(),
        }),
    );
    cpu.set_pc(0x100);
    cpu.set_x(0, 0xaaaa);
    cpu.set_x(1, 0x800);
    cpu.set_x(2, 0xbbbb);
    cpu.set_jit_mem(true);
    (cpu, observations)
}

#[test]
fn declined_pair_second_load_abort_preserves_both_destinations_and_exact_accesses() {
    let (mut cpu, observations) = machine(0xa940_0820); // LDP X0,X2,[X1]
    assert!(
        cpu.jit_compile_bounded().is_none(),
        "pair helpers are not admitted by the existing native gate"
    );
    assert!(observations.calls.lock().unwrap().is_empty());
    observations.fail_second.store(true, Ordering::Relaxed);
    cpu.jit.hot.insert(0x100, A64_JIT_HOT_THRESHOLD - 1);
    assert!(
        matches!(cpu.step_system_bounded(true), Err(ArmError::MemoryError(info))
        if info.address == 0x808 && info.access == crate::isa::arm::common::cpu::AccessType::Read)
    );
    assert_eq!(cpu.jit.bounded_runs, 0);
    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
    assert_eq!(
        (cpu.get_x(0), cpu.get_x(1), cpu.get_x(2)),
        (0xaaaa, 0x800, 0xbbbb)
    );
    assert_eq!(
        *observations.calls.lock().unwrap(),
        vec![(false, 0x800, 8), (false, 0x808, 8)]
    );
}

#[test]
fn declined_pair_second_store_abort_preserves_the_first_side_effect_once() {
    let (mut cpu, observations) = machine(0xa900_0820); // STP X0,X2,[X1]
    assert!(
        cpu.jit_compile_bounded().is_none(),
        "pair helpers are not admitted by the existing native gate"
    );
    assert!(observations.calls.lock().unwrap().is_empty());
    observations.fail_second.store(true, Ordering::Relaxed);
    cpu.jit.hot.insert(0x100, A64_JIT_HOT_THRESHOLD - 1);
    assert!(
        matches!(cpu.step_system_bounded(true), Err(ArmError::MemoryError(info))
        if info.address == 0x808 && info.access == crate::isa::arm::common::cpu::AccessType::Write)
    );
    assert_eq!(cpu.jit.bounded_runs, 0);
    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
    assert_eq!(
        *observations.calls.lock().unwrap(),
        vec![(true, 0x800, 8), (true, 0x808, 8)]
    );
    observations.fail_second.store(false, Ordering::Relaxed);
    assert_eq!(cpu.mem_read_u64(0x800).unwrap(), 0xaaaa);
    assert_eq!(cpu.mem_read_u64(0x808).unwrap(), 0x5555_6666_7777_8888);
}

#[test]
fn native_preindex_load_abort_preserves_base_destination_and_exact_single_access() {
    let (mut cpu, observations) = machine(0xf840_8c20); // LDR X0,[X1,#8]!
    let region = cpu
        .jit_compile_bounded()
        .expect("bounded native pre-index LDR");
    observations.fail_second.store(true, Ordering::Relaxed);
    assert!(cpu.jit_run_bounded(&region));
    assert!(
        matches!(cpu.execution.native_fault.as_ref(), Some(ArmError::MemoryError(info))
        if info.address == 0x808 && info.access == crate::isa::arm::common::cpu::AccessType::Read)
    );
    assert_eq!(cpu.jit.bounded_runs, 1);
    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
    assert_eq!(
        (cpu.get_x(0), cpu.get_x(1), cpu.get_x(2)),
        (0xaaaa, 0x800, 0xbbbb)
    );
    assert_eq!(*observations.calls.lock().unwrap(), vec![(false, 0x808, 8)]);
}

#[test]
fn private_capture_rejects_an_active_native_instruction_and_accepts_its_quiescent_frontier() {
    let (mut cpu, _) = machine(0x9100_0400);
    let before = CoreCheckpoint::capture(&cpu).unwrap();
    cpu.jit.bounded_active = true;
    assert!(matches!(
        CoreCheckpoint::capture(&cpu),
        Err(ArmError::Configuration(_))
    ));
    cpu.jit.bounded_active = false;
    assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
}
