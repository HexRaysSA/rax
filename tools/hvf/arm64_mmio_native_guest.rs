//! Actual signed native RAX ARM64 MMIO transaction consumer.
use rax::backend::{
    Backend,
    hvf::{HvfArm64Backend, HvfArm64Vm},
};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::vcpu::{
    Aarch64CpuState, Aarch64Registers, Aarch64SystemRegisters, CpuState, VCpu, VcpuExit,
};
use std::{path::PathBuf, sync::Arc};
use vm_memory::{Bytes, GuestAddress};
const BASE: u64 = 0x40000000;
const SEED: u64 = 0x1122334455667788;
fn event(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        let e = cpu.run().unwrap();
        if !matches!(e, VcpuExit::Hlt) {
            return e;
        }
    }
    panic!("no architectural exit");
}
fn state(cpu: &dyn VCpu) -> Aarch64CpuState {
    let CpuState::Aarch64(s) = cpu.get_state().unwrap() else {
        panic!()
    };
    s
}
fn initial(pc: u64) -> CpuState {
    let mut regs = Aarch64Registers {
        pc,
        sp: BASE + 0x3ff0,
        pstate: 0x3c5,
        ..Default::default()
    };
    regs.x[0] = SEED;
    regs.x[1] = 0x09000000;
    CpuState::aarch64(regs, Aarch64SystemRegisters::default())
}
fn record(rows: &mut Vec<u64>, cpu: &dyn VCpu, index: [u64; 4], exit: Option<VcpuExit>) {
    let (kind, addr, size) = match exit {
        None => (0, 0, 0),
        Some(VcpuExit::MmioRead { addr, size }) => (1, addr, u64::from(size)),
        Some(VcpuExit::Unknown(s)) if s == "Instruction abort at 0x200" => (2, 0, 0),
        other => panic!("unexpected exit: {other:?}"),
    };
    let s = state(cpu);
    rows.extend(index);
    rows.extend([
        kind,
        addr,
        size,
        s.regs.x[0],
        s.regs.x[10],
        s.regs.pc,
        s.regs.pstate,
        s.regs.sp,
    ]);
}
fn main() {
    let out = PathBuf::from(std::env::args_os().nth(1).unwrap());
    let backend = HvfArm64Backend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(BASE + 0x4000).unwrap();
    let code = std::fs::read(out.join("guest.bin")).unwrap();
    memory
        .memory()
        .write_slice(&code, GuestAddress(BASE))
        .unwrap();
    vm.as_any()
        .downcast_ref::<HvfArm64Vm>()
        .unwrap()
        .register_memory(&memory, BASE, 0x4000)
        .unwrap();
    let mut rows = Vec::new();
    for (case, size) in [1u8, 1, 1, 2, 2, 2, 4, 4, 8].into_iter().enumerate() {
        let modulus = 1u128 << (size * 8);
        let sign = modulus / 2;
        for (destination, rt) in [0u64, 31].into_iter().enumerate() {
            let pc = BASE + ((case * 2 + destination) * 16) as u64;
            for (pattern, value) in [
                0,
                1,
                modulus - 1,
                sign,
                sign - 1,
                0x8877665544332211 % modulus,
            ]
            .into_iter()
            .enumerate()
            {
                let mut cpu = vm
                    .create_vcpu(0, Arc::new(memory.memory().clone()))
                    .unwrap();
                cpu.set_state(&initial(pc)).unwrap();
                let first = event(&mut *cpu);
                record(
                    &mut rows,
                    &*cpu,
                    [case as u64, rt, pattern as u64, 0],
                    Some(first),
                );
                let before = format!("{:?}", cpu.get_state().unwrap());
                cpu.complete_io_in(&[]);
                assert_eq!(before, format!("{:?}", cpu.get_state().unwrap()));
                record(&mut rows, &*cpu, [case as u64, rt, pattern as u64, 1], None);
                let pending = event(&mut *cpu);
                record(
                    &mut rows,
                    &*cpu,
                    [case as u64, rt, pattern as u64, 2],
                    Some(pending),
                );
                let payload = (value as u64).to_le_bytes();
                cpu.complete_io_in(&payload[..usize::from(size) - 1]);
                assert_eq!(before, format!("{:?}", cpu.get_state().unwrap()));
                record(&mut rows, &*cpu, [case as u64, rt, pattern as u64, 3], None);
                let pending = event(&mut *cpu);
                record(
                    &mut rows,
                    &*cpu,
                    [case as u64, rt, pattern as u64, 4],
                    Some(pending),
                );
                let mut complete = payload[..usize::from(size)].to_vec();
                if pattern % 2 == 1 {
                    complete.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
                }
                cpu.complete_io_in(&complete);
                record(&mut rows, &*cpu, [case as u64, rt, pattern as u64, 5], None);
                let done = event(&mut *cpu);
                record(
                    &mut rows,
                    &*cpu,
                    [case as u64, rt, pattern as u64, 6],
                    Some(done),
                );
                drop(cpu);
            }
        }
    }
    // Invalid state admission must retain the old request. Successful state
    // replacement must cancel it, including a later reply for that request.
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let pc = BASE + 16 * 16;
    cpu.set_state(&initial(pc)).unwrap();
    let first = event(&mut *cpu);
    assert!(matches!(first, VcpuExit::MmioRead { size: 8, .. }));
    let before = format!("{:?}", cpu.get_state().unwrap());
    let mut invalid = state(&*cpu);
    invalid.regs.pstate = 0x3c1;
    let admission = cpu.set_state(&CpuState::Aarch64(invalid));
    std::fs::write(out.join("admission.txt"), format!("{admission:?}")).unwrap();
    assert!(admission.is_err());
    assert_eq!(before, format!("{:?}", cpu.get_state().unwrap()));
    record(&mut rows, &*cpu, [99, 0, 0, 8], None);
    let pending = event(&mut *cpu);
    record(&mut rows, &*cpu, [99, 0, 0, 9], Some(pending));
    let mut replacement = state(&*cpu);
    replacement.regs.x[0] = 0xaabbccddeeff0011;
    cpu.set_state(&CpuState::Aarch64(replacement)).unwrap();
    record(&mut rows, &*cpu, [99, 0, 0, 10], None);
    cpu.complete_io_in(&[0xff; 8]);
    record(&mut rows, &*cpu, [99, 0, 0, 11], None);
    let done = event(&mut *cpu);
    record(&mut rows, &*cpu, [99, 0, 0, 12], Some(done));
    std::fs::write(
        out.join("rows.bin"),
        rows.into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    drop(cpu);
    drop(vm);
}
