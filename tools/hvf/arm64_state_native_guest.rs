use rax::backend::{Backend, hvf::HvfArm64Backend};
use rax::vm::memory::vm::{GuestAddress, GuestMemoryMmap};
use rax::vm::vcpu::{Aarch64Registers, Aarch64SystemRegisters, CpuState};
use std::sync::Arc;
fn main() {
    let out = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let backend = HvfArm64Backend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let mut cpu = vm.create_vcpu(0, memory).unwrap();
    let mut bytes = Vec::new();
    for mode in [0u64, 4, 5] {
        for requested in [0, 1, 0x1111222233334444, u64::MAX] {
            let mut regs = Aarch64Registers {
                sp: requested,
                pstate: 0x3c0 | mode,
                ..Default::default()
            };
            regs.x[0] = 0x1234;
            let sregs = Aarch64SystemRegisters {
                sp_el0: 0x5555666677778888,
                sp_el1: 0x9999aaaabbbbcccc,
                ..Default::default()
            };
            cpu.set_state(&CpuState::aarch64(regs, sregs)).unwrap();
            let CpuState::Aarch64(s) = cpu.get_state().unwrap() else {
                panic!()
            };
            for word in [mode, requested, s.regs.sp, s.sregs.sp_el0, s.sregs.sp_el1] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    std::fs::write(out.join("rows.bin"), bytes).unwrap();
    let before = cpu.get_state().unwrap();
    let before_text = format!("{:?}", before);
    let mut bad = before.clone();
    let CpuState::Aarch64(ref mut s) = bad else {
        panic!()
    };
    s.regs.x[0] = 0xfeed_beef;
    s.regs.pstate = 0x3c1;
    let result = cpu.set_state(&bad);
    let after = cpu.get_state().unwrap();
    let after_text = format!("{:?}", after);
    let CpuState::Aarch64(ref a) = after else {
        panic!()
    };
    let values = [
        u64::from(result.is_ok()),
        u64::from(before_text == after_text),
        a.regs.x[0],
    ];
    std::fs::write(
        out.join("admission.bin"),
        values
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    std::fs::write(out.join("before.txt"), before_text).unwrap();
    std::fs::write(out.join("after.txt"), after_text).unwrap();
    std::fs::write(out.join("admission.txt"), format!("{:?}", result)).unwrap();
    drop(cpu);
    drop(vm);
}
