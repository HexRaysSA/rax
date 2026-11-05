//! Public RAX API observation to compare with the independent KVM INIT control.
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::memory::vm::{GuestAddress, GuestMemoryMmap};
use rax::vm::vcpu::{CpuState, VCpu};
use std::sync::Arc;

fn main() {
    let mut mismatches = 0;
    let mut observations = 0;
    let mut reset_mismatches = 0;
    for count in [1, 2, 4] {
        for cache in [0, 0x4000_0000, 0x6000_0000] {
            for id in 0..count {
                let memory =
                    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap());
                let mut cpu = X86_64Vcpu::new(id, memory);
                let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                let initial_cr0 = state.sregs.cr0;
                reset_mismatches += usize::from(initial_cr0 != 0x6000_0010);
                state.sregs.cr0 = cache | 0x0001_0031;
                state.regs.rax = 0xa5;
                cpu.set_state(&CpuState::X86_64(state)).unwrap();
                cpu.deliver_init().unwrap();
                let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                let expected = cache | 0x10;
                let actual = state.sregs.cr0;
                assert_eq!(state.regs.rax, 0);
                assert_eq!(state.regs.rip, 0xfff0);
                cpu.reset().unwrap();
                let CpuState::X86_64(reset) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                let after_reset = reset.sregs.cr0;
                reset_mismatches += usize::from(after_reset != 0x6000_0010);
                observations += 1;
                mismatches += usize::from(actual != expected);
                println!(
                    "{{\"cpus\":{count},\"id\":{id},\"cache\":{cache},\"expected\":{expected},\"actual\":{actual},\"initial_cr0\":{initial_cr0},\"after_reset\":{after_reset},\"reset_expected\":1610612752}}"
                );
            }
        }
    }
    eprintln!(
        "INIT_CACHE observations={observations} mismatches={mismatches} reset_mismatches={reset_mismatches}"
    );
    assert_eq!(mismatches, 0);
    assert_eq!(reset_mismatches, 0);
}
