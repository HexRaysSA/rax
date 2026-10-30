//! Actual per-CPU identity and mutable BSP state through a full VM checkpoint.
use super::*;
use crate::config::{CliConfig, MemorySize};
use vm_memory::{Bytes, GuestAddress};

const CODE: u64 = 0x8000;
fn fixture() -> Vmm {
    let mut config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            vcpus: Some(2),
            kernel: Some(std::env::current_exe().unwrap()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    config.memory = MemorySize(65536);
    Vmm::new_resume(config).unwrap()
}
fn prepare(vm: &mut Vmm, index: usize, leaf: u64, value: u64) {
    let mut state = vm.vcpus[index].get_state().unwrap();
    let CpuState::X86_64(cpu) = &mut state else {
        panic!()
    };
    cpu.regs.rip = CODE;
    cpu.regs.rax = value;
    cpu.regs.rdx = 0;
    cpu.regs.rcx = leaf;
    cpu.regs.rflags = 2;
    cpu.sregs.cr0 = 0x50033;
    cpu.sregs.cr4 = 1 << 5;
    cpu.sregs.efer = (1 << 8) | (1 << 10);
    cpu.sregs.cs.l = true;
    cpu.sregs.cs.selector = 0;
    vm.vcpus[index].set_state(&state).unwrap();
}

#[test]
fn full_vm_bundle_preserves_written_bsp_flags_and_each_cpus_initial_identity() {
    let mut vm = fixture();
    for (index, value) in [(0, 0xfee0_0800), (1, 0xfee0_0900)] {
        vm.guest_mem
            .memory()
            .write_slice(&[0x0f, 0x30], GuestAddress(CODE))
            .unwrap();
        prepare(&mut vm, index, 0x1b, value);
        assert!(vm.vcpus[index].step_insn().unwrap().is_none());
    }
    let bundle = vm.take_snapshot_bundle(0).unwrap();
    for (index, value) in [(0, 0xfee0_0900), (1, 0xfee0_0800)] {
        prepare(&mut vm, index, 0x1b, value);
        assert!(vm.vcpus[index].step_insn().unwrap().is_none());
    }
    vm.restore_snapshot_bundle(&bundle).unwrap();
    vm.guest_mem
        .memory()
        .write_slice(&[0x0f, 0x32], GuestAddress(CODE))
        .unwrap();
    for (index, expected) in [(0, 0xfee0_0800), (1, 0xfee0_0900)] {
        prepare(&mut vm, index, 0x1b, 0);
        assert!(vm.vcpus[index].step_insn().unwrap().is_none());
        let CpuState::X86_64(cpu) = vm.vcpus[index].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(cpu.regs.rax, expected);
        assert_eq!(cpu.regs.rdx, 0);
    }
    vm.guest_mem
        .memory()
        .write_slice(&[0x0f, 0xa2], GuestAddress(CODE))
        .unwrap();
    for index in 0..2 {
        prepare(&mut vm, index, 0, 1);
        assert!(vm.vcpus[index].step_insn().unwrap().is_none());
        let CpuState::X86_64(cpu) = vm.vcpus[index].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(cpu.regs.rbx >> 24, index as u64);
    }
}

#[test]
fn init_and_sipi_follow_written_bootstrap_roles_instead_of_cpu_index() {
    let mut vm = fixture();
    for (index, value) in [(0, 0xfee0_0800), (1, 0xfee0_0900)] {
        vm.guest_mem
            .memory()
            .write_slice(&[0x0f, 0x30], GuestAddress(CODE))
            .unwrap();
        prepare(&mut vm, index, 0x1b, value);
        assert!(vm.vcpus[index].step_insn().unwrap().is_none());
        {
            let mut sender = vm.local_apics[0].lock().unwrap();
            sender.write_register(0x310, (index as u32) << 24);
            sender.write_register(0x300, 0x4500);
        }
        vm.route_interprocessor_requests().unwrap();
        assert_eq!(vm.coordinator.online[index], index == 1);
        assert_eq!(
            vm.vcpus[index].is_bootstrap_processor().unwrap(),
            index == 1
        );
        let before = vm.vcpus[index].get_regs().unwrap().rip;
        {
            let mut sender = vm.local_apics[0].lock().unwrap();
            sender.write_register(0x310, (index as u32) << 24);
            sender.write_register(0x300, 0x4607);
        }
        vm.route_interprocessor_requests().unwrap();
        assert!(vm.coordinator.online[index]);
        let state = vm.vcpus[index].get_sregs().unwrap();
        assert_eq!(state.cs.base, if index == 0 { 0x7000 } else { 0xffff_0000 });
        assert_eq!(
            vm.vcpus[index].get_regs().unwrap().rip,
            if index == 0 { 0 } else { before }
        );
    }
}
