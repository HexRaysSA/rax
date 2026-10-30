//! Priority ownership across CPU state, guest instructions and native exits.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::MmioDevice;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use vm_memory::{Bytes, GuestAddress};
const CODE: u64 = 0x8000;
const TPR: u64 = LAPIC_BASE + 0x80;

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
fn long_state(vm: &mut Vmm, cpu: usize, value: u64) {
    let mut state = vm.vcpus[cpu].get_state().unwrap();
    let CpuState::X86_64(s) = &mut state else {
        panic!()
    };
    s.regs.rip = CODE;
    s.regs.rax = value;
    s.regs.rflags = 2;
    s.sregs.cr0 = 0x50033;
    s.sregs.cr3 = 0;
    s.sregs.cr4 = 1 << 5;
    s.sregs.efer = (1 << 8) | (1 << 10);
    s.sregs.cs.l = true;
    s.sregs.cs.db = false;
    s.sregs.cs.selector = 0;
    vm.vcpus[cpu].set_state(&state).unwrap();
}
fn tpr(vm: &Vmm, cpu: usize) -> u32 {
    let mut bytes = [0; 4];
    LapicDevice::new(vm.local_apics[cpu].clone()).read(TPR, &mut bytes);
    u32::from_le_bytes(bytes)
}

#[test]
fn guest_mov_to_cr8_updates_the_owning_ap_controller() {
    let mut vm = fixture();
    long_state(&mut vm, 1, 0xb);
    vm.guest_mem
        .memory()
        .write_slice(&[0x44, 0x0f, 0x22, 0xc0], GuestAddress(CODE))
        .unwrap();
    assert!(vm.vcpus[1].step_insn().unwrap().is_none());
    assert_eq!(tpr(&vm, 1), 0xb0);
    assert_eq!(tpr(&vm, 0), 0);
}

#[test]
fn guest_mov_from_cr8_and_public_state_follow_the_owning_tpr() {
    let mut vm = fixture();
    long_state(&mut vm, 1, 0);
    LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &0xa7u32.to_le_bytes());
    vm.guest_mem
        .memory()
        .write_slice(&[0x44, 0x0f, 0x20, 0xc0], GuestAddress(CODE))
        .unwrap();
    assert!(vm.vcpus[1].step_insn().unwrap().is_none());
    let CpuState::X86_64(s) = vm.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(s.regs.rax, 0xa);
    assert_eq!(s.sregs.cr8, 0xa);
    assert_eq!(tpr(&vm, 1), 0xa7);
}

#[test]
fn public_cr8_import_updates_the_shared_controller() {
    let mut vm = fixture();
    let mut s = vm.vcpus[1].get_state().unwrap();
    let CpuState::X86_64(state) = &mut s else {
        panic!()
    };
    state.sregs.cr8 = 9;
    vm.vcpus[1].set_state(&s).unwrap();
    assert_eq!(tpr(&vm, 1), 0x90);
    assert_eq!(tpr(&vm, 0), 0);
}

#[test]
fn unrelated_public_register_updates_keep_subclass_but_mov_cr8_clears_it() {
    let mut vm = fixture();
    long_state(&mut vm, 1, 0xa);
    LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &0xa7u32.to_le_bytes());
    let mut regs = vm.vcpus[1].get_regs().unwrap();
    regs.rip = CODE;
    regs.rax = 0xa;
    vm.vcpus[1].set_regs(&regs).unwrap();
    assert_eq!(tpr(&vm, 1), 0xa7);
    vm.guest_mem
        .memory()
        .write_slice(&[0x44, 0x0f, 0x22, 0xc0], GuestAddress(CODE))
        .unwrap();
    assert!(vm.vcpus[1].step_insn().unwrap().is_none());
    assert_eq!(tpr(&vm, 1), 0xa0);
}

struct NativeCpu {
    state: CpuState,
    exits: VecDeque<VcpuExit>,
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl VCpu for NativeCpu {
    fn id(&self) -> u32 {
        1
    }
    fn run(&mut self) -> Result<VcpuExit> {
        Ok(self.exits.pop_front().expect("complete native script"))
    }
    fn get_state(&self) -> Result<CpuState> {
        Ok(self.state.clone())
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.replies.lock().unwrap().push(data.to_vec());
    }
}

#[test]
fn native_ap_mmio_exits_use_its_controller_and_leave_the_bsp_unchanged() {
    let mut vm = fixture();
    let replies = Arc::new(Mutex::new(Vec::new()));
    vm.vcpus[1] = Box::new(NativeCpu {
        state: vm.vcpus[1].get_state().unwrap(),
        replies: replies.clone(),
        exits: [
            VcpuExit::MmioWrite {
                addr: TPR,
                data: 0xa7u32.to_le_bytes().to_vec(),
            },
            VcpuExit::MmioRead {
                addr: LAPIC_BASE + 0x20,
                size: 4,
            },
            VcpuExit::MmioRead { addr: TPR, size: 4 },
            VcpuExit::Shutdown,
        ]
        .into(),
    });
    vm.coordinator.online.fill(false);
    vm.coordinator.online[1] = true;
    vm.coordinator.cursor = 1;
    vm.run().unwrap();
    assert_eq!(
        *replies.lock().unwrap(),
        [
            0x0100_0000u32.to_le_bytes().to_vec(),
            0xa7u32.to_le_bytes().to_vec()
        ]
    );
    assert_eq!(tpr(&vm, 1), 0xa7);
    assert_eq!(tpr(&vm, 0), 0);
}

#[test]
fn every_tpr_byte_and_cr8_class_roundtrips_through_actual_guest_instructions() {
    let mut vm = fixture();
    vm.guest_mem
        .memory()
        .write_slice(&[0x44, 0x0f, 0x20, 0xc0], GuestAddress(CODE))
        .unwrap();
    for value in 0u32..=255 {
        long_state(&mut vm, 1, 0);
        LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &value.to_le_bytes());
        assert!(vm.vcpus[1].step_insn().unwrap().is_none());
        let CpuState::X86_64(state) = vm.vcpus[1].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.rax, u64::from(value >> 4));
        assert_eq!(state.sregs.cr8, state.regs.rax);
        assert_eq!(tpr(&vm, 1), value);
    }
    vm.guest_mem
        .memory()
        .write_slice(&[0x44, 0x0f, 0x22, 0xc0], GuestAddress(CODE))
        .unwrap();
    for value in 0..16 {
        long_state(&mut vm, 1, value);
        LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &0xa7u32.to_le_bytes());
        assert!(vm.vcpus[1].step_insn().unwrap().is_none());
        assert_eq!(tpr(&vm, 1), (value << 4) as u32);
    }
    assert_eq!(tpr(&vm, 0), 0);
}

#[test]
fn complete_checkpoint_freezes_priority_and_restore_keeps_the_live_cpu_binding() {
    let mut vm = fixture();
    long_state(&mut vm, 1, 0);
    LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &0xa7u32.to_le_bytes());
    let bundle = vm.take_snapshot_bundle(0).unwrap();
    let frozen = &bundle.execution().unwrap().local_apics[1].registers;
    assert_eq!(frozen.read_register(0x80), 0xa7);
    let mut state = vm.vcpus[1].get_state().unwrap();
    let CpuState::X86_64(s) = &mut state else {
        panic!()
    };
    s.sregs.cr8 = 3;
    vm.vcpus[1].set_state(&state).unwrap();
    assert_eq!(tpr(&vm, 1), 0x30);
    assert_eq!(frozen.read_register(0x80), 0xa7);
    vm.restore_snapshot_bundle(&bundle).unwrap();
    assert_eq!(tpr(&vm, 1), 0xa7);
    assert_eq!(vm.vcpus[1].get_sregs().unwrap().cr8, 0xa);
    LapicDevice::new(vm.local_apics[1].clone()).write(TPR, &0xb3u32.to_le_bytes());
    assert_eq!(
        vm.vcpus[1].get_sregs().unwrap().cr8,
        0xb,
        "restored CPU still shares the live owner"
    );
}

#[test]
fn mismatched_checkpoint_priority_rejects_before_cpu_ram_or_controller_publication() {
    let mut vm = fixture();
    let bundle = vm.take_snapshot_bundle(0).unwrap();
    let mut cpus = bundle.cpus().unwrap().entries().to_vec();
    let CpuState::X86_64(cpu) = &mut cpus[1].state else {
        panic!()
    };
    cpu.sregs.cr8 = 15;
    let malformed = bundle.with_cpus(cpus).unwrap();
    vm.guest_mem
        .memory()
        .write_slice(&[0x42], GuestAddress(128))
        .unwrap();
    let before = crate::codec::serialize(&vm.vcpus[1].get_state().unwrap()).unwrap();
    let error = vm
        .restore_snapshot_bundle(&malformed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("CR8") && error.contains("TPR"), "{error}");
    let mut byte = [0];
    vm.guest_mem
        .memory()
        .read_slice(&mut byte, GuestAddress(128))
        .unwrap();
    assert_eq!(byte, [0x42]);
    assert_eq!(
        crate::codec::serialize(&vm.vcpus[1].get_state().unwrap()).unwrap(),
        before
    );
    assert_eq!(tpr(&vm, 1), 0);
}
