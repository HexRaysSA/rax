//! Production owner completion after a changed data walk; no native guest.
use super::*;
use rax::vm::vcpu::{CpuState, VcpuExit};
use vm_memory::{Bytes, GuestAddress};

#[test]
fn recorded_physical_page_survives_changed_absent_and_reserved_current_pdes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for physical in [0xfee0_0000, 0xfec0_0000] {
        for entry in [0xfee0_0083u64, 0xfec0_0083, 0, 0x8000_0000_fee0_0083] {
            let (vm, memory, mut cpu) =
                super::native_mmio_debug::seeded(&[0x48, 0x8b, 0x03], 0x181, false);
            memory
                .memory()
                .write_slice(&entry.to_le_bytes(), GuestAddress(0x3fb8))
                .unwrap();
            {
                let mut sdk = SDK.lock().unwrap();
                let native = sdk.cpus.values_mut().next().unwrap();
                native.registers.insert(1, 0x1_0202);
                native.vmcs.insert(0x2400, physical);
            }
            assert!(
                matches!(cpu.run().unwrap(), VcpuExit::MmioRead {addr,size:8} if addr==physical)
            );
            cpu.complete_io_in(&5u64.to_le_bytes());
            cpu.io_completion_result().unwrap();
            let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                unreachable!()
            };
            assert_eq!(state.regs.rip, 0x103);
            assert_eq!(state.regs.rax, 5);
            assert_eq!(state.regs.rflags & 0x1_0100, 0);
            drop(cpu);
            drop(vm);
            drop(memory);
        }
    }
}

#[test]
fn pending_record_keeps_the_original_request_across_new_owner_and_ram() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory, mut cpu) = super::native_mmio_debug::seeded(&[0x48, 0x8b, 0x03], 0x181, false);
    memory
        .memory()
        .write_slice(&0xfec0_0083u64.to_le_bytes(), GuestAddress(0x3fb8))
        .unwrap();
    assert!(matches!(
        cpu.run().unwrap(),
        VcpuExit::MmioRead {
            addr: 0xfee0_0000,
            size: 8
        }
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    drop(boundary);
    drop(cpu);
    drop(vm);
    drop(memory);

    let (vm, memory, mut cpu) = super::native_mmio_debug::seeded(&[0x48, 0x8b, 0x03], 0x181, false);
    memory
        .memory()
        .write_slice(&0u64.to_le_bytes(), GuestAddress(0x3fb8))
        .unwrap();
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, private.as_ref())
        .unwrap();
    // Re-observing a held request must neither enter the SDK nor walk new RAM.
    let entries = SDK
        .lock()
        .unwrap()
        .trace
        .iter()
        .filter(|call| call.starts_with("run:"))
        .count();
    assert!(matches!(
        cpu.run().unwrap(),
        VcpuExit::MmioRead {
            addr: 0xfee0_0000,
            size: 8
        }
    ));
    assert_eq!(
        SDK.lock()
            .unwrap()
            .trace
            .iter()
            .filter(|call| call.starts_with("run:"))
            .count(),
        entries
    );
    cpu.complete_io_in(&5u64.to_le_bytes());
    cpu.io_completion_result().unwrap();
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.regs.rip, 0x103);
    assert_eq!(state.regs.rax, 5);
    drop(cpu);
    drop(vm);
    drop(memory);
}
