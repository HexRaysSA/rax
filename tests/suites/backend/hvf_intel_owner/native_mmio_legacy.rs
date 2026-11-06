//! Older deferred-debug records after code replacement and linear aliasing.
use super::*;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use vm_memory::{Bytes, GuestAddress};

type Owner = (Box<dyn rax::backend::Vm>, GuestMemoryWrapper, Box<dyn VCpu>);

pub(super) fn old_tag(data: &mut [u8]) {
    let tag = match &data[..8] {
        b"RAXHVI04" => *b"RAXHVI02",
        b"RAXHVI05" => *b"RAXHVI03",
        b"RAXHVI02" | b"RAXHVI03" => return,
        tag => panic!("unexpected simulated producer: {tag:?}"),
    };
    data[..8].copy_from_slice(&tag);
}

fn pending_alias(linear: u64) -> Owner {
    let mut code = vec![0x48, 0xa1]; // MOV RAX,moffs64, with a ten-byte encoding.
    code.extend(linear.to_le_bytes());
    let owner = super::native_mmio_debug::seeded(&code, 0x181, false);
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(1, 0x1_0202);
        native.registers.insert(41, 0x3ee0_0000);
        native.vmcs.insert(0x681a, 0x3_0401);
        native.vmcs.insert(0x640a, linear);
        native.vmcs.insert(0x440c, 10);
    }
    owner
}

fn legacy_alias_record(linear: u64) -> (Vec<u8>, Vec<u8>, u64) {
    let (vm, memory, mut cpu) = pending_alias(linear);
    assert!(matches!(
        cpu.run().unwrap(),
        VcpuExit::MmioRead {
            addr: 0xfee0_0000,
            size: 8
        }
    ));
    let causes = {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        let causes = native.vmcs.get(&0x6822).copied().unwrap_or(0);
        // Simulate the pre-fix producer's omitted synthesis, preserving the
        // actual pending descriptor and every other native field.
        native.vmcs.insert(0x6822, 0);
        causes
    };
    // A different guest CPU or DMA writer may replace already-fetched code
    // before the VM reaches its checkpoint boundary. The new RAM image cannot
    // recover the original moffs address from the saved RIP.
    memory
        .memory()
        .write_slice(&[0x90; 10], GuestAddress(0x100))
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let mut private = private.unwrap();
    old_tag(&mut private.data);
    let record =
        rax::codec::serialize(&(saved.state, saved.emulator, private.kind, private.data)).unwrap();
    let mut ram = vec![0; 0x4000];
    memory
        .memory()
        .read_slice(&mut ram, GuestAddress(0))
        .unwrap();
    drop(boundary);
    drop(cpu);
    drop(vm);
    drop(memory);
    (record, ram, causes)
}

#[test]
fn old_pending_mmio_aliases_cannot_recover_omitted_debug_causes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (watched, watched_ram, hit) = legacy_alias_record(0x3ee0_0000);
    let (missed, missed_ram, miss) = legacy_alias_record(0xfee0_0000);
    assert_eq!(hit, 0x1001);
    assert_eq!(miss, 0);
    assert_eq!(watched_ram, missed_ram);
    assert_eq!(
        watched, missed,
        "distinct original debug histories collapse to the same old record"
    );

    let (state, emulator, kind, data): (CpuState, rax::vm::snapshot::EmulatorState, u32, Vec<u8>) =
        rax::codec::deserialize_strict(&watched).unwrap();
    let (vm, memory, mut cpu) = pending_alias(0x3ee0_0000);
    let before = SDK.lock().unwrap().trace.len();
    let result = cpu.restore_checkpoint_context(
        &state,
        &emulator,
        Some(&rax::vm::snapshot::BackendContext { kind, data }),
    );
    assert!(
        result.is_err(),
        "ambiguous older pending MMIO record was admitted without its original data-debug cause"
    );
    let sdk = SDK.lock().unwrap();
    assert!(!sdk.trace[before..].iter().any(|call| {
        call.starts_with("write-") || call.starts_with("set-") || call.starts_with("run:")
    }));
    drop(sdk);
    assert!(cpu.get_state().is_ok());
    drop(cpu);
    drop(vm);
    drop(memory);
}

fn capture_record(
    owner: Owner,
    legacy: bool,
) -> (
    rax::vm::snapshot::CpuSnapshot,
    rax::vm::snapshot::BackendContext,
) {
    let (vm, memory, cpu) = owner;
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let mut private = private.unwrap();
    if legacy {
        old_tag(&mut private.data);
    }
    drop(boundary);
    drop(cpu);
    drop(vm);
    drop(memory);
    (saved, private)
}

fn finish(cpu: &mut dyn VCpu, exit: &VcpuExit) {
    if matches!(exit, VcpuExit::MmioWrite { .. }) {
        cpu.complete_io_out().unwrap();
    } else {
        cpu.complete_io_in(&5u64.to_le_bytes());
    }
    cpu.io_completion_result().unwrap();
}

#[test]
fn legacy_mmio_admission_covers_slots_enables_conditions_and_access_kinds() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (code, qualification, writing) in [
        (&[0x48, 0x8b, 0x03][..], 0x181, false),
        (&[0x48, 0x89, 0x03][..], 0x182, true),
        (&[0x48, 0x03, 0x03][..], 0x181, false),
        (&[0x48, 0x01, 0x03][..], 0x183, true),
        (&[0x48, 0xc1, 0x23, 0][..], 0x182, true),
    ] {
        for slot in 0..4 {
            for enable in 0..4u64 {
                for condition in 0..4u64 {
                    let (vm, memory, mut cpu) =
                        super::native_mmio_debug::seeded(code, qualification, false);
                    {
                        let mut sdk = SDK.lock().unwrap();
                        let native = sdk.cpus.values_mut().next().unwrap();
                        native.registers.insert(41 + slot, 0xfee0_0000);
                        native.vmcs.insert(
                            0x681a,
                            0x400 | (enable << (slot * 2)) | (condition << (16 + slot * 4)),
                        );
                    }
                    let exit = cpu.run().unwrap();
                    let (saved, private) = capture_record((vm, memory, cpu), true);
                    let (vm, memory, mut cpu) =
                        super::native_mmio_debug::seeded(code, qualification, false);
                    let calls = SDK.lock().unwrap().trace.len();
                    let result = cpu.restore_checkpoint_context(
                        &saved.state,
                        &saved.emulator,
                        Some(&private),
                    );
                    let ambiguous = enable != 0 && (condition == 3 || writing && condition == 1);
                    assert_eq!(
                        result.is_err(),
                        ambiguous,
                        "slot={slot}, enable={enable}, condition={condition}, writing={writing}"
                    );
                    if ambiguous {
                        let sdk = SDK.lock().unwrap();
                        assert!(
                            !sdk.trace[calls..]
                                .iter()
                                .any(|call| call.starts_with("write-")
                                    || call.starts_with("set-")
                                    || call.starts_with("run:"))
                        );
                        drop(sdk);
                        assert!(cpu.get_state().is_ok());
                    } else {
                        assert_eq!(format!("{:?}", cpu.run().unwrap()), format!("{exit:?}"));
                        finish(cpu.as_mut(), &exit);
                        assert!(cpu.get_state().is_ok());
                    }
                    drop(cpu);
                    drop(vm);
                    drop(memory);
                }
            }
        }
    }
}

#[test]
fn current_pending_mmio_records_and_readable_terminal_records_keep_their_carrier() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for fault in [
        None,
        Some(DataDebugFault::PendingWriteBefore),
        Some(DataDebugFault::PendingWriteAfter),
    ] {
        for legacy in [false, true] {
            let code = [0x48, 0x8b, 0x03];
            let (vm, memory, mut cpu) = super::native_mmio_debug::seeded(&code, 0x181, false);
            {
                let mut sdk = SDK.lock().unwrap();
                let native = sdk.cpus.values_mut().next().unwrap();
                native.registers.insert(41, 0xfee0_0000);
                native.vmcs.insert(0x681a, 0x3_0401);
                native.data_debug_fault = fault;
            }
            let result = cpu.run();
            assert_eq!(result.is_err(), fault.is_some());
            let (saved, private) = capture_record((vm, memory, cpu), legacy);
            let (vm, memory, mut cpu) = super::native_mmio_debug::seeded(&code, 0x181, false);
            let result =
                cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private));
            if legacy {
                assert!(result.is_err());
                assert!(cpu.get_state().is_ok());
            } else {
                result.unwrap();
                assert_eq!(&private.data[..8], b"RAXHVI05");
                if fault.is_some() {
                    assert!(cpu.run().is_err());
                } else {
                    finish(
                        cpu.as_mut(),
                        &VcpuExit::MmioRead {
                            addr: 0xfee0_0000,
                            size: 8,
                        },
                    );
                }
            }
            drop(cpu);
            drop(vm);
            drop(memory);
        }
    }
}
