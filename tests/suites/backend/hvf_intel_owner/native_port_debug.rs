//! Port-I/O debug frontiers through the production owner/completion paths.
//! The substituted SDK stores VMCS fields; no real guest #DB executes here.
use super::*;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};

type Owner = (Box<dyn rax::backend::Vm>, GuestMemoryWrapper, Box<dyn VCpu>);
const ORIGINAL_RAX: u64 = 0x1234_5678_9abc_def0;

fn seeded_port(read: bool, size: u8, tf: bool, immediate: bool) -> Owner {
    let code: &[u8] = match (read, size, immediate) {
        (true, 1, false) => &[0xec],
        (true, 2, false) => &[0x66, 0xed],
        (true, 4, false) => &[0xed],
        (false, 1, false) => &[0xee],
        (false, 2, false) => &[0x66, 0xef],
        (false, 4, false) => &[0xef],
        (true, 1, true) => &[0xe4, 0xf8],
        (true, 2, true) => &[0x66, 0xe5, 0xf8],
        (true, 4, true) => &[0xe5, 0xf8],
        (false, 1, true) => &[0xe6, 0xf8],
        (false, 2, true) => &[0x66, 0xe7, 0xf8],
        (false, 4, true) => &[0xe7, 0xf8],
        _ => panic!("invalid fixture width"),
    };
    let width = match size {
        1 => 0,
        2 => 1,
        4 => 3,
        _ => unreachable!(),
    };
    let port = if immediate { 0xf8 } else { 0x3f8 };
    let qualification =
        (port << 16) | width | if read { 8 } else { 0 } | if immediate { 0x40 } else { 0 };
    let owner = super::native_mmio_debug::seeded(code, qualification, false);
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native
            .registers
            .insert(1, 0x1_0202 | if tf { 0x100 } else { 0 });
        native.registers.insert(2, ORIGINAL_RAX);
        native.registers.insert(4, 0x3f8); // DX differs from the immediate-port operand.
        native.registers.insert(40, 0x28);
        native.vmcs.insert(0x6804, 0x28);
        native.registers.insert(47, 0xffff_0ff0);
        for (register, address) in [(41, port), (42, port + 1), (43, port + 3), (44, port + 4)] {
            native.registers.insert(register, address);
        }
        native.vmcs.insert(
            0x681a,
            0x479 | (2 << 16) | (2 << 20) | (2 << 24) | (2 << 28),
        );
        native.vmcs.insert(0x440c, code.len() as u64);
        native.exits.clear();
        native.exits.push_back(30);
    }
    owner
}

fn entries() -> usize {
    SDK.lock()
        .unwrap()
        .trace
        .iter()
        .filter(|call| call.starts_with("run:"))
        .count()
}

fn transfer(
    (vm, memory, cpu): Owner,
    read: bool,
    size: u8,
    tf: bool,
    step: bool,
    immediate: bool,
) -> Owner {
    transfer_image((vm, memory, cpu), read, size, tf, step, immediate, false)
}

fn transfer_image(
    (vm, memory, cpu): Owner,
    read: bool,
    size: u8,
    tf: bool,
    step: bool,
    immediate: bool,
    legacy: bool,
) -> Owner {
    let boundary = vm.checkpoint_boundary().unwrap();
    let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let mut private = private.unwrap();
    if legacy {
        super::native_mmio_legacy::old_tag(&mut private.data);
    }
    let bytes = rax::codec::serialize(&(public.state, public.emulator, private.kind, private.data))
        .unwrap();
    drop(boundary);
    drop(cpu);
    drop(vm);
    drop(memory);
    let (vm, memory, mut cpu) = seeded_port(read, size, tf, immediate);
    super::native_mmio_debug::host_step(cpu.as_mut(), step);
    let (state, emulator, kind, data): (CpuState, rax::vm::snapshot::EmulatorState, u32, Vec<u8>) =
        rax::codec::deserialize_strict(&bytes).unwrap();
    cpu.restore_checkpoint_context(
        &state,
        &emulator,
        Some(&rax::vm::snapshot::BackendContext { kind, data }),
    )
    .unwrap();
    (vm, memory, cpu)
}

fn complete(cpu: &mut dyn VCpu, read: bool, size: u8) {
    if read {
        cpu.complete_io_in(&[0x5a; 4][..usize::from(size)]);
    } else {
        cpu.complete_io_out().unwrap();
    }
    cpu.io_completion_result().unwrap();
}

fn breakpoint_after_completion(read: bool) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(1, 0x1_0202); // IF/RF, TF clear.
        native.registers.insert(40, 8); // CR4.DE enables I/O breakpoint conditions.
        native.registers.insert(41, 0x3f8); // DR0 matches the zero-extended port.
        native.vmcs.insert(0x6804, 8);
        native.vmcs.insert(0x681a, 0x2_0401); // L0, R/W0=10, LEN0=00.
        native
            .vmcs
            .insert(0x6400, (0x3f8 << 16) | if read { 8 } else { 0 });
        native.vmcs.insert(0x440c, 1);
        native.exits.push_back(30);
    }
    let exit = cpu.run().unwrap();
    assert!(if read {
        matches!(
            exit,
            VcpuExit::IoIn {
                port: 0x3f8,
                size: 1
            }
        )
    } else {
        matches!(exit, VcpuExit::IoOut { port: 0x3f8, .. })
    });
    assert!(cpu.get_state().is_err());
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    if read {
        cpu.complete_io_in(&[0x5a]);
    } else {
        cpu.complete_io_out().unwrap();
    }
    cpu.io_completion_result().unwrap();
    let pending = SDK
        .lock()
        .unwrap()
        .cpus
        .values()
        .next()
        .unwrap()
        .vmcs
        .get(&0x6822)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        pending, 0x1001,
        "successful port access lost its I/O breakpoint"
    );
    assert!(!cpu.can_inject_interrupt());
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    drop(cpu);
    drop(vm);
    drop(memory);
}

#[test]
fn input_breakpoint_is_pending_only_after_device_completion() {
    breakpoint_after_completion(true);
}

#[test]
fn output_breakpoint_is_pending_only_after_device_acknowledgment() {
    breakpoint_after_completion(false);
}

#[test]
fn port_causes_survive_both_directions_widths_and_source_owner_destruction() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        for (size, hits, input_rax) in [
            (1, 1, 0x1234_5678_9abc_de5a),
            (2, 3, 0x1234_5678_9abc_5a5a),
            (4, 7, 0x5a5a_5a5a),
        ] {
            for tf in [false, true] {
                for step in [false, true]
                    .into_iter()
                    .filter(|e| cfg!(feature = "debug") || !e)
                {
                    for immediate in [false, true] {
                        for phase in 0..3 {
                            let (mut vm, mut memory, mut cpu) =
                                seeded_port(read, size, tf, immediate);
                            super::native_mmio_debug::host_step(cpu.as_mut(), step);
                            let exit = cpu.run().unwrap();
                            assert!(cpu.get_state().is_err());
                            assert!(!cpu.inject_interrupt(0x51).unwrap());
                            assert!(!cpu.inject_nmi().unwrap());
                            for _ in 0..2 {
                                let before = entries();
                                assert_eq!(
                                    format!("{:?}", cpu.run().unwrap()),
                                    format!("{exit:?}")
                                );
                                assert_eq!(entries(), before);
                            }
                            if phase == 1 {
                                (vm, memory, cpu) =
                                    transfer((vm, memory, cpu), read, size, tf, step, immediate);
                                let before = entries();
                                assert_eq!(
                                    format!("{:?}", cpu.run().unwrap()),
                                    format!("{exit:?}")
                                );
                                assert_eq!(entries(), before);
                            }
                            complete(cpu.as_mut(), read, size);
                            if phase == 2 {
                                (vm, memory, cpu) =
                                    transfer((vm, memory, cpu), read, size, tf, step, immediate);
                            }
                            let expected = 0x1000 | hits | if tf { 0x4000 } else { 0 };
                            {
                                let sdk = SDK.lock().unwrap();
                                let native = sdk.cpus.values().next().unwrap();
                                assert_eq!(
                                    native.vmcs.get(&0x6822).copied().unwrap_or(0),
                                    expected
                                );
                                assert_eq!(native.registers[&47], 0xffff_0ff0);
                            }
                            let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                                unreachable!()
                            };
                            assert_eq!(state.regs.rax, if read { input_rax } else { ORIGINAL_RAX });
                            assert_eq!(
                                state.regs.rip,
                                0x100 + if size == 2 { 2 } else { 1 } + u64::from(immediate)
                            );
                            assert_eq!(
                                state.regs.rflags & 0x1_0300,
                                0x200 | if tf { 0x100 } else { 0 }
                            );
                            assert!(!cpu.can_inject_interrupt());
                            assert!(!cpu.inject_interrupt(0x51).unwrap());
                            assert!(!cpu.inject_nmi().unwrap());
                            #[cfg(feature = "debug")]
                            if step {
                                let before = entries();
                                assert!(matches!(cpu.run().unwrap(), VcpuExit::GdbStep));
                                assert_eq!(entries(), before);
                            }
                            drop(cpu);
                            drop(vm);
                            drop(memory);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn inactive_io_conditions_do_not_read_unneeded_address_registers() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        for (condition, de, enable) in [
            (0, true, 1),
            (1, true, 1),
            (3, true, 1),
            (2, false, 1),
            (2, true, 0),
        ] {
            let (vm, memory, mut cpu) = seeded_port(read, 1, false, false);
            {
                let mut sdk = SDK.lock().unwrap();
                let native = sdk.cpus.values_mut().next().unwrap();
                native
                    .vmcs
                    .insert(0x681a, 0x400 | enable | (condition << 16));
                native.vmcs.insert(0x6804, if de { 0x28 } else { 0x20 });
                native.data_debug_fault = Some(DataDebugFault::AddressRead(41));
            }
            cpu.run().unwrap();
            complete(cpu.as_mut(), read, 1);
            assert_eq!(
                SDK.lock()
                    .unwrap()
                    .cpus
                    .values()
                    .next()
                    .unwrap()
                    .vmcs
                    .get(&0x6822)
                    .copied()
                    .unwrap_or(0),
                0
            );
            assert!(cpu.can_inject_interrupt());
            drop(cpu);
            drop(vm);
            drop(memory);
        }
    }
}

#[test]
fn short_watched_input_replies_keep_the_fault_frontier_across_owner_replacement() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for immediate in [false, true] {
        for size in [1u8, 2, 4] {
            for received in 0..usize::from(size) {
                let (vm, memory, mut cpu) = seeded_port(true, size, false, immediate);
                assert!(matches!(cpu.run().unwrap(), VcpuExit::IoIn { .. }));
                cpu.complete_io_in(&vec![5; received]);
                assert!(cpu.io_completion_result().is_err());
                let before = entries();
                let error = cpu.run().unwrap_err().to_string();
                assert!(error.contains("expected") && error.contains("received"));
                assert_eq!(entries(), before);
                let (vm, memory, mut cpu) =
                    transfer((vm, memory, cpu), true, size, false, false, immediate);
                cpu.complete_io_in(&vec![5; usize::from(size)]);
                let before = entries();
                assert!(cpu.run().is_err());
                assert_eq!(entries(), before);
                assert!(!cpu.can_inject_interrupt());
                assert!(!cpu.inject_interrupt(0x51).unwrap());
                assert!(!cpu.inject_nmi().unwrap());
                let boundary = vm.checkpoint_boundary().unwrap();
                let (saved, _) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                let CpuState::X86_64(guest) = saved.state else {
                    unreachable!()
                };
                assert_eq!(guest.regs.rip, 0x100);
                assert_eq!(guest.regs.rax, ORIGINAL_RAX);
                assert_eq!(guest.sregs.dr6, 0xffff_0ff0);
                drop(boundary);
                drop(cpu);
                drop(vm);
                drop(memory);
            }
        }
    }
}

#[test]
fn io_debug_sdk_failures_keep_execution_fenced_after_late_replies_and_restore() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        for fault in [
            DataDebugFault::ControlRead,
            DataDebugFault::ExtensionRead,
            DataDebugFault::AddressRead(41),
            DataDebugFault::PendingRead,
            DataDebugFault::PendingWriteBefore,
            DataDebugFault::PendingWriteAfter,
        ] {
            let (vm, memory, mut cpu) = seeded_port(read, 1, false, false);
            SDK.lock()
                .unwrap()
                .cpus
                .values_mut()
                .next()
                .unwrap()
                .data_debug_fault = Some(fault);
            assert!(cpu.run().is_err(), "{fault:?}");
            let before = entries();
            if read {
                cpu.complete_io_in(&[0x5a]);
            } else {
                assert!(cpu.complete_io_out().is_err());
            }
            assert!(cpu.io_completion_result().is_err());
            for _ in 0..3 {
                assert!(cpu.run().is_err());
                assert!(cpu.get_state().is_err());
                assert!(!cpu.can_inject_interrupt());
                assert!(!cpu.inject_nmi().unwrap());
                assert_eq!(entries(), before);
            }
            let boundary = vm.checkpoint_boundary().unwrap();
            let captured = cpu.capture_checkpoint_record(&boundary, None);
            drop(boundary);
            let bytes = if matches!(
                fault,
                DataDebugFault::PendingWriteBefore | DataDebugFault::PendingWriteAfter
            ) {
                let (public, private) = captured.unwrap();
                let private = private.unwrap();
                Some(
                    rax::codec::serialize(&(
                        public.state,
                        public.emulator,
                        private.kind,
                        private.data,
                    ))
                    .unwrap(),
                )
            } else {
                assert!(captured.is_err());
                None
            };
            drop(cpu);
            drop(vm);
            drop(memory);
            if let Some(bytes) = bytes {
                let (vm, memory, mut cpu) = seeded_port(read, 1, false, false);
                let (state, emulator, kind, data): (
                    CpuState,
                    rax::vm::snapshot::EmulatorState,
                    u32,
                    Vec<u8>,
                ) = rax::codec::deserialize_strict(&bytes).unwrap();
                cpu.restore_checkpoint_context(
                    &state,
                    &emulator,
                    Some(&rax::vm::snapshot::BackendContext { kind, data }),
                )
                .unwrap();
                let before = entries();
                assert!(cpu.run().is_err());
                assert!(cpu.get_state().is_err());
                assert!(!cpu.can_inject_interrupt());
                assert!(!cpu.inject_nmi().unwrap());
                assert_eq!(entries(), before);
                drop(cpu);
                drop(vm);
                drop(memory);
            }
        }
    }
}

fn simulated_legacy_pending_debug(read: bool) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for size in [1, 2, 4] {
        for immediate in [false, true] {
            for tf in [false, true] {
                let (vm, memory, mut cpu) = seeded_port(read, size, tf, immediate);
                cpu.run().unwrap();
                // Simulate the old producer: all state is retained except the
                // omitted port cause. Preserve an independent pending BS bit.
                SDK.lock()
                    .unwrap()
                    .cpus
                    .values_mut()
                    .next()
                    .unwrap()
                    .vmcs
                    .insert(0x6822, if tf { 1 << 14 } else { 0 });
                let (vm, memory, mut cpu) =
                    transfer_image((vm, memory, cpu), read, size, tf, false, immediate, true);
                complete(cpu.as_mut(), read, size);
                let pending = SDK
                    .lock()
                    .unwrap()
                    .cpus
                    .values()
                    .next()
                    .unwrap()
                    .vmcs
                    .get(&0x6822)
                    .copied()
                    .unwrap_or(0);
                let expected = 0x1000
                    | match size {
                        1 => 1,
                        2 => 3,
                        4 => 7,
                        _ => unreachable!(),
                    }
                    | if tf { 1 << 14 } else { 0 };
                assert_eq!(
                    pending, expected,
                    "legacy pending port={read}/{size}/{immediate}/{tf}"
                );
                assert!(!cpu.inject_interrupt(0x51).unwrap());
                assert!(!cpu.inject_nmi().unwrap());
                drop(cpu);
                drop(vm);
                drop(memory);
            }
        }
    }
}

#[test]
fn simulated_legacy_input_debug_record() {
    simulated_legacy_pending_debug(true);
}

#[test]
fn simulated_legacy_output_debug_record() {
    simulated_legacy_pending_debug(false);
}

#[test]
fn rollback_pending_port_images_are_exact() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        for size in [1, 2, 4] {
            for pending in [0, 0x4000] {
                let (vm, memory, mut cpu) = seeded_port(read, size, false, false);
                cpu.run().unwrap();
                SDK.lock()
                    .unwrap()
                    .cpus
                    .values_mut()
                    .next()
                    .unwrap()
                    .vmcs
                    .insert(0x6822, pending);
                let boundary = vm.checkpoint_boundary().unwrap();
                let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                cpu.restore_checkpoint_record(
                    &boundary,
                    &saved.state,
                    &saved.emulator,
                    private.as_ref(),
                )
                .unwrap();
                let forward = SDK.lock().unwrap().cpus.values().next().unwrap().vmcs[&0x6822];
                let causes = 0x1000
                    | match size {
                        1 => 1,
                        2 => 3,
                        4 => 7,
                        _ => unreachable!(),
                    };
                assert_eq!(
                    forward,
                    pending | causes,
                    "forward import reconstructs the omitted cause"
                );
                cpu.rollback_checkpoint_record(
                    &boundary,
                    &saved.state,
                    &saved.emulator,
                    private.as_ref(),
                )
                .unwrap();
                let observed = SDK.lock().unwrap().cpus.values().next().unwrap().vmcs[&0x6822];
                assert_eq!(
                    observed, pending,
                    "rollback must preserve its exact destination image"
                );
                drop(boundary);
                drop(cpu);
                drop(vm);
                drop(memory);
            }
        }
    }
}

#[cfg(feature = "debug")]
fn fail_debug_control(cpu: &mut dyn VCpu, requested_step: bool) {
    SDK.lock().unwrap().fault = Some(Fault {
        operation: "read-vmcs",
        remaining: 1,
        persistent: false,
    });
    cpu.set_single_step(requested_step);
    assert!(cpu.run().is_err());
}

#[cfg(feature = "debug")]
#[test]
fn pending_legacy_port_causes_follow_the_current_debugger_failure_state() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        for source_failed in [false, true] {
            for destination_failed in [false, true] {
                for step in [false, true] {
                    let (vm, memory, mut cpu) = seeded_port(read, 4, false, false);
                    cpu.run().unwrap();
                    SDK.lock()
                        .unwrap()
                        .cpus
                        .values_mut()
                        .next()
                        .unwrap()
                        .vmcs
                        .insert(0x6822, 0);
                    if source_failed {
                        fail_debug_control(cpu.as_mut(), true);
                    }
                    let boundary = vm.checkpoint_boundary().unwrap();
                    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                    let mut private = private.unwrap();
                    super::native_mmio_legacy::old_tag(&mut private.data);
                    drop(boundary);
                    drop(cpu);
                    drop(vm);
                    drop(memory);

                    let (vm, memory, mut cpu) = seeded_port(read, 4, false, false);
                    cpu.set_single_step(step);
                    if destination_failed {
                        fail_debug_control(cpu.as_mut(), !step);
                    }
                    let boundary = vm.checkpoint_boundary().unwrap();
                    cpu.restore_checkpoint_record(
                        &boundary,
                        &saved.state,
                        &saved.emulator,
                        Some(&private),
                    )
                    .unwrap();
                    let observed = SDK.lock().unwrap().cpus.values().next().unwrap().vmcs[&0x6822];
                    assert_eq!(
                        observed,
                        if destination_failed { 0 } else { 0x1007 },
                        "read={read}, source_failed={source_failed}, destination_failed={destination_failed}, step={step}"
                    );
                    drop(boundary);
                    assert_eq!(cpu.is_single_step(), step);
                    if destination_failed {
                        assert!(cpu.run().is_err());
                    } else {
                        complete(cpu.as_mut(), read, 4);
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
