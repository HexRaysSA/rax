//! Real RAX completion/checkpoint paths backed by deterministic SDK storage.
//! These tests do not execute native guest instructions or deliver a real #DB.
use super::*;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use vm_memory::{Bytes, GuestAddress};

fn seeded(
    code: &[u8],
    qualification: u64,
    btf: bool,
) -> (Box<dyn rax::backend::Vm>, GuestMemoryWrapper, Box<dyn VCpu>) {
    let (vm, memory) = fixture();
    memory
        .memory()
        .write_slice(code, GuestAddress(0x100))
        .unwrap();
    for (address, entry) in [
        (0x1000, 0x2003u64),
        (0x2000, 0x3003),
        (0x2018, 0x3003),
        (0x3000, 0x83),
        (0x3fb8, 0xfee0_0083),
    ] {
        memory
            .memory()
            .write_slice(&entry.to_le_bytes(), GuestAddress(address))
            .unwrap();
    }
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(0, 0x100);
        native.registers.insert(1, 0x1_0302); // EPT-saved RF, guest TF and IF.
        native.registers.insert(2, 2); // RAX.
        native.registers.insert(5, 0xfee0_0000); // RBX.
        for (register, field, value) in [
            (36, 0x6800, 0x8000_0021),
            (39, 0x6802, 0x1000),
            (40, 0x6804, 0x20),
        ] {
            native.registers.insert(register, value);
            native.vmcs.insert(field, value);
        }
        native.vmcs.insert(0x2806, 0x500);
        native.vmcs.insert(0x2802, if btf { 2 } else { 0 });
        *native.vmcs.entry(0x4012).or_default() |= 1 << 9;
        native.vmcs.insert(0x6400, qualification);
        native.vmcs.insert(0x640a, 0xfee0_0000);
        native.vmcs.insert(0x2400, 0xfee0_0000);
        native.exits.push_back(48);
    }
    (vm, memory, cpu)
}

fn entries() -> usize {
    SDK.lock()
        .unwrap()
        .trace
        .iter()
        .filter(|call| call.starts_with("run:"))
        .count()
}

fn complete(cpu: &mut dyn VCpu, exit: &VcpuExit) {
    if matches!(exit, VcpuExit::MmioWrite { .. }) {
        cpu.complete_io_out().unwrap();
    } else {
        cpu.complete_io_in(&5u64.to_le_bytes());
    }
    cpu.io_completion_result().unwrap();
}

fn host_step(cpu: &mut dyn VCpu, enabled: bool) {
    #[cfg(feature = "debug")]
    cpu.set_single_step(enabled);
    #[cfg(not(feature = "debug"))]
    {
        let _ = cpu;
        assert!(!enabled);
    }
}

#[test]
fn scalar_mmio_data_breakpoint_is_pending_after_device_completion() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(1, 0x1_0202); // RF/IF set, TF clear.
        native.registers.insert(41, 0xfee0_0000); // DR0: exact linear byte.
        native.vmcs.insert(0x681a, 0x3_0401); // L0, read/write, one-byte length.
    }
    let exit = cpu.run().unwrap();
    assert!(matches!(exit, VcpuExit::MmioRead { size: 8, .. }));
    assert!(cpu.get_state().is_err());
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    complete(cpu.as_mut(), &exit);
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
    // SDM 19.3.1.2: a successful data access traps even with RF=1 and TF=0.
    // VM entry uses B0 plus enabled-breakpoint bit12 to deliver that trap.
    assert_eq!(
        pending, 0x1001,
        "data match was lost at emulated retirement"
    );
    assert!(!cpu.can_inject_interrupt());
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    drop(cpu);
    drop(vm);
    drop(memory);
}

#[test]
fn guest_tf_mmio_continues_after_source_owner_destruction_and_preserves_host_step() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (code, qualification, expected_rax) in [
        (&[0x48, 0x8b, 0x03][..], 0x181, 5),
        (&[0x48, 0x89, 0x03][..], 0x182, 2),
        (&[0x48, 0x03, 0x03][..], 0x181, 7),
        (&[0x48, 0x01, 0x03][..], 0x183, 2),
        (&[0x48, 0xc1, 0x23, 1][..], 0x182, 2),
        (&[0x48, 0x0f, 0xa4, 0x03, 1][..], 0x183, 2),
    ] {
        for btf in [false, true] {
            for enabled in [false, true]
                .into_iter()
                .filter(|e| cfg!(feature = "debug") || !e)
            {
                let (vm, memory, mut source) = seeded(code, qualification, btf);
                host_step(source.as_mut(), enabled);
                let exit = source.run().unwrap();
                assert!(matches!(
                    exit,
                    VcpuExit::MmioRead { .. }
                        | VcpuExit::MmioWrite { .. }
                        | VcpuExit::MmioRmw { .. }
                ));
                let boundary = vm.checkpoint_boundary().unwrap();
                let (public, private) = source.capture_checkpoint_record(&boundary, None).unwrap();
                let private = private.expect("native private record");
                let bytes = rax::codec::serialize(&(
                    public.state,
                    public.emulator,
                    private.kind,
                    private.data,
                ))
                .unwrap();
                drop(boundary);
                drop(source);
                drop(vm);
                drop(memory);
                let (vm, memory, mut destination) = seeded(code, qualification, btf);
                // This destination retains its current debugger configuration.
                host_step(destination.as_mut(), enabled);
                let (state, emulator, kind, data): (
                    CpuState,
                    rax::vm::snapshot::EmulatorState,
                    u32,
                    Vec<u8>,
                ) = rax::codec::deserialize_strict(&bytes).unwrap();
                let private = rax::vm::snapshot::BackendContext { kind, data };
                destination
                    .restore_checkpoint_context(&state, &emulator, Some(&private))
                    .unwrap();
                let before = entries();
                assert_eq!(
                    format!("{:?}", destination.run().unwrap()),
                    format!("{exit:?}")
                );
                assert_eq!(entries(), before, "restored input must not enter the SDK");
                complete(destination.as_mut(), &exit);
                let CpuState::X86_64(state) = destination.get_state().unwrap() else {
                    panic!("wrong architecture")
                };
                assert_eq!(state.regs.rax, expected_rax);
                assert_eq!(state.regs.rip, 0x100 + code.len() as u64);
                assert_eq!(state.regs.rflags & 0x1_0300, 0x300);
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
                assert_eq!(pending, if btf { 0 } else { 1 << 14 });
                if !btf {
                    assert!(!destination.can_inject_interrupt());
                    assert!(!destination.inject_interrupt(0x51).unwrap());
                    assert!(!destination.inject_nmi().unwrap());
                }
                #[cfg(feature = "debug")]
                if enabled {
                    assert!(matches!(destination.run().unwrap(), VcpuExit::GdbStep));
                    assert_eq!(
                        entries(),
                        before,
                        "MTF completion must precede another entry"
                    );
                }
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
                    pending
                );
                drop(destination);
                drop(vm);
                drop(memory);
            }
        }
    }
}

#[test]
fn saved_pending_debug_traps_defer_irq_and_nmi_until_guest_delivery() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for pending in [1 << 12, 1 << 14, 0x500f] {
        let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            native.exits.clear();
            native.vmcs.insert(0x6822, pending);
        }
        let boundary = vm.checkpoint_boundary().unwrap();
        let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        drop(boundary);
        cpu.restore_checkpoint_context(&public.state, &public.emulator, private.as_ref())
            .unwrap();
        for _ in 0..3 {
            assert!(!cpu.can_inject_interrupt());
            assert!(!cpu.inject_interrupt(0x51).unwrap());
            assert!(!cpu.inject_nmi().unwrap());
        }
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            assert_eq!(native.vmcs.get(&0x6822).copied().unwrap_or(0), pending);
            assert_eq!(
                native.vmcs.get(&0x4016).copied().unwrap_or(0) & (1 << 31),
                0
            );
            // The SDK fixture has no guest. Model completed guest #DB delivery.
            native.vmcs.insert(0x6822, 0);
        }
        assert!(cpu.can_inject_interrupt());
        assert!(cpu.inject_interrupt(0x51).unwrap());
        assert!(!cpu.inject_nmi().unwrap());
        drop(cpu);
        drop(vm);
        drop(memory);
    }
}

#[test]
fn scalar_data_causes_survive_fresh_pending_and_retired_owner_replacement() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    type Owner = (Box<dyn rax::backend::Vm>, GuestMemoryWrapper, Box<dyn VCpu>);
    for (code, qualification, writing) in [
        (&[0x48, 0x8b, 0x03][..], 0x181, false),
        (&[0x48, 0x89, 0x03][..], 0x182, true),
        (&[0x48, 0x03, 0x03][..], 0x181, false),
        (&[0x48, 0x3b, 0x03][..], 0x181, false),
        (&[0x48, 0x01, 0x03][..], 0x183, true),
        (&[0x48, 0xc1, 0x23, 0][..], 0x182, true),
        (&[0x48, 0xc1, 0x23, 1][..], 0x182, true),
        (&[0x48, 0x0f, 0xa4, 0x03, 1][..], 0x183, true),
    ] {
        for tf in [false, true] {
            for enabled in [false, true]
                .into_iter()
                .filter(|e| cfg!(feature = "debug") || !e)
            {
                for phase in 0..3 {
                    let (mut vm, mut memory, mut cpu) = seeded(code, qualification, false);
                    host_step(cpu.as_mut(), enabled);
                    {
                        let mut sdk = SDK.lock().unwrap();
                        let native = sdk.cpus.values_mut().next().unwrap();
                        native
                            .registers
                            .insert(1, 0x1_0202 | if tf { 0x100 } else { 0 });
                        native.registers.insert(47, 0xffff_0ff0);
                        for (register, address) in [
                            (41, 0xfee0_0000),
                            (42, 0xfee0_0001),
                            (43, 0xfee0_0007),
                            (44, 0xfee0_0008),
                        ] {
                            native.registers.insert(register, address);
                        }
                        native.vmcs.insert(
                            0x681a,
                            0x479 | (3 << 16) | (1 << 20) | (3 << 24) | (3 << 28),
                        );
                    }
                    let transfer = |(vm, memory, cpu): Owner| -> Owner {
                        let boundary = vm.checkpoint_boundary().unwrap();
                        let (public, private) =
                            cpu.capture_checkpoint_record(&boundary, None).unwrap();
                        let private = private.unwrap();
                        let bytes = rax::codec::serialize(&(
                            public.state,
                            public.emulator,
                            private.kind,
                            private.data,
                        ))
                        .unwrap();
                        drop(boundary);
                        drop(cpu);
                        drop(vm);
                        drop(memory);
                        let (vm, memory, mut cpu) = seeded(code, qualification, false);
                        host_step(cpu.as_mut(), enabled);
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
                        (vm, memory, cpu)
                    };
                    let exit = cpu.run().unwrap();
                    assert!(cpu.get_state().is_err());
                    assert!(!cpu.inject_nmi().unwrap());
                    let entry_count = entries();
                    assert_eq!(format!("{:?}", cpu.run().unwrap()), format!("{exit:?}"));
                    assert_eq!(entries(), entry_count);
                    if phase == 1 {
                        (vm, memory, cpu) = transfer((vm, memory, cpu));
                        assert_eq!(format!("{:?}", cpu.run().unwrap()), format!("{exit:?}"));
                    }
                    complete(cpu.as_mut(), &exit);
                    if phase == 2 {
                        (vm, memory, cpu) = transfer((vm, memory, cpu));
                    }
                    let expected =
                        0x1000 | if writing { 7 } else { 5 } | if tf { 0x4000 } else { 0 };
                    {
                        let sdk = SDK.lock().unwrap();
                        let native = sdk.cpus.values().next().unwrap();
                        assert_eq!(native.vmcs.get(&0x6822).copied().unwrap_or(0), expected);
                        assert_eq!(
                            native.registers[&47], 0xffff_0ff0,
                            "emulation must not publish DR6 before actual #DB delivery"
                        );
                    }
                    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                        unreachable!()
                    };
                    assert_eq!(state.regs.rip, 0x100 + code.len() as u64);
                    assert_eq!(
                        state.regs.rflags & 0x1_0300,
                        0x200 | if tf { 0x100 } else { 0 }
                    );
                    assert!(!cpu.can_inject_interrupt());
                    assert!(!cpu.inject_interrupt(0x51).unwrap());
                    assert!(!cpu.inject_nmi().unwrap());
                    #[cfg(feature = "debug")]
                    if enabled {
                        let entry_count = entries();
                        assert!(matches!(cpu.run().unwrap(), VcpuExit::GdbStep));
                        assert_eq!(entries(), entry_count);
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
fn data_breakpoints_compare_linear_aliases_and_ignore_unwatched_address_reads() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for watched_alias in [false, true] {
        let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
        let alias = 0xcee0_0000u64;
        let pde = 0x3000 + ((alias >> 21) & 511) * 8;
        memory
            .memory()
            .write_slice(&0xfee0_0083u64.to_le_bytes(), GuestAddress(pde))
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            native.registers.insert(1, 0x202);
            native.registers.insert(5, alias);
            native
                .registers
                .insert(41, if watched_alias { alias } else { 0xfee0_0000 });
            native.vmcs.insert(0x640a, alias);
            native.vmcs.insert(0x681a, 0x3_0401);
        }
        let exit = cpu.run().unwrap();
        complete(cpu.as_mut(), &exit);
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
        assert_eq!(pending, if watched_alias { 0x1001 } else { 0 });
        assert_eq!(cpu.can_inject_interrupt(), !watched_alias);
        drop(cpu);
        drop(vm);
        drop(memory);
    }
    let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(1, 0x202);
        native.vmcs.insert(0x681a, 0x400);
        native.data_debug_fault = Some(DataDebugFault::AddressRead(41));
    }
    let exit = cpu.run().unwrap();
    complete(cpu.as_mut(), &exit);
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
    drop(cpu);
    drop(vm);
    drop(memory);
}

#[test]
fn data_debug_sdk_failures_fence_entry_without_exporting_a_device_access() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for fault in [
        DataDebugFault::ControlRead,
        DataDebugFault::AddressRead(41),
        DataDebugFault::AddressRead(42),
        DataDebugFault::PendingRead,
        DataDebugFault::PendingWriteBefore,
        DataDebugFault::PendingWriteAfter,
    ] {
        let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            native.registers.insert(1, 0x202);
            native.registers.insert(41, 0xfee0_0000);
            native.registers.insert(42, 0xfee0_0001);
            native
                .vmcs
                .insert(0x681a, 0x400 | 5 | (3 << 16) | (3 << 20));
            native.data_debug_fault = Some(fault);
        }
        assert!(cpu.run().is_err(), "{fault:?}");
        let before = entries();
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
        let terminal = match fault {
            DataDebugFault::PendingWriteBefore | DataDebugFault::PendingWriteAfter => {
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
            }
            _ => {
                assert!(
                    captured.is_err(),
                    "a retained SDK read failure prevents capture"
                );
                None
            }
        };
        drop(cpu);
        drop(vm);
        drop(memory);
        if let Some(bytes) = terminal {
            let (state, emulator, kind, data): (
                CpuState,
                rax::vm::snapshot::EmulatorState,
                u32,
                Vec<u8>,
            ) = rax::codec::deserialize_strict(&bytes).unwrap();
            let (vm, memory, mut cpu) = seeded(&[0x48, 0x8b, 0x03], 0x181, false);
            cpu.restore_checkpoint_context(
                &state,
                &emulator,
                Some(&rax::vm::snapshot::BackendContext { kind, data }),
            )
            .unwrap();
            let before = entries();
            assert!(
                cpu.run().is_err(),
                "restoring readable terminal state must retain its fence"
            );
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
