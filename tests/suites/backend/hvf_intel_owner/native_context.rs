//! Full native records must exist independently of their register projection.
use super::*;
use rax::vm::vcpu::{CpuState, VcpuExit};

#[test]
fn native_cpu_capture_returns_its_complete_backend_record() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let (public, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    assert!(matches!(public.state, CpuState::X86_64(_)));
    assert!(
        context.is_some(),
        "native checkpoint lost its private CPU state"
    );
    assert!(!context.unwrap().data.is_empty());
    drop(boundary);
    drop(cpu);
    drop(vm);
}

#[test]
fn native_checkpoint_captures_a_pending_input_without_discarding_it() {
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
        native.vmcs.insert(0x6400, (0x3f8 << 16) | 8);
        native.vmcs.insert(0x440c, 3);
        native.exits.push_back(30);
    }
    assert!(matches!(
        cpu.run().unwrap(),
        VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        }
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    let (public, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    assert!(matches!(public.state, CpuState::X86_64(_)));
    assert!(context.is_some());
    drop(boundary);
    cpu.complete_io_in(&[0x5a]);
    assert!(cpu.io_completion_result().is_ok());
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    assert_eq!(state.regs.rax & 0xff, 0x5a);
    assert_eq!(state.regs.rip, 3);
    drop(cpu);
    drop(vm);
}

fn capture(
    vm: &dyn rax::backend::Vm,
    cpu: &dyn rax::vm::vcpu::VCpu,
) -> (
    rax::vm::snapshot::CpuSnapshot,
    Option<rax::vm::snapshot::BackendContext>,
) {
    let boundary = vm.checkpoint_boundary().unwrap();
    cpu.capture_checkpoint_record(&boundary, None).unwrap()
}
fn port_exit(read: bool) {
    let mut sdk = SDK.lock().unwrap();
    let native = sdk.cpus.values_mut().next().unwrap();
    native
        .vmcs
        .insert(0x6400, (0x3f8 << 16) | if read { 8 } else { 0 });
    native.vmcs.insert(0x440c, 3);
    native.exits.push_back(30);
}
fn entries() -> usize {
    SDK.lock()
        .unwrap()
        .trace
        .iter()
        .filter(|item| item.starts_with("run:"))
        .count()
}

#[test]
fn pending_port_requests_restore_reemit_and_complete_once() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        port_exit(read);
        let exit = cpu.run().unwrap();
        assert!(matches!(
            exit,
            VcpuExit::IoIn { .. } | VcpuExit::IoOut { .. }
        ));
        let (public, context) = capture(vm.as_ref(), cpu.as_ref());
        if read {
            cpu.complete_io_in(&[0x5a]);
        } else {
            cpu.complete_io_out().unwrap();
        }
        assert!(cpu.io_completion_result().is_ok());
        cpu.restore_checkpoint_context(&public.state, &public.emulator, context.as_ref())
            .unwrap();
        let before = entries();
        assert!(matches!(
            cpu.run().unwrap(),
            VcpuExit::IoIn {
                port: 0x3f8,
                size: 1
            } | VcpuExit::IoOut { port: 0x3f8, .. }
        ));
        assert_eq!(entries(), before, "re-emission must not enter the SDK");
        if read {
            cpu.complete_io_in(&[0xa5]);
        } else {
            cpu.complete_io_out().unwrap();
        }
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture")
        };
        assert_eq!(state.regs.rip, 3);
        if read {
            assert_eq!(state.regs.rax & 0xff, 0xa5);
        }
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn received_input_and_acknowledged_output_failures_survive_raw_restore_without_redispatch() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for read in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        port_exit(read);
        cpu.run().unwrap();
        SDK.lock().unwrap().fault = Some(Fault {
            operation: "write-register",
            remaining: 1,
            persistent: false,
        });
        if read {
            cpu.complete_io_in(&[0x5a]);
        } else {
            assert!(cpu.complete_io_out().is_err());
        }
        assert!(cpu.io_completion_result().is_err());
        let (public, context) = capture(vm.as_ref(), cpu.as_ref());
        cpu.restore_checkpoint_context(&public.state, &public.emulator, context.as_ref())
            .unwrap();
        let before = entries();
        assert!(cpu.run().is_err());
        assert_eq!(
            entries(),
            before,
            "a completed device effect must not be reissued"
        );
        let (after, _) = capture(vm.as_ref(), cpu.as_ref());
        assert_eq!(
            rax::codec::serialize(&after.state).unwrap(),
            rax::codec::serialize(&public.state).unwrap()
        );
        drop(cpu);
        drop(vm);
    }
}

#[cfg(feature = "debug")]
#[test]
fn vm_restore_preserves_current_debug_controls_while_raw_import_uses_payload() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
    cpu.set_single_step(true);
    // The current client requested #BP interception after capture.
    SDK.lock()
        .unwrap()
        .cpus
        .values_mut()
        .next()
        .unwrap()
        .vmcs
        .insert(0x4004, 1 << 3);
    port_exit(false);
    assert!(matches!(cpu.run().unwrap(), VcpuExit::IoOut { .. }));
    cpu.complete_io_out().unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    cpu.restore_checkpoint_record(&boundary, &saved.state, &saved.emulator, context.as_ref())
        .unwrap();
    cpu.finish_checkpoint_restore(&boundary, context.as_ref())
        .unwrap();
    drop(boundary);
    assert!(cpu.is_single_step());
    {
        let sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values().next().unwrap();
        assert_ne!(native.vmcs[&0x4002] & (1 << 27), 0);
        assert_ne!(native.vmcs[&0x4004] & (1 << 3), 0);
        assert_eq!(native.registers.get(&1).copied().unwrap_or(2) & (1 << 8), 0);
    }
    let before = entries();
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(
        entries(),
        before + 1,
        "forward restore retained a stale step completion"
    );
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
        .unwrap();
    assert!(!cpu.is_single_step());
    let sdk = SDK.lock().unwrap();
    let native = sdk.cpus.values().next().unwrap();
    assert_eq!(native.vmcs[&0x4002] & (1 << 27), 0);
    assert_eq!(native.vmcs[&0x4004] & (1 << 3), 0);
    drop(sdk);
    drop(cpu);
    drop(vm);
}

#[cfg(feature = "debug")]
#[test]
fn rollback_restores_original_pending_debug_notification() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let (source, source_context) = capture(vm.as_ref(), cpu.as_ref());
    cpu.set_single_step(true);
    port_exit(false);
    assert!(matches!(cpu.run().unwrap(), VcpuExit::IoOut { .. }));
    cpu.complete_io_out().unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let (backup, backup_context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    cpu.restore_checkpoint_record(
        &boundary,
        &source.state,
        &source.emulator,
        source_context.as_ref(),
    )
    .unwrap();
    cpu.rollback_checkpoint_record(
        &boundary,
        &backup.state,
        &backup.emulator,
        backup_context.as_ref(),
    )
    .unwrap();
    cpu.finish_checkpoint_restore(&boundary, backup_context.as_ref())
        .unwrap();
    drop(boundary);
    let before = entries();
    assert!(matches!(cpu.run().unwrap(), VcpuExit::GdbStep));
    assert_eq!(
        entries(),
        before,
        "rollback lost the original destination notification"
    );
    drop(cpu);
    drop(vm);
}

#[test]
fn invalid_native_cpu_payload_rejects_before_any_sdk_write() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let (public, context) = capture(vm.as_ref(), cpu.as_ref());
    for corruption in 0..4 {
        let mut context = context.clone().unwrap();
        let mut public = public.clone();
        match corruption {
            0 => context.kind = rax::vm::snapshot::HVF_AARCH64_CONTEXT,
            1 => {
                context.data.pop();
            }
            2 => context.data.push(0),
            3 => {
                if let CpuState::X86_64(state) = &mut public.state {
                    state.regs.rax ^= 1;
                }
            }
            _ => unreachable!(),
        }
        let before = SDK.lock().unwrap().trace.len();
        assert!(
            cpu.restore_checkpoint_context(&public.state, &public.emulator, Some(&context))
                .is_err()
        );
        assert_eq!(SDK.lock().unwrap().trace.len(), before);
    }
    drop(cpu);
    drop(vm);
}

fn msr_exit(native_id: u32, write: Option<u64>) {
    let mut sdk = SDK.lock().unwrap();
    let native = sdk.cpus.get_mut(&native_id).unwrap();
    native.registers.insert(3, 0x10); // RCX
    if let Some(value) = write {
        native.registers.insert(2, value & 0xffff_ffff); // RAX
        native.registers.insert(4, value >> 32); // RDX
    }
    native.vmcs.insert(0x440c, 3);
    native.exits = [if write.is_some() { 32 } else { 31 }, 12]
        .into_iter()
        .collect();
}

#[test]
fn restored_native_cpus_rebase_distinct_tsc_values_against_one_resume_epoch() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for values in [[200u64, 400u64], [0, u64::MAX - 10]] {
        let (vm, memory) = fixture();
        let mut cpus = (0..2)
            .map(|id| {
                vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        SDK.lock().unwrap().tsc = 1000;
        for (id, cpu) in cpus.iter_mut().enumerate() {
            msr_exit(id as u32, Some(values[id]));
            assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        }
        let boundary = vm.checkpoint_boundary().unwrap();
        let saved = cpus
            .iter()
            .map(|cpu| cpu.capture_checkpoint_record(&boundary, None).unwrap())
            .collect::<Vec<_>>();
        let shared = vm.capture_checkpoint_vm_context(&boundary).unwrap();
        for (cpu, (state, context)) in cpus.iter_mut().zip(&saved) {
            cpu.restore_checkpoint_record(
                &boundary,
                &state.state,
                &state.emulator,
                context.as_ref(),
            )
            .unwrap();
        }
        vm.restore_checkpoint_vm_context(&boundary, shared.as_ref())
            .unwrap();
        for (cpu, (_, context)) in cpus.iter_mut().zip(&saved) {
            cpu.finish_checkpoint_restore(&boundary, context.as_ref())
                .unwrap();
        }
        drop(boundary);
        for (id, cpu) in cpus.iter_mut().enumerate() {
            SDK.lock().unwrap().tsc = 9000 + 50 * id as u64;
            cpu.wake();
            msr_exit(id as u32, None);
            assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
            let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                panic!("wrong architecture")
            };
            let value = state.regs.rax | (state.regs.rdx << 32);
            assert_eq!(value, values[id].wrapping_add(50 * id as u64));
            let sdk = SDK.lock().unwrap();
            assert_eq!(
                sdk.tsc
                    .wrapping_add(sdk.cpus[&(id as u32)].tsc_offset as u64),
                value
            );
        }
        drop(cpus);
        drop(vm);
    }
}

#[test]
fn native_mmio_load_store_alu_and_rmw_continuations_survive_raw_restore() {
    use rax::devices::bus::MmioRmwOp;
    use vm_memory::{Bytes, GuestAddress};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (code, qualification, expected_rax, expected_operation, expected_flags) in [
        (&[0x48, 0x8b, 0x03][..], 0x181, 5u64, None, 2), // MOV RAX,[RBX]
        (&[0x48, 0x89, 0x03][..], 0x182, 2, None, 2),    // MOV [RBX],RAX
        (&[0x48, 0x03, 0x03][..], 0x181, 7, None, 2),    // ADD RAX,[RBX]
        (
            &[0xf0, 0x48, 0x0f, 0xc1, 0x03][..],
            0x183,
            5,
            Some(MmioRmwOp::Add {
                value: 2,
                carry: false,
            }),
            2,
        ), // LOCK XADD
        (
            &[0x48, 0x0f, 0xa4, 0x03, 1][..],
            0x182,
            2,
            Some(MmioRmwOp::DoubleShiftLeft {
                source: 2,
                count: 1,
            }),
            6,
        ),
        (
            &[0x48, 0x0f, 0xad, 0x03][..],
            0x183,
            2,
            Some(MmioRmwOp::DoubleShiftRight {
                source: 2,
                count: 1,
            }),
            3,
        ),
    ] {
        let (vm, memory) = fixture();
        memory
            .memory()
            .write_slice(code, GuestAddress(0x100))
            .unwrap();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            native.registers.insert(0, 0x100);
            native.registers.insert(2, 2);
            native.registers.insert(3, 1); // CL count for SHRD; also a captured source.
            native.registers.insert(5, 0xfee0_0000);
            native.vmcs.insert(0x6400, qualification);
            native.vmcs.insert(0x640a, 0xfee0_0000);
            native.vmcs.insert(0x2400, 0xfee0_0000);
            native.exits.push_back(48);
        }
        // Real IA-32e inspection requires coherent CR0.PG/CR4.PAE/EFER.LMA.
        // PML4[0] -> PDPT, with PDPT[0] and PDPT[3] sharing one PD. Its
        // 2 MiB leaves map the code page and LAPIC operand page exactly.
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
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            // The SDK aliases CR0/CR3/CR4 and their VMCS guest fields.
            for (register, field, value) in [
                (36, 0x6800, 0x8000_0021),
                (39, 0x6802, 0x1000),
                (40, 0x6804, 0x20),
            ] {
                native.registers.insert(register, value);
                native.vmcs.insert(field, value);
            }
            native.registers.insert(1, 2); // RFLAGS architectural fixed bit.
            native.vmcs.insert(0x2806, 0x500); // EFER.LME and LMA.
            *native.vmcs.entry(0x4012).or_default() |= 1 << 9; // IA-32e entry.
        }
        let exit = cpu.run().unwrap();
        match &exit {
            VcpuExit::MmioRead {
                addr: 0xfee0_0000,
                size: 8,
            } => (),
            VcpuExit::MmioWrite {
                addr: 0xfee0_0000,
                data,
            } => assert_eq!(data, &2u64.to_le_bytes()),
            VcpuExit::MmioRmw {
                addr: 0xfee0_0000,
                size: 8,
                operation,
            } => assert_eq!(Some(*operation), expected_operation),
            exit => panic!("unexpected MMIO exit for {code:02x?}: {exit:?}"),
        }
        let (public, context) = capture(vm.as_ref(), cpu.as_ref());
        if matches!(exit, VcpuExit::MmioWrite { .. }) {
            cpu.complete_io_out().unwrap();
        } else {
            cpu.complete_io_in(&5u64.to_le_bytes());
        }
        assert!(cpu.io_completion_result().is_ok());
        cpu.restore_checkpoint_context(&public.state, &public.emulator, context.as_ref())
            .unwrap();
        let before = entries();
        let restored = cpu.run().unwrap();
        assert_eq!(format!("{restored:?}"), format!("{exit:?}"));
        assert_eq!(entries(), before);
        if matches!(restored, VcpuExit::MmioWrite { .. }) {
            cpu.complete_io_out().unwrap();
        } else {
            cpu.complete_io_in(&5u64.to_le_bytes());
        }
        assert!(cpu.io_completion_result().is_ok());
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture")
        };
        assert_eq!(state.regs.rax, expected_rax, "{code:02x?}");
        assert_eq!(
            state.regs.rflags & 0x8d5,
            expected_flags & 0x8d5,
            "{code:02x?}"
        );
        assert_eq!(state.regs.rip, 0x100 + code.len() as u64);
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn native_raw_record_restores_full_tpr_apic_role_and_pending_guest_event() {
    use rax::devices::bus::MmioDevice;
    use rax::devices::lapic::{LapicDevice, LocalApic};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    cpu.attach_local_apic(lapic.clone());
    let mut device = LapicDevice::new(lapic);
    device.write(0xfee0_0080, &0xabu32.to_le_bytes());
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.registers.insert(3, 0x1b);
        native.registers.insert(2, 0xfee0_0800);
        native.registers.insert(4, 0);
        native.vmcs.insert(0x440c, 3);
        native.exits = [32, 12].into_iter().collect();
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    cpu.wake();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.vmcs.insert(0x4016, 0x8000_0b0d); // queued #GP with error code
        native.vmcs.insert(0x4018, 0x20);
        native.vmcs.insert(0x401a, 0);
        native.vmcs.insert(0x6822, 1 << 14);
    }
    assert!(!cpu.is_bootstrap_processor().unwrap());
    let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
    device.write(0xfee0_0080, &0x10u32.to_le_bytes());
    SDK.lock()
        .unwrap()
        .cpus
        .values_mut()
        .next()
        .unwrap()
        .vmcs
        .insert(0x4016, 0);
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
        .unwrap();
    assert!(!cpu.is_bootstrap_processor().unwrap());
    let mut priority = [0; 4];
    device.read(0xfee0_0080, &mut priority);
    assert_eq!(u32::from_le_bytes(priority), 0xab);
    let sdk = SDK.lock().unwrap();
    let native = sdk.cpus.values().next().unwrap();
    assert_eq!(native.registers[&49], 0xab);
    assert_eq!(native.vmcs[&0x4016], 0x8000_0b0d);
    assert_eq!(native.vmcs[&0x4018], 0x20);
    assert_eq!(native.vmcs[&0x6822], 1 << 14);
    drop(sdk);
    drop(cpu);
    drop(vm);
}

#[test]
fn shared_record_keeps_sources_in_the_bus_controller_and_rejects_incomplete_topology() {
    fn controller_image(
        controller: &Mutex<rax::devices::ioapic::IoApic>,
    ) -> (Vec<u32>, Vec<rax::devices::ioapic::PendingIrq>) {
        use rax::devices::bus::MmioDevice;
        let mut controller = controller.lock().unwrap();
        let mut selected = [0; 4];
        controller.read(0xfec0_0000, &mut selected);
        let mut registers = Vec::new();
        for index in 0u8..0x40 {
            controller.write(0xfec0_0000, &[index]);
            let mut value = [0; 4];
            controller.read(0xfec0_0010, &mut value);
            registers.push(u32::from_le_bytes(value));
        }
        controller.write(0xfec0_0000, &selected);
        (registers, controller.pending().to_vec())
    }

    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ioapic = Arc::new(Mutex::new(rax::devices::ioapic::IoApic::new()));
    {
        use rax::devices::bus::MmioDevice;
        let mut controller = ioapic.lock().unwrap();
        for pin in [17u8, 20, 21] {
            controller.write(0xfec0_0000, &[0x10 + 2 * pin]);
            controller.write(0xfec0_0010, &(0x8051u32 + u32::from(pin)).to_le_bytes());
        }
    }
    let (vm, memory) = fixture_with_ioapic(ioapic.clone());
    let first = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let extra = vm
        .create_vcpu(2, Arc::new(memory.memory().clone()))
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    assert!(vm.capture_checkpoint_vm_context(&boundary).is_err());
    drop(boundary);
    drop(extra);
    vm.set_irq_line(20, true).unwrap();
    vm.set_irq_line(17, true).unwrap();
    vm.set_irq_line(20, true).unwrap();
    assert_eq!(ioapic.lock().unwrap().pending().len(), 2);
    for gsi in [24, 33, 44, u32::MAX] {
        assert!(vm.set_irq_line(gsi, true).is_err());
        assert!(vm.set_irq_line(gsi, false).is_err());
    }
    let boundary = vm.checkpoint_boundary().unwrap();
    let saved = vm.capture_checkpoint_vm_context(&boundary).unwrap();
    drop(boundary);
    vm.set_irq_line(20, false).unwrap();
    vm.set_irq_line(21, true).unwrap();
    let controller_after = controller_image(&ioapic);
    let boundary = vm.checkpoint_boundary().unwrap();
    let changed = vm.capture_checkpoint_vm_context(&boundary).unwrap();
    // CPU/global import does not replay source setters or rewind the PC-owned
    // controller. The complete VMM restore commits that controller separately.
    assert_eq!(changed, saved);
    vm.restore_checkpoint_vm_context(&boundary, saved.as_ref())
        .unwrap();
    assert_eq!(vm.capture_checkpoint_vm_context(&boundary).unwrap(), saved);
    assert_eq!(controller_image(&ioapic), controller_after);
    type SharedWire = (
        u8,
        u64,
        Vec<(u64, u64)>,
        Vec<(u64, u64)>,
        Vec<u32>,
        Option<u64>,
        u64,
    );
    let mut detached = saved.clone().unwrap();
    let mut wire: SharedWire = rax::codec::deserialize_strict(&detached.data[8..]).unwrap();
    wire.4 = vec![20];
    detached.data.truncate(8);
    detached.data.extend(rax::codec::serialize(&wire).unwrap());
    assert!(
        vm.restore_checkpoint_vm_context(&boundary, Some(&detached))
            .is_err()
    );
    assert_eq!(vm.capture_checkpoint_vm_context(&boundary).unwrap(), saved);
    assert_eq!(controller_image(&ioapic), controller_after);
    let mut foreign = saved.clone().unwrap();
    foreign.kind = rax::vm::snapshot::HVF_AARCH64_CONTEXT;
    assert!(
        vm.restore_checkpoint_vm_context(&boundary, Some(&foreign))
            .is_err()
    );
    assert_eq!(vm.capture_checkpoint_vm_context(&boundary).unwrap(), saved);
    drop(boundary);
    drop(first);
    drop(vm);
}

#[test]
fn native_emulator_projection_round_trips_x87_mxcsr_kernel_gs_and_auxiliary_state() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let mut emulator = cpu.get_emulator_state().unwrap();
    assert_eq!(emulator.pat, 0x0007_0406_0007_0406);
    emulator.pat = 0x0405_0607_0001_0406;
    emulator.kernel_gs_base = 0xffff_8000_1234_0000;
    emulator.tsc_aux = 0x89ab_cdef;
    emulator.mxcsr = 0x5f81;
    emulator.fpu.top = 3;
    emulator.fpu.status_word = 3 << 11;
    emulator.fpu.tag_word &= !(3 << 6);
    emulator.fpu.st[3][..8].copy_from_slice(&(1u64 << 63).to_le_bytes());
    emulator.fpu.st[3][8..].copy_from_slice(&0x3fffu16.to_le_bytes());
    emulator.fpu.instr_ptr = 0xffff_8000_7654_3210;
    emulator.fpu.data_ptr = 0xffff_8000_0123_4567;
    emulator.interrupt_inhibit = true;
    emulator.halted = true;
    cpu.set_emulator_state(&emulator).unwrap();
    let actual = cpu.get_emulator_state().unwrap();
    assert_eq!(
        rax::codec::serialize(&actual).unwrap(),
        rax::codec::serialize(&emulator).unwrap()
    );
    let CpuState::X86_64(public) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    assert_eq!(public.regs.mm[3], 1 << 63);
    emulator.pat = 2; // Reserved PAT memory type.
    let calls = SDK.lock().unwrap().trace.len();
    assert!(cpu.set_emulator_state(&emulator).is_err());
    assert_eq!(SDK.lock().unwrap().trace.len(), calls);
    assert_eq!(
        rax::codec::serialize(&cpu.get_emulator_state().unwrap()).unwrap(),
        rax::codec::serialize(&actual).unwrap()
    );
    drop(cpu);
    drop(vm);
}

#[test]
fn raw_native_import_rolls_back_every_partial_sdk_setter_and_full_fp_image() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for operation in [
        "write-register",
        "fp-write",
        "write-vmcs",
        "write-msr",
        "invalidate",
    ] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let (source, source_context) = capture(vm.as_ref(), cpu.as_ref());
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values_mut().next().unwrap();
            native.registers.insert(2, 0xface_1234);
            native.vmcs.insert(0x6004, 0x1234); // CR0 read shadow
            native.vmcs.insert(0x2802, 1); // guest DEBUGCTL
            native.msrs.insert(0xc000_0102, 0xffff_8000_1234_0000);
            native.fpstate[512..520].copy_from_slice(&7u64.to_le_bytes());
            native.fpstate[160..416].fill(0x5a);
            native.fpstate[576..832].fill(0xa5);
        }
        let (before, before_context) = capture(vm.as_ref(), cpu.as_ref());
        let fp = SDK
            .lock()
            .unwrap()
            .cpus
            .values()
            .next()
            .unwrap()
            .fpstate
            .clone();
        SDK.lock().unwrap().fault = Some(Fault {
            operation,
            remaining: if matches!(operation, "write-register" | "write-vmcs" | "write-msr") {
                2
            } else {
                1
            },
            persistent: false,
        });
        let error = cpu
            .restore_checkpoint_context(&source.state, &source.emulator, source_context.as_ref())
            .unwrap_err();
        assert!(
            !error.to_string().contains("rollback failed"),
            "{operation}: {error}"
        );
        let (after, after_context) = capture(vm.as_ref(), cpu.as_ref());
        assert_eq!(
            rax::codec::serialize(&after.state).unwrap(),
            rax::codec::serialize(&before.state).unwrap(),
            "{operation}"
        );
        assert_eq!(after_context, before_context, "{operation}");
        assert_eq!(
            SDK.lock().unwrap().cpus.values().next().unwrap().fpstate,
            fp,
            "{operation}"
        );
        assert!(
            cpu.get_state().is_ok(),
            "successful rollback must clear the temporary restore fence"
        );
        drop(cpu);
        drop(vm);
    }
}

#[cfg(not(feature = "debug"))]
#[test]
fn no_debug_backend_rejects_raw_debug_controls_and_preserves_current_vm_controls() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
    let boundary = vm.checkpoint_boundary().unwrap();
    let shared = vm.capture_checkpoint_vm_context(&boundary).unwrap();
    drop(boundary);
    for single_step in [false, true] {
        let mut record = context.clone().unwrap();
        let id: u32 = if single_step { 0x4002 } else { 0x4004 };
        let old = SDK.lock().unwrap().cpus.values().next().unwrap().vmcs[&id];
        let mut marker = id.to_le_bytes().to_vec();
        marker.extend(old.to_le_bytes());
        let offset = record
            .data
            .windows(marker.len())
            .rposition(|bytes| bytes == marker)
            .unwrap();
        let value = old | if single_step { 1 << 27 } else { 1 << 3 };
        record.data[offset + 4..offset + 12].copy_from_slice(&value.to_le_bytes());
        if single_step {
            // DebugState is the final inner schema field: enabled, completed,
            // and the absent-failure Option tag are one byte each.
            let length = record.data.len();
            assert_eq!(&record.data[length - 3..], &[0, 0, 0]);
            record.data[length - 3] = 1;
        }
        // This remains a readable producer record for forward VM restoration.
        cpu.validate_checkpoint_context(&saved.state, &saved.emulator, Some(&record))
            .unwrap();
        let calls = SDK.lock().unwrap().trace.len();
        let error = cpu
            .restore_checkpoint_context(&saved.state, &saved.emulator, Some(&record))
            .unwrap_err();
        assert!(
            error.to_string().contains("debug-enabled backend"),
            "{error}"
        );
        assert_eq!(SDK.lock().unwrap().trace.len(), calls);
        let boundary = vm.checkpoint_boundary().unwrap();
        cpu.restore_checkpoint_record(&boundary, &saved.state, &saved.emulator, Some(&record))
            .unwrap();
        vm.restore_checkpoint_vm_context(&boundary, shared.as_ref())
            .unwrap();
        cpu.finish_checkpoint_restore(&boundary, Some(&record))
            .unwrap();
        drop(boundary);
        {
            let sdk = SDK.lock().unwrap();
            let native = sdk.cpus.values().next().unwrap();
            assert_eq!(native.vmcs[&0x4002] & (1 << 27), 0);
            assert_eq!(native.vmcs[&0x4004] & ((1 << 1) | (1 << 3)), 0);
        }
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    }
    let mut guest = cpu.get_state().unwrap();
    let CpuState::X86_64(state) = &mut guest else {
        panic!("wrong architecture")
    };
    state.regs.rflags |= 1 << 8;
    cpu.set_state(&guest).unwrap();
    let (guest, guest_context) = capture(vm.as_ref(), cpu.as_ref());
    cpu.restore_checkpoint_context(&guest.state, &guest.emulator, guest_context.as_ref())
        .unwrap();
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    assert_ne!(
        state.regs.rflags & (1 << 8),
        0,
        "guest TF is independent of host debugger controls"
    );
    drop(cpu);
    drop(vm);
}
