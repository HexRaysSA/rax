//! Actual native bank composition through managed descriptors and exclusion.
use super::*;
use crate::backend::kvm::KvmBackend;
use crate::backend::{Backend, Vm};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

#[path = "first_entry_tests.rs"]
mod first_entry;

#[path = "device_clock_tests.rs"]
mod device_clock;

#[path = "deferred_owner_tests.rs"]
mod deferred;

#[path = "terminal_owner_tests.rs"]
mod terminal;

#[path = "terminal_provenance_tests.rs"]
mod terminal_provenance;

fn graph(count: u8, irqchip: bool) -> (Box<dyn Vm>, GuestMemoryWrapper, Vec<Box<dyn VCpu>>) {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    vm.configure_cpu_topology(count, 2 * 1024 * 1024).unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    if irqchip {
        native.create_irq_chip().unwrap();
    }
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    memory
        .memory()
        .write_slice(&[0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap(); // OUT 0xe9,AL; HLT.
    let mut cpus = Vec::new();
    for id in 0..count {
        let mut cpu = vm
            .create_vcpu(u32::from(id), Arc::new(memory.memory().clone()))
            .unwrap();
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rip = 0x1000;
        state.regs.rax = 0x21 + u64::from(id);
        state.regs.rbx = 0x1234_5678_9000 + u64::from(id);
        state.regs.rflags = 2;
        state.sregs.cs.base = 0;
        state.sregs.cs.selector = 0;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
        cpus.push(cpu);
    }
    // The fixture deliberately starts every CPU directly. Startup/IPI/HLT
    // scheduling has separate actual VMM tests; it is not inferred here.
    let boundary = vm.checkpoint_boundary().unwrap();
    let handles = native.checkpoint_cpu_handles(&boundary).unwrap();
    for core in lock_cpus(native, &handles).unwrap() {
        core.vcpu_fd
            .set_mp_state(kvm_bindings::kvm_mp_state {
                mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
            })
            .unwrap();
    }
    drop(boundary);
    (vm, memory, cpus)
}

fn native(vm: &dyn Vm) -> &KvmVm {
    vm.as_any().downcast_ref().unwrap()
}

fn stored_cpu_banks(image: &Image) -> serde_json::Value {
    let mut cpus = serde_json::to_value(&image.cpus).unwrap();
    for cpu in cpus.as_array_mut().unwrap() {
        // These three counters advance while stopped and were explicitly
        // separated by the qualified migration-MSR plan. Stored banks remain
        // exact; this exclusion is not a claim of full clock activation.
        cpu["msrs"]["counters"] = serde_json::Value::Null;
    }
    cpus
}

fn controller_bytes(vm: &KvmVm) -> Vec<Vec<u8>> {
    use zerocopy::IntoBytes;
    [
        kvm_bindings::KVM_IRQCHIP_PIC_MASTER,
        kvm_bindings::KVM_IRQCHIP_PIC_SLAVE,
        kvm_bindings::KVM_IRQCHIP_IOAPIC,
    ]
    .into_iter()
    .map(|chip_id| {
        let mut chip = kvm_bindings::kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        vm.memory.vm_fd.get_irqchip(&mut chip).unwrap();
        chip.as_bytes().to_vec()
    })
    .collect()
}

fn program_masked_controllers(vm: &KvmVm) {
    for (chip_id, irq_base, priority_add) in [
        (kvm_bindings::KVM_IRQCHIP_PIC_MASTER, 0x20, 3),
        (kvm_bindings::KVM_IRQCHIP_PIC_SLAVE, 0x28, 5),
    ] {
        let mut chip = kvm_bindings::kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        vm.memory.vm_fd.get_irqchip(&mut chip).unwrap();
        // SAFETY: successful GET_IRQCHIP selected this PIC member by chip_id.
        // It is a live initialized integer-only value, copied locally while
        // the fixture owns VM exclusion. No union reference or pointer escapes.
        let mut pic = unsafe { chip.chip.pic };
        pic.irq_base = irq_base;
        pic.priority_add = priority_add;
        pic.imr = 0xff;
        chip.chip.pic = pic;
        vm.memory.vm_fd.set_irqchip(&chip).unwrap();
    }
    let mut chip = kvm_bindings::kvm_irqchip {
        chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    vm.memory.vm_fd.get_irqchip(&mut chip).unwrap();
    // SAFETY: successful GET_IRQCHIP selected the initialized IOAPIC member.
    // The union has integer-only fields and is copied under fixture exclusion.
    let mut ioapic = unsafe { chip.chip.ioapic };
    ioapic.id = 7;
    ioapic.ioregsel = 0x1b;
    for (pin, entry) in ioapic.redirtbl.iter_mut().enumerate() {
        // Mask every pin, retain distinct vectors and alternate trigger modes.
        entry.bits = (1 << 16) | ((pin as u64 & 1) << 15) | (0x40 + pin as u64);
    }
    chip.chip.ioapic = ioapic;
    vm.memory.vm_fd.set_irqchip(&chip).unwrap();
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn shared_irqchip_banks_survive_source_free_owner_restore() {
    for count in [1, 2, 4] {
        let (source, memory, cpus) = graph(count, true);
        let boundary = source.checkpoint_boundary().unwrap();
        let source_vm = native(&*source);
        program_masked_controllers(source_vm);
        let expected = controller_bytes(source_vm);
        let image = source_vm.capture_native_banks(&boundary).unwrap();
        let json = serde_json::to_vec(&image).unwrap();
        let binary = crate::codec::serialize(&image).unwrap();
        drop(boundary);
        drop(cpus);
        drop(source);
        drop(memory);
        for image in [
            serde_json::from_slice::<Image>(&json).unwrap(),
            crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
        ] {
            let (target, _memory, _cpus) = graph(count, true);
            let boundary = target.checkpoint_boundary().unwrap();
            let target_vm = native(&*target);
            assert_ne!(controller_bytes(target_vm), expected);
            image.restore_stored(target_vm, &boundary).unwrap();
            assert_eq!(
                controller_bytes(target_vm),
                expected,
                "shared native controller banks were omitted from managed restore"
            );
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn source_free_shared_restore_replaces_every_external_line_level() {
    for count in [1, 2, 4] {
        for levels in [
            [false; 24],
            [true; 24],
            std::array::from_fn(|pin| pin % 2 == 0),
        ] {
            let (source, memory, cpus) = graph(count, true);
            let boundary = source.checkpoint_boundary().unwrap();
            program_masked_controllers(native(&*source));
            drop(boundary);
            for (gsi, level) in levels.iter().copied().enumerate() {
                source.set_irq_line(gsi as u32, level).unwrap();
            }
            let boundary = source.checkpoint_boundary().unwrap();
            let source_vm = native(&*source);
            let expected = controller_bytes(source_vm);
            let image = source_vm.capture_native_banks(&boundary).unwrap();
            let json = serde_json::to_vec(&image).unwrap();
            let binary = crate::codec::serialize(&image).unwrap();
            drop(boundary);
            drop(cpus);
            drop(source);
            drop(memory);
            for image in [
                serde_json::from_slice::<Image>(&json).unwrap(),
                crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
            ] {
                let (target, _memory, _cpus) = graph(count, true);
                let boundary = target.checkpoint_boundary().unwrap();
                program_masked_controllers(native(&*target));
                drop(boundary);
                for (gsi, level) in levels.iter().copied().enumerate() {
                    target.set_irq_line(gsi as u32, !level).unwrap();
                }
                let boundary = target.checkpoint_boundary().unwrap();
                let target_vm = native(&*target);
                image.restore_stored(target_vm, &boundary).unwrap();
                assert_eq!(controller_bytes(target_vm), expected);
                let after = target_vm.capture_native_banks(&boundary).unwrap();
                assert_eq!(after.shared, image.shared);
                assert_eq!(target_vm.memory.irq_lines.lock().unwrap().levels(), levels);
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn malformed_shared_banks_reject_before_cpu_controller_or_line_changes() {
    let (vm, _memory, _cpus) = graph(2, true);
    vm.set_irq_line(3, true).unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let before = vm.capture_native_banks(&boundary).unwrap();
    let controllers = controller_bytes(vm);
    let json = serde_json::to_value(&before).unwrap();
    let mut bad = Vec::new();
    let mut version = json.clone();
    version["shared"]["version"] = 2.into();
    bad.push(version);
    let mut kind = json.clone();
    kind["shared"]["pics"][0]["kind"] = 14.into();
    bad.push(kind);
    let mut length = json.clone();
    length["shared"]["ioapic"]["bytes"]
        .as_array_mut()
        .unwrap()
        .pop();
    bad.push(length);
    let mut padding = json.clone();
    // The retained x86 UAPI puts IOAPIC.pad at byte 20.
    padding["shared"]["ioapic"]["bytes"][20] = 1.into();
    bad.push(padding);
    let mut missing = json;
    missing["shared"] = serde_json::Value::Null;
    bad.push(missing);
    for record in bad {
        let image: Image = serde_json::from_value(record).unwrap();
        assert!(image.restore_stored(vm, &boundary).is_err());
        assert_eq!(controller_bytes(vm), controllers);
        let after = vm.capture_native_banks(&boundary).unwrap();
        assert_eq!(after.shared, before.shared);
        assert_eq!(stored_cpu_banks(&after), stored_cpu_banks(&before));
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn unmanaged_vm_sdk_access_disables_only_managed_checkpoint_admission() {
    let (vm, _memory, mut cpus) = graph(1, true);
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    // SAFETY: this fixture retains VM/RAM/CPU owners and does not derive an
    // object, mutate the descriptor or enter concurrently. The borrow merely
    // exercises monotonic admission after SDK access could have changed routes.
    let _ = unsafe { native.vm_fd() };
    assert!(native.capture_native_banks(&boundary).is_err());
    drop(boundary);
    assert!(vm.checkpoint_boundary().is_err());
    vm.set_irq_line(3, true).unwrap();
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoOut { port: 0xe9, data } if data == [0x21]
    ));
}

fn interrupt_graph(
    count: u8,
    masked: bool,
) -> (Box<dyn Vm>, GuestMemoryWrapper, Vec<Box<dyn VCpu>>) {
    let (vm, memory, mut cpus) = graph(count, true);
    memory
        .memory()
        .write_slice(&[0xfb, 0xf4, 0xeb, 0xfd], GuestAddress(0x1000))
        .unwrap(); // STI; HLT; JMP back to HLT.
    memory
        .memory()
        .write_slice(&[0x00, 0x20, 0x00, 0x00], GuestAddress(0x41 * 4))
        .unwrap(); // Real-mode vector0x41 -> 0000:2000.
    memory
        .memory()
        .write_slice(
            &[
                0xfe, 0x06, 0x00, 0x30, // INC byte [0x3000].
                0xa0, 0x00, 0x30, // MOV AL,[0x3000].
                0xe6, 0xe9, // OUT 0xe9,AL before EOI.
                0x67, 0x66, 0xc7, 0x05, 0xb0, 0x00, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00,
                // MOV dword [0xfee000b0],0; address/operand-size overrides.
                0xcf, // IRET.
            ],
            GuestAddress(0x2000),
        )
        .unwrap();
    for (id, cpu) in cpus.iter_mut().enumerate() {
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rsp = 0x8000 + id as u64 * 0x1000;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 0x3ff;
        // Unreal-mode flat data permits the 32-bit EOI MMIO address. The
        // default real-mode 64 KiB segment would fault before acknowledging it.
        state.sregs.ds.limit = u32::MAX;
        state.sregs.ds.g = true;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
    }
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    program_masked_controllers(native);
    let handles = native.checkpoint_cpu_handles(&boundary).unwrap();
    for core in lock_cpus(native, &handles).unwrap() {
        let mut lapic = core.vcpu_fd.get_lapic().unwrap();
        lapic.regs[0xf0..0xf4].copy_from_slice(&0x1ff_u32.to_le_bytes().map(|byte| byte as i8));
        lapic.regs[0x350..0x354]
            .copy_from_slice(&(1_u32 << 16).to_le_bytes().map(|byte| byte as i8));
        core.vcpu_fd.set_lapic(&lapic).unwrap();
    }
    set_level_route(native, count - 1, masked);
    drop(boundary);
    (vm, memory, cpus)
}

fn set_level_route(vm: &KvmVm, destination: u8, masked: bool) {
    let mut chip = kvm_bindings::kvm_irqchip {
        chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    vm.memory.vm_fd.get_irqchip(&mut chip).unwrap();
    // SAFETY: GET_IRQCHIP selected the initialized integer-only IOAPIC member.
    // The fixture owns VM exclusion and replaces only a local redirection entry.
    let mut ioapic = unsafe { chip.chip.ioapic };
    ioapic.redirtbl[17].bits =
        (u64::from(destination) << 56) | (u64::from(masked) << 16) | (1 << 15) | 0x41;
    chip.chip.ioapic = ioapic;
    vm.memory.vm_fd.set_irqchip(&chip).unwrap();
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn restored_level_interrupt_routes_to_saved_cpu_and_eoi_does_not_duplicate_it() {
    for count in [1, 2, 4] {
        for masked in [false, true] {
            let (source, memory, cpus) = interrupt_graph(count, masked);
            source.set_irq_line(17, true).unwrap();
            let boundary = source.checkpoint_boundary().unwrap();
            let image = native(&*source).capture_native_banks(&boundary).unwrap();
            let json = serde_json::to_vec(&image).unwrap();
            let binary = crate::codec::serialize(&image).unwrap();
            drop(boundary);
            drop(cpus);
            drop(source);
            drop(memory);
            for image in [
                serde_json::from_slice::<Image>(&json).unwrap(),
                crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
            ] {
                // Identical fixture RAM is supplied independently. This proves
                // IRQ/CPU continuation, not full RAM checkpoint publication.
                let (target, _memory, mut cpus) = interrupt_graph(count, masked);
                let boundary = target.checkpoint_boundary().unwrap();
                let vm = native(&*target);
                image.restore_stored(vm, &boundary).unwrap();
                if masked {
                    set_level_route(vm, count - 1, false);
                }
                image.rebase_clock(vm, &boundary).unwrap();
                drop(boundary);
                let selected = usize::from(count - 1);
                for cpu in &mut cpus[..selected] {
                    assert!(
                        cpu.run_host_slice(Duration::from_millis(10))
                            .unwrap()
                            .is_none()
                    );
                }
                assert!(matches!(
                    exit(&mut *cpus[selected]),
                    VcpuExit::IoOut { port: 0xe9, data } if data == [1]
                ));
                target.set_irq_line(17, false).unwrap();
                cpus[selected].complete_io_out().unwrap();
                assert!(
                    cpus[selected]
                        .run_host_slice(Duration::from_millis(10))
                        .unwrap()
                        .is_none()
                );
                // A new assertion must deliver once after the saved remote-IRR
                // is acknowledged, rather than getting lost or replaying twice.
                target.set_irq_line(17, true).unwrap();
                assert!(matches!(
                    exit(&mut *cpus[selected]),
                    VcpuExit::IoOut { port: 0xe9, data } if data == [2]
                ));
                target.set_irq_line(17, false).unwrap();
                cpus[selected].complete_io_out().unwrap();
                assert!(
                    cpus[selected]
                        .run_host_slice(Duration::from_millis(10))
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}

fn offsets(image: &Image) -> Vec<u64> {
    serde_json::to_value(&image.clock).unwrap()["cpus"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cpu| cpu["offset"].as_u64().unwrap())
        .collect()
}

fn exit(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            return exit;
        }
    }
    panic!("native bank fixture did not reach its output frontier");
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn managed_bank_records_restore_source_free_one_two_four_cpu_graphs() {
    for count in [1, 2, 4] {
        for irqchip in [false, true] {
            let (source, memory, cpus) = graph(count, irqchip);
            let boundary = source.checkpoint_boundary().unwrap();
            let saved = native(&*source).capture_native_banks(&boundary).unwrap();
            let json = serde_json::to_vec(&saved).unwrap();
            let binary = crate::codec::serialize(&saved).unwrap();
            drop(boundary);
            // No original native CPU, VM FD or RAM owner survives decoding.
            drop(cpus);
            drop(source);
            drop(memory);
            for image in [
                serde_json::from_slice::<Image>(&json).unwrap(),
                crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
            ] {
                let (target, _memory, mut cpus) = graph(count, irqchip);
                let boundary = target.checkpoint_boundary().unwrap();
                let vm = native(&*target);
                image.validate_target(vm, &boundary).unwrap();
                image.restore_stored(vm, &boundary).unwrap();
                image.rebase_clock(vm, &boundary).unwrap();
                let restored = vm.capture_native_banks(&boundary).unwrap();
                assert_eq!(stored_cpu_banks(&restored), stored_cpu_banks(&image));
                let before = offsets(&image);
                let after = offsets(&restored);
                let delta = after[0].wrapping_sub(before[0]);
                assert!(
                    after
                        .iter()
                        .zip(&before)
                        .all(|(after, before)| after.wrapping_sub(*before) == delta)
                );
                drop(boundary);
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    assert!(
                        matches!(exit(&mut **cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8])
                    );
                    cpu.complete_io_out().unwrap();
                    if irqchip {
                        // A kernel LAPIC consumes HLT and blocks natively;
                        // the bounded host yield is not a guest HLT exit.
                        assert!(
                            cpu.run_host_slice(Duration::from_millis(10))
                                .unwrap()
                                .is_none()
                        );
                    } else {
                        assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn foreign_bank_boundary_is_rejected_by_the_actual_owner() {
    let (source, _source_memory, _source_cpus) = graph(1, false);
    let (target, _target_memory, _target_cpus) = graph(1, false);
    let foreign = source.checkpoint_boundary().unwrap();
    assert!(native(&*target).capture_native_banks(&foreign).is_err());
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn reordered_cpu_records_reject_before_changing_any_target_bank() {
    let (vm, _memory, _cpus) = graph(2, true);
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let before = vm.capture_native_banks(&boundary).unwrap();
    let mut bad = before.clone();
    bad.cpus.swap(0, 1);
    assert!(bad.restore_stored(vm, &boundary).is_err());
    assert_eq!(
        stored_cpu_banks(&before),
        stored_cpu_banks(&vm.capture_native_banks(&boundary).unwrap())
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn unsupported_bank_version_rejects_before_changing_any_target_bank() {
    let (vm, _memory, _cpus) = graph(1, false);
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let before = vm.capture_native_banks(&boundary).unwrap();
    let mut bad = before.clone();
    bad.version = u16::MAX;
    assert!(bad.restore_stored(vm, &boundary).is_err());
    assert_eq!(
        stored_cpu_banks(&before),
        stored_cpu_banks(&vm.capture_native_banks(&boundary).unwrap())
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn userspace_halt_survives_source_free_restore_and_replaces_the_target_wait_state() {
    for count in [1, 2, 4] {
        for halted in [false, true] {
            let (source, memory, mut cpus) = graph(count, false);
            memory
                .memory()
                .write_slice(&[0xf4, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
                .unwrap(); // HLT; OUT 0xe9,AL; HLT.
            for (id, cpu) in cpus.iter_mut().enumerate() {
                let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                state.sregs.cr8 = id as u64 + 1;
                cpu.set_state(&CpuState::X86_64(state)).unwrap();
                if halted {
                    assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
                } else {
                    cpu.set_current_pc(0x1001).unwrap();
                }
                assert_eq!(cpu.current_pc(), 0x1001);
            }
            let boundary = source.checkpoint_boundary().unwrap();
            let saved = native(&*source).capture_native_banks(&boundary).unwrap();
            if halted {
                // The incomplete public producer must not silently omit the
                // wait state retained by the internal complete CPU bank.
                assert!(cpus[0].capture_checkpoint_record(&boundary, None).is_err());
            }
            let json = serde_json::to_vec(&saved).unwrap();
            let binary = crate::codec::serialize(&saved).unwrap();
            drop(boundary);
            drop(cpus);
            drop(source);
            drop(memory);
            for image in [
                serde_json::from_slice::<Image>(&json).unwrap(),
                crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
            ] {
                let (target, memory, mut cpus) = graph(count, false);
                memory
                    .memory()
                    .write_slice(&[0xf4, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
                    .unwrap();
                if !halted {
                    for cpu in &mut cpus {
                        assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
                    }
                }
                let boundary = target.checkpoint_boundary().unwrap();
                image.restore_stored(native(&*target), &boundary).unwrap();
                let restored = native(&*target).capture_native_banks(&boundary).unwrap();
                assert!(
                    restored
                        .cpus
                        .iter()
                        .all(|cpu| cpu.userspace_halted == halted)
                );
                drop(boundary);
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    assert_eq!(cpu.current_pc(), 0x1001);
                    if halted {
                        for _ in 0..3 {
                            assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
                            assert_eq!(cpu.current_pc(), 0x1001);
                        }
                        cpu.wake();
                    }
                    assert!(
                        matches!(exit(&mut **cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8])
                    );
                    let CpuState::X86_64(observed) = cpu.get_state().unwrap() else {
                        unreachable!()
                    };
                    assert_eq!(observed.sregs.cr8, id as u64 + 1);
                }
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn legacy_or_kernel_owned_userspace_halt_records_reject_before_native_mutation() {
    for irqchip in [false, true] {
        let (target, _memory, _cpus) = graph(1, irqchip);
        let boundary = target.checkpoint_boundary().unwrap();
        let vm = native(&*target);
        let before = vm.capture_native_banks(&boundary).unwrap();
        let mut record = serde_json::to_value(&before).unwrap();
        if irqchip {
            record["cpus"][0]["userspace_halted"] = true.into();
        } else {
            record["cpus"][0]["version"] = 1.into();
        }
        let invalid: Image = serde_json::from_value(record).unwrap();
        assert!(invalid.restore_stored(vm, &boundary).is_err());
        assert_eq!(
            stored_cpu_banks(&before),
            stored_cpu_banks(&vm.capture_native_banks(&boundary).unwrap())
        );
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn explicit_kernel_wake_resumes_halted_cpus_but_preserves_uninitialized_peers() {
    let (vm, memory, mut cpus) = graph(2, true);
    memory
        .memory()
        .write_slice(&[0xf4, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap();
    for cpu in &mut cpus {
        assert!(
            cpu.run_host_slice(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        assert_eq!(cpu.current_pc(), 0x1001);
    }
    let boundary = vm.checkpoint_boundary().unwrap();
    let handles = native(&*vm).checkpoint_cpu_handles(&boundary).unwrap();
    let cores = lock_cpus(native(&*vm), &handles).unwrap();
    assert!(cores.iter().all(|core| {
        core.vcpu_fd.get_mp_state().unwrap().mp_state == kvm_bindings::KVM_MP_STATE_HALTED
    }));
    cores[1]
        .vcpu_fd
        .set_mp_state(kvm_bindings::kvm_mp_state {
            mp_state: kvm_bindings::KVM_MP_STATE_UNINITIALIZED,
        })
        .unwrap();
    drop(cores);
    drop(boundary);
    cpus[0].wake();
    cpus[1].wake();
    assert!(matches!(exit(&mut *cpus[0]), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21]));
    let boundary = vm.checkpoint_boundary().unwrap();
    let handles = native(&*vm).checkpoint_cpu_handles(&boundary).unwrap();
    let cores = lock_cpus(native(&*vm), &handles).unwrap();
    assert_eq!(
        cores[1].vcpu_fd.get_mp_state().unwrap().mp_state,
        kvm_bindings::KVM_MP_STATE_UNINITIALIZED
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn pending_input_is_preserved_when_managed_bank_capture_rejects() {
    let (vm, memory, mut cpus) = graph(1, false);
    memory
        .memory()
        .write_slice(&[0xec, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x1234;
    cpus[0].set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoIn {
            port: 0x1234,
            size: 1
        }
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    assert!(native(&*vm).capture_native_banks(&boundary).is_err());
    drop(boundary);
    cpus[0].complete_io_in(&[0x7c]);
    assert!(matches!(exit(&mut *cpus[0]), VcpuExit::IoOut { port: 0xe9, data } if data == [0x7c]));
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn pending_peer_preflight_does_not_accept_another_cpus_init() {
    let (vm, memory, mut cpus) = graph(2, true);
    memory
        .memory()
        .write_slice(&[0xec, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpus[1].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x1234;
    cpus[1].set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(
        exit(&mut *cpus[1]),
        VcpuExit::IoIn {
            port: 0x1234,
            size: 1
        }
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    let handles = native.checkpoint_cpu_handles(&boundary).unwrap();
    let before = handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap();
    // Deliver a real physical-destination INIT to CPU0. GET_MP_STATE would
    // accept it and reset CPU0; the peer's pending I/O must reject the whole
    // capture before any CPU getter with that architectural side effect.
    assert_eq!(
        native
            .memory
            .vm_fd
            .signal_msi(kvm_bindings::kvm_msi {
                address_lo: 0xfee0_0000,
                data: 0x4500,
                ..Default::default()
            })
            .unwrap(),
        1
    );
    assert!(native.capture_native_banks(&boundary).is_err());
    assert_eq!(
        handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap(),
        before,
        "rejected peer capture accepted CPU0 INIT before checking all CPUs"
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn errored_peer_rejects_capture_before_accepting_another_cpus_init() {
    let (vm, _memory, mut cpus) = graph(2, true);
    // There is no outstanding input. The void compatibility callback retains
    // this protocol error even though no native buffer is pending.
    cpus[1].complete_io_in(&[0x7c]);
    assert!(cpus[1].io_completion_result().is_err());
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    let handles = native.checkpoint_cpu_handles(&boundary).unwrap();
    let before = handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap();
    assert_eq!(
        native
            .memory
            .vm_fd
            .signal_msi(kvm_bindings::kvm_msi {
                address_lo: 0xfee0_0000,
                data: 0x4500,
                ..Default::default()
            })
            .unwrap(),
        1
    );
    let captured = native.capture_native_banks(&boundary);
    assert_eq!(
        handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap(),
        before,
        "errored peer capture accepted CPU0 INIT before checking sticky I/O failure"
    );
    assert!(
        captured
            .unwrap_err()
            .to_string()
            .contains("unexpected native input completion")
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn public_capture_preserves_a_protocol_failure_without_a_pending_buffer() {
    let (vm, _memory, mut cpus) = graph(1, false);
    cpus[0].complete_io_in(&[0x7c]);
    assert!(cpus[0].io_completion_result().is_err());
    let boundary = vm.checkpoint_boundary().unwrap();
    assert!(
        cpus[0].capture_checkpoint_record(&boundary, None).is_err(),
        "public capture discarded a sticky I/O failure without a pending buffer"
    );
    drop(boundary);
    assert!(cpus[0].get_state().is_err());
    assert!(cpus[0].run_host_slice(Duration::from_millis(10)).is_err());
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn public_state_overlay_cannot_clear_a_sticky_protocol_failure() {
    let (_vm, _memory, mut cpus) = graph(1, false);
    let before = cpus[0].get_state().unwrap();
    cpus[0].complete_io_in(&[0x7c]);
    assert!(cpus[0].io_completion_result().is_err());
    assert!(
        cpus[0].set_state(&before).is_err(),
        "public state overlay cleared the sticky I/O failure"
    );
    assert!(cpus[0].io_completion_result().is_err());
}
