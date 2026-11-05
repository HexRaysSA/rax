//! Terminal native transfers survive source destruction without device replay.
use super::*;
use crate::backend::kvm::io;
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState};

fn prepare_terminal_frontiers(memory: &GuestMemoryWrapper, cpus: &mut [Box<dyn VCpu>]) {
    memory
        .memory()
        .write_slice(&[0, 0x20, 0x34, 0x12, 0x78, 0x56], GuestAddress(0x3000))
        .unwrap();
    for (id, cpu) in cpus.iter_mut().enumerate() {
        let mut program = match id {
            0 => vec![0xf3, 0x6f],                // REP OUTSW, three elements.
            1 => vec![0xec],                      // IN AL,DX.
            2 => vec![0x67, 0xa0, 0, 0, 0, 0xf0], // MOV AL,[0xf0000000].
            _ => vec![0x67, 0xc6, 0x05, 0, 0, 0, 0xf0, 0x80],
        };
        program.extend_from_slice(&[0xc6, 0x06, 0, 0x50, 0xa5, 0xf4]);
        let pc = 0x1000 + id as u64 * 0x100;
        memory
            .memory()
            .write_slice(&program, GuestAddress(pc))
            .unwrap();
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rip = pc;
        state.regs.rcx = 3;
        state.regs.rsi = 0x3000;
        state.regs.rdx = if id == 0 { 0x604 } else { 0x1234 };
        state.regs.rax = 0x80;
        for segment in [&mut state.sregs.ds, &mut state.sregs.es] {
            segment.base = 0;
            segment.selector = 0;
            segment.limit = u32::MAX;
            segment.g = true;
        }
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn source_free_poweroff_preserves_rep_progress_and_every_peers_unserviced_transfer() {
    for irqchip in [false, true] {
        for count in [1, 2, 4] {
            for replied in [false, true] {
                let (source, memory, mut cpus) = graph(count, irqchip);
                prepare_terminal_frontiers(&memory, &mut cpus);
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    let event = exit(&mut **cpu);
                    assert!(match (id, event) {
                        (0, VcpuExit::IoOut { port: 0x604, data }) => data == [0, 0x20],
                        (
                            1,
                            VcpuExit::IoIn {
                                port: 0x1234,
                                size: 1,
                            },
                        ) => true,
                        (
                            2,
                            VcpuExit::MmioRead {
                                addr: 0xf000_0000,
                                size: 1,
                            },
                        ) => true,
                        (
                            3,
                            VcpuExit::MmioWrite {
                                addr: 0xf000_0000,
                                data,
                            },
                        ) => data == [0x80],
                        _ => false,
                    });
                    if replied && matches!(id, 1 | 2) {
                        cpu.complete_io_in(&[0x7c]);
                    }
                }
                let mut calls = 0;
                assert_eq!(cpus[0].settle_checkpoint_io(&mut |event| {
                    assert!(matches!(event, VcpuExit::IoOut { port: 0x604, data } if data == [0, 0x20]));
                    calls += 1;
                    Ok(CheckpointIoReply::PowerOff)
                }).unwrap(), CheckpointIoState::Deferred);
                assert_eq!(calls, 1);
                let boundary = source.checkpoint_boundary().unwrap();
                let handles = native(&*source).checkpoint_cpu_handles(&boundary).unwrap();
                let native_count = {
                    let mut core = handles[0].lock().unwrap();
                    let run = core.vcpu_fd.get_kvm_run();
                    assert_eq!(run.exit_reason, kvm_bindings::KVM_EXIT_IO);
                    // SAFETY: KVM_RUN returned this IO descriptor and no new
                    // entry occurred. The stopped CPU guard owns its live run
                    // mapping; the checked tag selects this integer-only copy.
                    let descriptor = unsafe { run.__bindgen_anon_1.io };
                    assert_eq!((descriptor.port, descriptor.size), (0x604, 2));
                    assert!((1..=3).contains(&descriptor.count));
                    descriptor.count
                };
                let before: Vec<_> = handles
                    .iter()
                    .map(|core| core.lock().unwrap().vcpu_fd.get_regs().unwrap())
                    .collect();
                let image = native(&*source).capture_native_banks(&boundary).unwrap();
                assert!(image.powered_off);
                let value = serde_json::to_value(&image).unwrap();
                assert_eq!(value["terminal"][0]["acknowledged"], 2);
                assert_eq!(value["terminal"][0]["count"], native_count);
                assert_eq!(
                    value["terminal"][0]["data"],
                    serde_json::json!(
                        [0, 0x20, 0x34, 0x12, 0x78, 0x56][..native_count as usize * 2]
                    )
                );
                for (saved, before) in image.cpus.iter().zip(&before) {
                    let (public, _) = saved.public().unwrap();
                    assert_eq!(
                        (public.regs.rip, public.regs.rcx, public.regs.rsi),
                        (before.rip, before.rcx, before.rsi),
                    );
                }
                let json = serde_json::to_vec(&image).unwrap();
                let binary = crate::codec::serialize(&image).unwrap();
                drop(boundary);
                drop(handles);
                drop(cpus);
                drop(source);
                drop(memory);
                for image in [
                    serde_json::from_slice::<Image>(&json).unwrap(),
                    crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
                ] {
                    let (target, memory, mut cpus) = graph(count, irqchip);
                    let boundary = target.checkpoint_boundary().unwrap();
                    let active = native(&*target).capture_native_banks(&boundary).unwrap();
                    image.restore_stored(native(&*target), &boundary).unwrap();
                    let recaptured = native(&*target).capture_native_banks(&boundary).unwrap();
                    assert_eq!(recaptured.terminal, image.terminal);
                    assert_eq!(recaptured.deferred, image.deferred);
                    assert!(recaptured.powered_off);
                    let handles = native(&*target).checkpoint_cpu_handles(&boundary).unwrap();
                    for core in lock_cpus(native(&*target), &handles).unwrap() {
                        assert!(core.pending_io_in.is_none());
                        assert!(!core.native_io_unsettled);
                    }
                    drop(boundary);
                    for cpu in &mut cpus {
                        for _ in 0..2 {
                            assert!(matches!(
                                cpu.run_host_slice(Duration::from_millis(10)).unwrap(),
                                Some(VcpuExit::Shutdown)
                            ));
                            assert_eq!(
                                cpu.settle_checkpoint_io(&mut |_| {
                                    panic!("restored powered-off CPU replayed a device effect")
                                })
                                .unwrap(),
                                CheckpointIoState::Deferred
                            );
                        }
                    }
                    assert_eq!(
                        memory
                            .memory()
                            .read_obj::<u8>(GuestAddress(0x5000))
                            .unwrap(),
                        0
                    );
                    // This destination has only restored logical records;
                    // no kernel I/O was issued on its fresh native CPUs.
                    let boundary = target.checkpoint_boundary().unwrap();
                    active.restore_stored(native(&*target), &boundary).unwrap();
                    drop(boundary);
                    for (id, cpu) in cpus.iter_mut().enumerate() {
                        assert!(
                            matches!(exit(&mut **cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8])
                        );
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn terminal_metadata_and_active_callback_reject_before_native_bank_changes() {
    let (vm, _memory, _cpus) = graph(2, true);
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let before = vm.capture_native_banks(&boundary).unwrap();
    let handles = vm.checkpoint_cpu_handles(&boundary).unwrap();
    handles[1].lock().unwrap().servicing_io = true;
    assert!(
        vm.capture_native_banks(&boundary)
            .unwrap_err()
            .to_string()
            .contains("callback")
    );
    handles[1].lock().unwrap().servicing_io = false;
    let mut short = before.clone();
    short.terminal.pop();
    assert!(short.restore_stored(vm, &boundary).is_err());
    let mut pending = io::State::default();
    pending
        .begin_input(
            io::Input::Port {
                port: 1,
                size: 1,
                count: 1,
            },
            1,
        )
        .unwrap();
    let mut active = before.clone();
    active.terminal[1] = pending.capture_terminal().unwrap();
    assert!(
        active
            .restore_stored(vm, &boundary)
            .unwrap_err()
            .to_string()
            .contains("power-off")
    );
    let after = vm.capture_native_banks(&boundary).unwrap();
    assert_eq!(stored_cpu_banks(&before), stored_cpu_banks(&after));
    assert!(!after.powered_off);
    assert_eq!(after.terminal, before.terminal);
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn idle_poweroff_flag_is_replaced_in_both_directions_without_native_entry() {
    let (vm, _memory, _cpus) = graph(1, false);
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let active = vm.capture_native_banks(&boundary).unwrap();
    vm.memory.powered_off.store(true, Ordering::Release);
    let stopped = vm.capture_native_banks(&boundary).unwrap();
    active.restore_stored(vm, &boundary).unwrap();
    assert!(!vm.memory.powered_off.load(Ordering::Acquire));
    stopped.restore_stored(vm, &boundary).unwrap();
    assert!(vm.memory.powered_off.load(Ordering::Acquire));
}
