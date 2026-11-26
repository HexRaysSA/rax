//! Cross-CPU terminal state must conserve every pending device transaction.
use super::*;
use crate::vm::runtime::coordinator::ExecutionTurn;
use std::time::Duration;

const SHUTDOWN_PC: u64 = CODE + 0x2000;
const SHUTDOWN_GATE: u64 = CODE + 0x3000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Read,
    ReplyError,
    RetryReply,
    Write,
}

fn public(cpu: &dyn crate::vm::vcpu::VCpu) -> crate::vm::vcpu::Aarch64CpuState {
    let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_unserviced_peer_input_through_file_restart() {
    exercise(Phase::Read, None);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_consumed_peer_input_and_error_through_file_restart() {
    exercise(Phase::ReplyError, None);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_retryable_peer_input_through_file_restart() {
    exercise(Phase::RetryReply, None);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_undispatched_peer_output_through_file_restart() {
    exercise(Phase::Write, None);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_parallel_shutdown_preserves_peer_io_in_both_dispatch_orders() {
    for phase in [Phase::Read, Phase::Write] {
        for peer_first in [true, false] {
            exercise(phase, Some(peer_first));
        }
    }
}

fn exercise(phase: Phase, parallel_peer_first: Option<bool>) {
    let fixture = Fixture::new();
    let mut config = fixture.config(2);
    config.hvf_parallel_vcpus = parallel_peer_first.is_some();
    let mut source = Vmm::new_resume(config).unwrap();
    psci::boot_native_secondaries(&mut source);
    let entry = CODE + 0x1000;
    let pc = if parallel_peer_first.is_some() {
        install_words(&source, entry, &[0x88df_fc83, 0x34ff_ffe3]); // LDAR W3,[X4]; CBZ W3,.-4.
        entry + 8
    } else {
        entry
    };
    let write = phase == Phase::Write;
    install_words(
        &source,
        pc,
        &[
            if write { 0x39000020 } else { 0x39400020 }, // STRB/LDRB W0,[X1].
            0xd2800002 | (0xbeef << 5),                  // MOV X2,#0xbeef.
            0xd503207f,                                  // WFI.
            0x14000000,                                  // B . after the optional wait.
        ],
    );
    source
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0xab, 0xcd]);
    let mut state = public(source.vcpus[1].as_ref());
    state.regs.pc = entry;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = if write { 0xab } else { 0x123456789abcdef0 };
    state.regs.x[1] = UART + if write { 0x30 } else { 0 };
    state.regs.x[2] = 0;
    state.regs.x[4] = SHUTDOWN_GATE;
    source.vcpus[1]
        .set_state(&CpuState::Aarch64(state))
        .unwrap();
    if phase == Phase::Read && parallel_peer_first.is_none() {
        source.take_snapshot(0).unwrap();
    }
    let turns = if let Some(peer_first) = parallel_peer_first {
        Some(collect_parallel_shutdown(&mut source, write, peer_first))
    } else {
        let exit = run_until_exit(source.vcpus[1].as_mut());
        check_peer_exit(&exit, write);
        None
    };
    if matches!(phase, Phase::ReplyError | Phase::RetryReply) {
        let mut data = [0];
        source.mmio_bus.read(UART, &mut data).unwrap();
        assert_eq!(data, [0xab]);
        source
            .vm
            .as_any()
            .downcast_ref::<crate::backend::hvf::HvfArm64Vm>()
            .unwrap()
            .fail_next_gpr_writes(1, 0, 1);
        source.vcpus[1].complete_io_in(&data);
        assert!(
            source.vcpus[1]
                .io_completion_result()
                .unwrap_err()
                .to_string()
                .contains("injected native GPR write failure")
        );
        if phase == Phase::RetryReply {
            assert!(
                source.vcpus[1]
                    .run()
                    .unwrap_err()
                    .to_string()
                    .contains("injected native GPR write failure")
            );
        }
    }
    let mut expected = private_states(&source).remove(1);
    assert_eq!(expected.shutdown, parallel_peer_first.is_some());
    assert!(expected.pending_read.is_some() || expected.pending_write.is_some());
    assert_eq!(
        expected.pending_reply.is_some(),
        matches!(phase, Phase::ReplyError | Phase::RetryReply)
    );
    assert_eq!(
        expected.completion_error.is_some(),
        phase == Phase::ReplyError
    );
    if parallel_peer_first.is_none() {
        let error = source
            .take_snapshot(0)
            .err()
            .expect("legacy capture accepted a pending native ARM64 device transaction");
        assert!(error.to_string().contains("vCPU 1"), "{error}");
        assert!(error.to_string().contains("pending MMIO"), "{error}");
        assert_eq!(private_states(&source)[1], expected);
    }

    // A different CPU requests VM-wide shutdown while the AP is at its I/O frontier.
    if let Some(mut turns) = turns {
        assert!(source.apply_native_round(&mut turns).unwrap());
        assert!(turns.is_empty());
    } else {
        run_shutdown(&mut source);
    }
    expected.shutdown = true;
    assert_eq!(private_states(&source)[1], expected);
    let before = public(source.vcpus[1].as_ref());
    assert!(matches!(source.vcpus[1].run().unwrap(), VcpuExit::Shutdown));
    assert_eq!(public(source.vcpus[1].as_ref()), before);
    // Before the fix this rejects the legal cross-CPU terminal/pending combination.
    let saved = source.take_snapshot_bundle(0).unwrap();
    assert_eq!(private_states(&source)[1], expected);
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    if let Some(path) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).unwrap();
        let name = match parallel_peer_first {
            Some(peer_first) => format!("native-terminal-{phase:?}-peer-first-{peer_first}.rxc"),
            None => format!("native-terminal-{phase:?}.rxc"),
        };
        std::fs::copy(&fixture.checkpoint, path.join(name)).unwrap();
    }
    drop(source);
    std::fs::remove_file(&fixture.kernel).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert!(
        GlobalContext::decode(&loaded.vm_context().unwrap().data)
            .unwrap()
            .power
            .shutdown
    );
    assert_eq!(private_states(&target)[1], expected);
    for _ in 0..2 {
        assert!(matches!(target.vcpus[1].run().unwrap(), VcpuExit::Shutdown));
        assert_eq!(private_states(&target)[1], expected);
    }
    target.vcpus[1].wake();
    if phase == Phase::ReplyError {
        assert!(
            target.vcpus[1]
                .run()
                .unwrap_err()
                .to_string()
                .contains("injected native GPR write failure")
        );
    }
    if phase == Phase::Read {
        assert!(matches!(
            target.vcpus[1].run().unwrap(),
            VcpuExit::MmioRead {
                addr: UART,
                size: 1
            }
        ));
        let mut data = [0];
        target.mmio_bus.read(UART, &mut data).unwrap();
        assert_eq!(data, [0xab]);
        target.vcpus[1].complete_io_in(&data);
        target.vcpus[1].io_completion_result().unwrap();
    } else if write {
        for _ in 0..2 {
            assert!(
                matches!(target.vcpus[1].run().unwrap(), VcpuExit::MmioWrite { addr, data } if addr == UART + 0x30 && data == [0xab])
            );
        }
        target.mmio_bus.write(UART + 0x30, &[0xab]).unwrap();
        target.vcpus[1].complete_io_out().unwrap();
        assert!(target.vcpus[1].complete_io_out().is_err());
    }
    let mut finished = false;
    for _ in 0..32 {
        assert!(matches!(
            native_wait_turn(target.vcpus[1].as_mut()),
            None | Some(VcpuExit::Hlt)
        ));
        let state = public(target.vcpus[1].as_ref());
        if state.regs.pc == pc + 12 {
            assert_eq!(state.regs.x[0], 0xab);
            assert_eq!(state.regs.x[2], 0xbeef);
            finished = true;
            break;
        }
    }
    assert!(finished, "{phase:?}: no continuation after explicit wake");
    target.vcpus[1].io_completion_result().unwrap();
    let after = private_states(&target).remove(1);
    assert!(
        after.pending_read.is_none()
            && after.pending_write.is_none()
            && after.pending_reply.is_none()
            && after.completion_error.is_none()
    );
    let mut data = [0];
    target.mmio_bus.read(UART, &mut data).unwrap();
    assert_eq!(
        data,
        [if write { 0xab } else { 0xcd }],
        "{phase:?}: duplicated device input consumption"
    );
}

fn install_words(vm: &Vmm, pc: u64, words: &[u32]) {
    let code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    vm.guest_mem
        .memory()
        .write_slice(&code, GuestAddress(pc))
        .unwrap();
    publish_native_code(&vm.guest_mem, pc, code.len());
}

fn run_until_exit(cpu: &mut dyn crate::vm::vcpu::VCpu) -> VcpuExit {
    for _ in 0..32 {
        let exit = cpu.run().unwrap();
        if !matches!(exit, VcpuExit::Hlt) {
            return exit;
        }
    }
    panic!("no native exit beyond guest wait hints");
}

fn check_peer_exit(exit: &VcpuExit, write: bool) {
    match exit {
        VcpuExit::MmioRead {
            addr: UART,
            size: 1,
        } if !write => (),
        VcpuExit::MmioWrite { addr, data } if write && *addr == UART + 0x30 => {
            assert_eq!(data, &[0xab]);
        }
        other => panic!("unexpected peer I/O exit: {other:?}"),
    }
}

fn prepare_shutdown(vm: &mut Vmm, words: &[u32]) {
    install_words(vm, SHUTDOWN_PC, words);
    let bsp = &mut vm.vcpus[0];
    let mut state = public(bsp.as_ref());
    state.regs.pc = SHUTDOWN_PC;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = 0x84000008;
    state.regs.x[1] = SHUTDOWN_GATE;
    bsp.set_state(&CpuState::Aarch64(state)).unwrap();
}

fn run_shutdown(vm: &mut Vmm) {
    prepare_shutdown(vm, &[0xd4000002]); // HVC #0.
    let exit = run_until_exit(vm.vcpus[0].as_mut());
    assert!(matches!(exit, VcpuExit::Shutdown), "{exit:?}");
}

fn collect_parallel_shutdown(vm: &mut Vmm, write: bool, peer_first: bool) -> Vec<ExecutionTurn> {
    vm.guest_mem
        .memory()
        .store(0u64, GuestAddress(SHUTDOWN_GATE), Ordering::Relaxed)
        .unwrap();
    prepare_shutdown(
        vm,
        &[
            0x5280_0022, // MOV W2,#1
            0x889f_fc22, // STLR W2,[X1]
            0x9100_1021, // ADD X1,X1,#4
            0x88df_fc22, // LDAR W2,[X1]
            0x34ff_ffe2, // CBZ W2,.-4
            0xd400_0002, // HVC #0
        ],
    );
    // The peer must see the BSP executing guest code. The BSP cannot shut
    // down until the peer's real SDK MMIO exit has been collected.
    for cpu in &mut vm.vcpus {
        cpu.post_host_slice(Duration::from_secs(2)).unwrap();
    }
    let peer = vm.vcpus[1].collect_host_slice();
    vm.guest_mem
        .memory()
        .store(1u32, GuestAddress(SHUTDOWN_GATE + 4), Ordering::Release)
        .unwrap();
    let terminal = vm.vcpus[0].collect_host_slice().unwrap().unwrap();
    let peer = peer.unwrap().unwrap();
    assert!(matches!(terminal, VcpuExit::Shutdown), "{terminal:?}");
    check_peer_exit(&peer, write);
    let mut turns = vec![
        ExecutionTurn {
            cpu_index: 0,
            exit: terminal,
            #[cfg(feature = "debug")]
            debug_step_completed: false,
        },
        ExecutionTurn {
            cpu_index: 1,
            exit: peer,
            #[cfg(feature = "debug")]
            debug_step_completed: false,
        },
    ];
    if peer_first {
        turns.swap(0, 1);
    }
    turns
}
