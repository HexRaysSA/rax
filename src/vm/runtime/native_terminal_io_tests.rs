//! Cross-CPU terminal state must conserve every pending device transaction.
use super::*;

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
    exercise(Phase::Read);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_consumed_peer_input_and_error_through_file_restart() {
    exercise(Phase::ReplyError);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_retryable_peer_input_through_file_restart() {
    exercise(Phase::RetryReply);
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_shutdown_conserves_undispatched_peer_output_through_file_restart() {
    exercise(Phase::Write);
}

fn exercise(phase: Phase) {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut source);
    let pc = CODE + 0x1000;
    let write = phase == Phase::Write;
    for (index, word) in [
        if write { 0x39000020u32 } else { 0x39400020 }, // STRB/LDRB W0,[X1].
        0xd2800002 | (0xbeef << 5),                     // MOV X2,#0xbeef.
        0xd503207f,                                     // WFI.
    ]
    .into_iter()
    .enumerate()
    {
        source
            .guest_mem
            .memory()
            .write_obj(word.to_le(), GuestAddress(pc + index as u64 * 4))
            .unwrap();
    }
    source
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0xab, 0xcd]);
    let mut state = public(source.vcpus[1].as_ref());
    state.regs.pc = pc;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = if write { 0xab } else { 0x123456789abcdef0 };
    state.regs.x[1] = UART + if write { 0x30 } else { 0 };
    state.regs.x[2] = 0;
    source.vcpus[1]
        .set_state(&CpuState::Aarch64(state))
        .unwrap();
    let mut pending = false;
    for _ in 0..32 {
        match source.vcpus[1].run().unwrap() {
            VcpuExit::MmioRead {
                addr: UART,
                size: 1,
            } if !write => {
                pending = true;
                break;
            }
            VcpuExit::MmioWrite { addr, data } if write && addr == UART + 0x30 => {
                assert_eq!(data, [0xab]);
                pending = true;
                break;
            }
            VcpuExit::Hlt => (),
            other => panic!("{phase:?}: unexpected I/O frontier {other:?}"),
        }
    }
    assert!(pending, "{phase:?}: no pending transaction");
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
    assert!(expected.pending_read.is_some() || expected.pending_write.is_some());
    assert_eq!(
        expected.pending_reply.is_some(),
        matches!(phase, Phase::ReplyError | Phase::RetryReply)
    );
    assert_eq!(
        expected.completion_error.is_some(),
        phase == Phase::ReplyError
    );

    // A different CPU requests VM-wide shutdown while the AP is at its I/O frontier.
    let shutdown_pc = CODE + 0x2000;
    source
        .guest_mem
        .memory()
        .write_obj(0xd4000002u32.to_le(), GuestAddress(shutdown_pc))
        .unwrap();
    let mut bsp = public(source.vcpus[0].as_ref());
    bsp.regs.pc = shutdown_pc;
    bsp.regs.x[0] = 0x84000008;
    source.vcpus[0].set_state(&CpuState::Aarch64(bsp)).unwrap();
    let mut shutdown = false;
    for _ in 0..32 {
        match source.vcpus[0].run().unwrap() {
            VcpuExit::Shutdown => {
                shutdown = true;
                break;
            }
            VcpuExit::Hlt => (),
            other => panic!("SYSTEM_OFF returned {other:?}"),
        }
    }
    assert!(shutdown);
    let before = public(source.vcpus[1].as_ref());
    assert!(matches!(source.vcpus[1].run().unwrap(), VcpuExit::Shutdown));
    assert_eq!(public(source.vcpus[1].as_ref()), before);
    expected.shutdown = true;
    // Before the fix this rejects the legal cross-CPU terminal/pending combination.
    let saved = source.take_snapshot_bundle(0).unwrap();
    assert_eq!(private_states(&source)[1], expected);
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    if let Some(path) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::copy(
            &fixture.checkpoint,
            path.join(format!("native-terminal-{phase:?}.rxc")),
        )
        .unwrap();
    }
    drop(source);
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
        assert!(matches!(target.vcpus[1].run().unwrap(), VcpuExit::Hlt));
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
