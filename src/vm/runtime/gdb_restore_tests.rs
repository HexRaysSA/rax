//! Current frontend ownership survives actual guest checkpoint file import.
use super::*;
use crate::vm::snapshot::SnapshotBundle;

struct Archive(PathBuf);
impl Drop for Archive {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn exchange(fixture: &mut Fixture, stream: &mut TcpStream, request: &str) -> String {
    gdb::protocol::send_packet(stream, request).unwrap();
    let command = fixture.receive();
    fixture.handle(command);
    packet(stream)
}

#[test]
fn file_restore_preserves_the_current_session_and_rebinds_imported_cpu_controls() {
    for count in [2, 4] {
        restore_current_session(count);
    }
}

fn restore_current_session(count: u8) {
    let mut source = super::super::execution_tests::Fixture::new(count);
    source.write(super::super::execution_tests::BSP, &[0x40, 0xf4]);
    let CpuState::X86_64(mut state) = source.vm.vcpus[0].get_state().unwrap() else {
        panic!("x86 fixture");
    };
    state.regs.rax = 100;
    source.vm.vcpus[0]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    assert!(source.vm.debug_breakpoint(0x8800, true).unwrap());
    let saved = source.vm.take_snapshot_bundle(0).unwrap();

    let mut target = Fixture::with_cpus(true, unused_address(), count);
    let archive = Archive(target.kernel.with_extension("rxc"));
    saved.save(&archive.0).unwrap();
    let saved = SnapshotBundle::load(&archive.0).unwrap();

    let mut stream = connect(target.address);
    let attach = target.receive();
    assert!(matches!(attach, GdbCommand::Attach));
    target.handle(attach);
    assert_eq!(exchange(&mut target, &mut stream, "Hg2"), "OK");
    assert_eq!(exchange(&mut target, &mut stream, "Hc1"), "OK");
    assert_eq!(
        exchange(&mut target, &mut stream, "Qqemu.PhyMemMode:1"),
        "OK"
    );
    assert_eq!(exchange(&mut target, &mut stream, "Z0,8000,1"), "OK");
    gdb::protocol::send_packet(&mut stream, "s").unwrap();
    let step = target.receive();
    assert!(matches!(step, GdbCommand::Step));
    target.handle(step);
    let mut ack = [0];
    stream.read_exact(&mut ack).unwrap();
    assert_eq!(ack, *b"+");

    let vm = target.vm.as_mut().unwrap();
    let controls: Vec<_> = vm.vcpus.iter().map(|cpu| cpu.debugger_controls()).collect();
    assert!(controls[0].as_ref().unwrap().single_step);
    let session = format!("{:?}", vm.debugger);
    let breakpoints = vm.gdb_breakpoints.clone();
    let stopped = vm.gdb_stopped;
    let single_step = vm.gdb_single_step;
    vm.restore_snapshot_bundle(&saved).unwrap();
    assert_eq!(format!("{:?}", vm.debugger), session);
    assert_eq!(vm.gdb_breakpoints, breakpoints);
    assert_eq!(vm.gdb_stopped, stopped);
    assert_eq!(vm.gdb_single_step, single_step);
    assert_eq!(
        vm.vcpus
            .iter()
            .map(|cpu| cpu.debugger_controls())
            .collect::<Vec<_>>(),
        controls,
        "imported guest state must bind to the current frontend's CPU controls"
    );
    let retired = vm.coordinator.retired;
    let turn = vm.execute_turn().unwrap().unwrap();
    assert_eq!(turn.cpu_index, 0);
    assert!(turn.debug_step_completed);
    assert_eq!(vm.coordinator.retired, retired + 1);
    assert!(matches!(turn.exit, VcpuExit::GdbStep));
    let CpuState::X86_64(state) = vm.vcpus[0].get_state().unwrap() else {
        panic!("x86 restored CPU");
    };
    assert_eq!(state.regs.rax, 101);
    vm.stop_debugger(turn.cpu_index, 5).unwrap();
    vm.gdb_channels
        .as_ref()
        .unwrap()
        .resp_tx
        .send(GdbResponse::ThreadStop {
            signal: 5,
            index: 0,
        })
        .unwrap();
    let reply = packet(&mut stream);
    assert!(
        reply.starts_with("T05") && reply.contains("thread:1;"),
        "{reply}"
    );
    target.destroy();
    disconnected(&mut stream);
}
