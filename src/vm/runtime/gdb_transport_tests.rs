//! Malformed wire text and loss of the sole production controller endpoint.
use super::*;
use std::process::{Command, Stdio};
use std::sync::Arc;

#[test]
fn malformed_unicode_packets_are_rejected_without_losing_the_connection() {
    let mut fixture = Fixture::new(true, unused_address());
    let mut stream = connect(fixture.address);
    fixture.handle(fixture.receive());
    let state =
        crate::codec::serialize(&fixture.vm.as_ref().unwrap().vcpus[0].get_state().unwrap())
            .unwrap();
    for (request, expected) in [
        ("G💩", "E01"),
        ("M0,2:💩", "E01"),
        ("M0,1:+f", "E01"),
        ("💩", ""),
    ] {
        gdb::protocol::send_packet(&mut stream, request).unwrap();
        assert_eq!(packet(&mut stream), expected, "{request}");
        assert!(matches!(
            fixture
                .vm
                .as_ref()
                .unwrap()
                .gdb_channels
                .as_ref()
                .unwrap()
                .cmd_rx
                .try_recv(),
            Err(TryRecvError::Empty)
        ));
        gdb::protocol::send_packet(&mut stream, "qC").unwrap();
        let query = fixture.receive();
        assert!(matches!(query, GdbCommand::CurrentThread));
        fixture.handle(query);
        assert_eq!(packet(&mut stream), "QC1");
    }
    assert_eq!(
        crate::codec::serialize(&fixture.vm.as_ref().unwrap().vcpus[0].get_state().unwrap(),)
            .unwrap(),
        state
    );
    fixture.destroy();
    disconnected(&mut stream);
}

struct ShutdownCpu {
    state: CpuState,
    entries: Arc<AtomicU64>,
}

impl VCpu for ShutdownCpu {
    fn id(&self) -> u32 {
        0
    }
    fn run(&mut self) -> Result<VcpuExit> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        Ok(VcpuExit::Shutdown)
    }
    fn get_state(&self) -> Result<CpuState> {
        Ok(self.state.clone())
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }
    fn complete_io_in(&mut self, _data: &[u8]) {}
}

#[test]
#[ignore = "Executed by the bounded production-owner parent test"]
fn disconnected_owner_child() {
    let mut fixture = super::super::execution_tests::Fixture::new(1);
    let entries = Arc::new(AtomicU64::new(0));
    fixture.vm.vcpus[0] = Box::new(ShutdownCpu {
        state: fixture.vm.vcpus[0].get_state().unwrap(),
        entries: entries.clone(),
    });
    let (client, owner) = gdb::create_channels();
    fixture.vm.gdb_channels = Some(owner);
    fixture.vm.handle_gdb_command(GdbCommand::Attach).unwrap();
    assert!(matches!(
        client.resp_rx.recv().unwrap(),
        GdbResponse::Attached
    ));
    assert!(fixture.vm.gdb_stopped);
    drop(client);
    fixture.vm.run().unwrap();
    assert_eq!(entries.load(Ordering::SeqCst), 1);
    println!("RAX_GDB_DISCONNECTED_OWNER_OK");
}

#[test]
fn losing_the_controller_releases_its_stop_mask_before_another_entry() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "vm::runtime::gdb_lifecycle_tests::transport::disconnected_owner_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !timed_out && output.status.success() && stdout.contains("RAX_GDB_DISCONNECTED_OWNER_OK"),
        "timeout={timed_out}, stdout={stdout}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn retrying_a_terminal_debugger_owner_returns_error_before_waiting_for_commands() {
    let (client, owner) = gdb::create_channels();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut fixture = super::super::execution_tests::Fixture::new(1);
        fixture.vm.gdb_channels = Some(owner);
        fixture.vm.gdb_stopped = true;
        fixture.vm.debugger.failure = Some("scripted terminal debugger failure".into());
        ready_tx.send(()).unwrap();
        let result = fixture.vm.run();
        result_tx
            .send((result.is_err(), fixture.vm.coordinator.retired))
            .unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let result = match result_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => Some(result),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // Release the known-bad baseline worker without leaving a thread
            // behind. The fixed owner returns before this cleanup is needed.
            let _ = client.cmd_tx.send(GdbCommand::Kill);
            result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            None
        }
        Err(error) => panic!("owner result: {error}"),
    };
    worker.join().unwrap();
    assert_eq!(result, Some((true, 0)));
}
