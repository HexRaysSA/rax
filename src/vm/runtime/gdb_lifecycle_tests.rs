//! Production listener ownership, including blocked transport/owner boundaries.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    vm: Option<Vmm>,
    kernel: PathBuf,
    address: SocketAddr,
}

impl Fixture {
    fn new(wait: bool, address: SocketAddr) -> Self {
        Self::with_cpus(wait, address, 1)
    }

    fn with_cpus(wait: bool, address: SocketAddr, count: u8) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-gdb-lifetime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                vcpus: Some(count),
                gdb_port: Some(address.port()),
                wait_gdb: wait,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(65536);
        config.pci_devices = false;
        let vm = Vmm::new_resume(config).unwrap();
        assert!(TcpListener::bind(address).is_err());
        Self {
            vm: Some(vm),
            kernel,
            address,
        }
    }

    fn receive(&self) -> GdbCommand {
        self.vm
            .as_ref()
            .unwrap()
            .gdb_channels
            .as_ref()
            .unwrap()
            .cmd_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
    }

    fn handle(&mut self, command: GdbCommand) {
        self.vm
            .as_mut()
            .unwrap()
            .handle_gdb_command(command)
            .unwrap();
    }

    fn destroy(&mut self) {
        let start = Instant::now();
        drop(self.vm.take());
        assert!(start.elapsed() < Duration::from_secs(2));
        let listener = TcpListener::bind(self.address)
            .expect("destroyed VMM must release its production debugger listener");
        drop(listener);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.vm.take());
        let _ = std::fs::remove_file(&self.kernel);
    }
}

fn unused_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn disconnected(stream: &mut TcpStream) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = 0;
    loop {
        let mut bytes = [0; 128];
        match stream.read(&mut bytes) {
            Ok(0) => return,
            // A pending command may receive a terminal error before shutdown.
            Ok(count) => received += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            result => panic!("destroyed owner retained a live transport: {result:?}"),
        }
        assert!(received < 4096 && Instant::now() < deadline);
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn packet(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        if let Some((value, _)) = gdb::protocol::parse_packet(&bytes) {
            stream.write_all(b"+").unwrap();
            return value;
        }
        assert!(bytes.len() < 4096);
    }
}

#[test]
fn dropping_an_unconnected_vmm_releases_its_port_in_both_wait_modes() {
    for wait in [false, true] {
        let address = unused_address();
        for _ in 0..3 {
            Fixture::new(wait, address).destroy();
        }
    }
}

#[test]
fn destruction_cancels_a_client_waiting_for_the_attach_barrier() {
    let mut fixture = Fixture::new(true, unused_address());
    let mut stream = connect(fixture.address);
    assert!(matches!(fixture.receive(), GdbCommand::Attach));
    fixture.destroy();
    disconnected(&mut stream);
}

#[test]
fn destruction_closes_an_attached_idle_client_and_releases_the_listener() {
    let mut fixture = Fixture::new(true, unused_address());
    let mut stream = connect(fixture.address);
    let attach = fixture.receive();
    assert!(matches!(attach, GdbCommand::Attach));
    fixture.handle(attach);
    gdb::protocol::send_packet(&mut stream, "qC").unwrap();
    let query = fixture.receive();
    assert!(matches!(query, GdbCommand::CurrentThread));
    fixture.handle(query);
    assert_eq!(packet(&mut stream), "QC1");
    fixture.destroy();
    disconnected(&mut stream);
}

#[test]
fn destruction_cancels_an_outstanding_continue_without_a_guest_entry() {
    let mut fixture = Fixture::new(true, unused_address());
    let mut stream = connect(fixture.address);
    fixture.handle(fixture.receive());
    gdb::protocol::send_packet(&mut stream, "c").unwrap();
    assert!(matches!(fixture.receive(), GdbCommand::Continue));
    let mut ack = [0];
    stream.read_exact(&mut ack).unwrap();
    assert_eq!(ack, *b"+");
    fixture.destroy();
    disconnected(&mut stream);
}

#[path = "gdb_restore_tests.rs"]
mod restore;

#[path = "gdb_transport_tests.rs"]
mod transport;

#[path = "gdb_restore_admission_tests.rs"]
mod restore_admission;
