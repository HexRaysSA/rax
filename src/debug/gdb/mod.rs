//! GDB Remote Serial Protocol server for debugging.
//!
//! This module implements a GDB RSP server that runs in a separate thread,
//! communicating with the VMM via channels.

mod commands;
mod lifecycle;
mod queries;
mod thread_commands;
pub mod threads;
pub(crate) mod x86_registers;
pub use threads::{Resume, ResumeAction, ThreadId};
pub mod protocol;
pub mod registers;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use tracing::{debug, error, info, trace, warn};

pub use commands::handle_command;
pub(crate) use lifecycle::{OwnedServer, spawn_owned_server};
pub use protocol::{parse_packet, send_packet, send_stop_reply};
pub use registers::{pack_registers, unpack_registers};

/// Commands sent from GDB server to VMM.
#[derive(Debug, Clone)]
pub enum GdbCommand {
    /// QEMU-compatible explicit physical/translated debugger memory mode.
    MemoryMode(Option<bool>),
    /// Begin a new all-stop connection.
    Attach,
    /// Resume after the controlling connection closes.
    ConnectionClosed,
    /// Select the CPU for register/memory or legacy execution operations.
    SelectThread { execution: bool, thread: ThreadId },
    /// Enumerate configured virtual CPU threads.
    Threads,
    /// Query the selected CPU thread.
    CurrentThread,
    /// Query a CPU's presence or its descriptive label.
    ThreadInfo { thread: ThreadId, describe: bool },
    /// Apply an ordered, fully validated set of per-CPU actions.
    Resume(Vec<Resume>),
    /// Write one register of the selected CPU.
    WriteRegister { index: usize, data: Vec<u8> },

    /// Continue execution.
    Continue,
    /// Single step one instruction.
    Step,
    /// Interrupt execution (Ctrl+C from debugger).
    Interrupt,
    /// Read all registers.
    ReadRegisters,
    /// Write all registers.
    WriteRegisters(Vec<u8>),
    /// Read memory.
    ReadMemory { addr: u64, len: usize },
    /// Write memory.
    WriteMemory { addr: u64, data: Vec<u8> },
    /// Set software breakpoint.
    SetBreakpoint { addr: u64 },
    /// Remove software breakpoint.
    RemoveBreakpoint { addr: u64 },
    /// Query halt reason.
    QueryHaltReason,
    /// Detach from target.
    Detach,
    /// Kill target.
    Kill,
}

/// Responses sent from VMM to GDB server.
#[derive(Debug, Clone)]
pub enum GdbResponse {
    /// Owner-side new-connection barrier.
    Attached,
    /// Thread-bearing all-stop event (RSP IDs are one-based).
    ThreadStop { signal: u8, index: usize },
    /// Generic query data.
    Text(String),
    /// Guest exit status.
    Exited(u8),

    /// Command succeeded.
    Ok,
    /// Error with code.
    Error(u8),
    /// Register data (hex-encoded).
    Registers(String),
    /// Memory data (hex-encoded).
    Memory(String),
    /// Stop reply with signal number (5 = SIGTRAP).
    StopReply(u8),
    /// Target stopped.
    Stopped,
    /// Target detached.
    Detached,
}

/// Channel pair for communication between GDB server and VMM.
pub struct GdbChannels {
    /// Send commands to VMM.
    pub cmd_tx: Sender<GdbCommand>,
    /// Receive responses from VMM.
    pub resp_rx: Receiver<GdbResponse>,
}

/// VMM-side channel endpoints.
pub struct VmmGdbChannels {
    /// Receive commands from GDB server.
    pub cmd_rx: Receiver<GdbCommand>,
    /// Send responses to GDB server.
    pub resp_tx: Sender<GdbResponse>,
}

/// Create a pair of channel endpoints for GDB/VMM communication.
pub fn create_channels() -> (GdbChannels, VmmGdbChannels) {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (resp_tx, resp_rx) = mpsc::channel();

    (
        GdbChannels { cmd_tx, resp_rx },
        VmmGdbChannels { cmd_rx, resp_tx },
    )
}

/// GDB Remote Serial Protocol server.
pub struct GdbServer {
    listener: TcpListener,
    channels: GdbChannels,
    /// Whether we're waiting for initial connection.
    wait_for_connection: bool,
}

impl GdbServer {
    /// Create a new GDB server listening on the specified port.
    pub fn new(port: u16, channels: GdbChannels, wait: bool) -> std::io::Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        info!(port = port, "GDB server listening");

        Ok(GdbServer {
            listener,
            channels,
            wait_for_connection: wait,
        })
    }

    /// Run the GDB server (blocking).
    pub fn run(mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    info!(addr = %addr, "GDB client connected");
                    if let Err(e) = self.handle_client(stream) {
                        error!(error = %e, "GDB client error");
                    }
                    info!("GDB client disconnected");
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection");
                    break;
                }
            }
        }
    }

    /// Handle a single GDB client connection.
    fn handle_client(&mut self, stream: TcpStream) -> std::io::Result<()> {
        let result = self.client_loop(stream);
        let _ = self.channels.cmd_tx.send(GdbCommand::ConnectionClosed);
        result
    }

    fn client_loop(&mut self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_nodelay(true)?;
        self.channels
            .cmd_tx
            .send(GdbCommand::Attach)
            .map_err(std::io::Error::other)?;
        loop {
            match self
                .channels
                .resp_rx
                .recv_timeout(std::time::Duration::from_secs(5))
            {
                Ok(GdbResponse::Attached) => break,
                // The owner processes this barrier after all prior-connection
                // commands, so earlier asynchronous events cannot leak across it.
                Ok(_) => continue,
                Err(error) => return Err(std::io::Error::other(error)),
            }
        }

        let mut buf = [0u8; 4096];
        let mut pending = Vec::new();

        loop {
            // Read data from client
            let n = match stream.read(&mut buf) {
                Ok(0) => return Ok(()), // Client disconnected
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };

            pending.extend_from_slice(&buf[..n]);

            // Log raw data received
            let raw_display = String::from_utf8_lossy(&buf[..n]);
            trace!(bytes = n, raw = %raw_display, "GDB RX raw");

            // Process packets
            while let Some((packet, consumed)) = protocol::parse_packet(&pending) {
                pending.drain(..consumed);

                // Send ACK
                stream.write_all(b"+")?;
                stream.flush()?;
                trace!("GDB TX: +");

                debug!(packet = %packet, "GDB packet received");

                // Handle the packet
                match self.handle_packet(&packet, &mut stream) {
                    Ok(true) => {}              // Continue
                    Ok(false) => return Ok(()), // Detach/kill
                    Err(e) => {
                        error!(error = %e, "Error handling packet");
                        protocol::send_packet(&mut stream, "E01")?;
                    }
                }
            }

            // Handle ACK/NAK
            if !pending.is_empty() && (pending[0] == b'+' || pending[0] == b'-') {
                if pending[0] == b'-' {
                    warn!("Received NAK from GDB");
                }
                pending.remove(0);
            }

            // Handle interrupt (Ctrl+C)
            if !pending.is_empty() && pending[0] == 0x03 {
                pending.remove(0);
                debug!("Received interrupt");
                let reply = thread_commands::request(&self.channels, GdbCommand::Interrupt)?;
                thread_commands::send_response(&mut stream, reply)?;
            }
        }
    }

    /// Handle a single GDB packet. Returns Ok(true) to continue, Ok(false) to disconnect.
    fn handle_packet(&mut self, packet: &str, stream: &mut TcpStream) -> std::io::Result<bool> {
        commands::handle_command(packet, stream, &self.channels)
    }

    /// Wait for initial GDB connection (blocks until connected).
    pub fn wait_connection(&self) -> std::io::Result<()> {
        if self.wait_for_connection {
            info!("Waiting for GDB connection...");
            // Set listener to blocking mode temporarily
            self.listener.set_nonblocking(false)?;
        }
        Ok(())
    }
}

/// Spawn the GDB server in a background thread.
pub fn spawn_server(
    port: u16,
    channels: GdbChannels,
    wait: bool,
) -> std::io::Result<JoinHandle<()>> {
    let server = GdbServer::new(port, channels, wait)?;

    if wait {
        server.wait_connection()?;
    }

    let handle = thread::Builder::new()
        .name("gdb-server".to_string())
        .spawn(move || {
            server.run();
        })?;

    Ok(handle)
}

#[cfg(test)]
pub(crate) mod test_support;
