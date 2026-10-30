//! VMM-owned listener and active socket lifetime; legacy spawn API stays stable.
use super::{GdbChannels, GdbServer};
use std::net::{Shutdown, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Default)]
struct Control {
    stopped: AtomicBool,
    active: Mutex<Option<TcpStream>>,
}

/// Release the retained socket even if command handling unwinds.
struct ActiveConnection<'a>(&'a Control);

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        let stream = self
            .0
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Close outside the mutex, as in the owning handle's shutdown path.
        drop(stream);
    }
}

/// The owning VMM closes its channel endpoints before dropping this handle.
/// That releases response waits; socket shutdown releases blocked packet reads.
pub(crate) struct OwnedServer {
    control: Arc<Control>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        self.control.stopped.store(true, Ordering::Release);
        let stream = self
            .control
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(stream) = stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            // The owner is not the worker: the server only owns channel/socket
            // endpoints and never invokes a VMM callback or takes this handle.
            worker.thread().unpark();
            if worker.join().is_err() {
                warn!("GDB server worker panicked before shutdown completed");
            }
        }
    }
}

pub(crate) fn spawn_owned_server(
    port: u16,
    channels: GdbChannels,
    wait: bool,
) -> std::io::Result<OwnedServer> {
    let mut server = GdbServer::new(port, channels, wait)?;
    server.wait_connection()?;
    server.listener.set_nonblocking(true)?;
    let control = Arc::new(Control::default());
    let worker_control = control.clone();
    let worker = thread::Builder::new()
        .name("gdb-server".into())
        .spawn(move || {
            while !worker_control.stopped.load(Ordering::Acquire) {
                match server.listener.accept() {
                    Ok((stream, address)) => {
                        // Accepted sockets can inherit listener flags on some
                        // hosts. Packet reads retain the blocking RSP contract.
                        if let Err(error) = stream.set_nonblocking(false) {
                            error!(error = %error, "Failed to configure GDB connection");
                            continue;
                        }
                        let socket = match stream.try_clone() {
                            Ok(socket) => socket,
                            Err(error) => {
                                error!(error = %error, "Failed to retain GDB connection control");
                                continue;
                            }
                        };
                        {
                            let mut active = worker_control
                                .active
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if worker_control.stopped.load(Ordering::Acquire) {
                                break;
                            }
                            *active = Some(socket);
                        }
                        let _connection = ActiveConnection(&worker_control);
                        info!(addr = %address, "GDB client connected");
                        if let Err(error) = server.handle_client(stream) {
                            error!(error = %error, "GDB client error");
                        }
                        info!("GDB client disconnected");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::park_timeout(Duration::from_millis(100));
                    }
                    Err(error) => {
                        error!(error = %error, "Failed to accept GDB connection");
                        break;
                    }
                }
            }
        })?;
    Ok(OwnedServer {
        control,
        worker: Some(worker),
    })
}
