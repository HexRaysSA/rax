//! Bounded real RSP connections for VMM regression tests.
use super::*;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) fn serve(channels: GdbChannels) -> (SocketAddr, JoinHandle<()>, Arc<AtomicBool>) {
    let mut server = GdbServer::new(0, channels, false).unwrap();
    let address = server.listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let handle = std::thread::spawn(move || {
        loop {
            let (stream, _) = server.listener.accept().unwrap();
            if worker_stop.load(Ordering::SeqCst) {
                break;
            }
            // Match the production accept loop: connection errors do not prevent
            // another client from attaching to the same stopped owner.
            let _ = server.handle_client(stream);
            if worker_stop.load(Ordering::SeqCst) {
                break;
            }
        }
    });
    (address, handle, stop)
}
