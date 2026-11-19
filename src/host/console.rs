//! Host console multiplexer for the interactive serial console.
//!
//! Owns the background thread that reads host stdin and a small escape-key
//! state machine (à la qemu's `Ctrl-A` serial mux). Most bytes are forwarded
//! verbatim to the guest UART; a `Ctrl-A` prefix introduces a host command:
//!
//!   Ctrl-A s   take a snapshot / checkpoint now
//!   Ctrl-A x   quit the VM cleanly
//!   Ctrl-A h   print this help
//!   Ctrl-A Ctrl-A   send a literal Ctrl-A (0x01) to the guest
//!
//! Keeping the mux here (rather than inside the UART model) means the UART stays
//! a faithful 16550 and the host-only control surface lives at the VMM layer,
//! which is the only place that can actually act on a snapshot/quit request.

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

/// Escape prefix byte: Ctrl-A (0x01).
const ESC_PREFIX: u8 = 0x01;

/// A host-side action requested through the escape prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleAction {
    /// Take a snapshot / checkpoint of the running machine now.
    Snapshot,
    /// Quit the VM cleanly.
    Quit,
    /// Print the escape-key help banner.
    Help,
}

/// One-line-per-binding help text shown on `Ctrl-A h`.
pub const ESCAPE_HELP: &str = "\
rax console escapes:\r\n\
\x20 Ctrl-A s   take a snapshot (checkpoint)\r\n\
\x20 Ctrl-A x   quit the VM\r\n\
\x20 Ctrl-A h   show this help\r\n\
\x20 Ctrl-A Ctrl-A   send a literal Ctrl-A to the guest\r\n";

/// Host console: a stdin reader thread plus the escape-prefix state machine.
pub struct Console {
    rx: Option<Receiver<u8>>,
    /// True once the escape prefix has been seen and we are waiting for the
    /// command key.
    armed: bool,
}

impl Console {
    /// Spawn the stdin reader thread and return a ready console. Safe to call
    /// even when stdin is not a TTY — it will simply observe EOF/no input.
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            let mut buf = [0u8; 1];
            loop {
                match handle.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        if tx.send(buf[0]).is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Console {
            rx: Some(rx),
            armed: false,
        }
    }

    /// A console with no input source (used for non-interactive runs/tests).
    pub fn inert() -> Self {
        Console {
            rx: None,
            armed: false,
        }
    }

    /// Preload a deterministic receiver for tests of the console consumer.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let (tx, rx) = mpsc::channel();
        for &byte in bytes {
            tx.send(byte).unwrap();
        }
        Self {
            rx: Some(rx),
            armed: false,
        }
    }

    /// Drain all currently-available stdin bytes through the escape mux.
    /// Returns `(guest_bytes, actions)` where `guest_bytes` should be queued
    /// into the UART and `actions` handled by the VMM.
    pub fn poll(&mut self) -> (Vec<u8>, Vec<ConsoleAction>) {
        let mut guest = Vec::new();
        let mut actions = Vec::new();
        loop {
            let (bytes, action) = self.poll_batch();
            guest.extend(bytes);
            match action {
                Some(action) => actions.push(action),
                None => return (guest, actions),
            }
        }
    }

    /// Read guest input up to the first host command. Bytes following that
    /// command stay in the receiver until its caller has handled the command.
    pub(crate) fn poll_batch(&mut self) -> (Vec<u8>, Option<ConsoleAction>) {
        let mut guest = Vec::new();
        while let Some(rx) = &self.rx {
            let b = match rx.try_recv() {
                Ok(byte) => byte,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.rx = None;
                    break;
                }
            };
            if self.armed {
                self.armed = false;
                match b {
                    b's' | b'S' => return (guest, Some(ConsoleAction::Snapshot)),
                    b'x' | b'X' => return (guest, Some(ConsoleAction::Quit)),
                    b'h' | b'H' | b'?' => return (guest, Some(ConsoleAction::Help)),
                    ESC_PREFIX => guest.push(ESC_PREFIX), // literal Ctrl-A
                    other => {
                        // Unknown escape: pass both bytes through so nothing is
                        // silently lost.
                        guest.push(ESC_PREFIX);
                        guest.push(other);
                    }
                }
            } else if b == ESC_PREFIX {
                self.armed = true;
            } else {
                guest.push(b);
            }
        }

        (guest, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes_pass_through() {
        let mut c = Console::from_bytes(b"echo hi\n");
        let (guest, actions) = c.poll();
        assert_eq!(guest, b"echo hi\n");
        assert!(actions.is_empty());
    }

    #[test]
    fn escape_snapshot_and_quit() {
        let mut c = Console::from_bytes(&[0x01, b's', b'a', 0x01, b'x']);
        let (guest, actions) = c.poll();
        assert_eq!(guest, b"a");
        assert_eq!(actions, vec![ConsoleAction::Snapshot, ConsoleAction::Quit]);
    }

    #[test]
    fn ordered_batches_stop_at_each_host_command() {
        let mut console = Console::from_bytes(b"A\x01\x01\x01sB\x01hC\x01xD");
        for (bytes, action) in [
            (b"A\x01".as_slice(), Some(ConsoleAction::Snapshot)),
            (b"B".as_slice(), Some(ConsoleAction::Help)),
            (b"C".as_slice(), Some(ConsoleAction::Quit)),
            (b"D".as_slice(), None),
        ] {
            assert_eq!(console.poll_batch(), (bytes.to_vec(), action));
        }
    }

    #[test]
    fn literal_ctrl_a() {
        let mut c = Console::from_bytes(&[0x01, 0x01, b'z']);
        let (guest, actions) = c.poll();
        assert_eq!(guest, vec![0x01, b'z']);
        assert!(actions.is_empty());
    }

    #[test]
    fn unknown_escape_passes_both_bytes() {
        let mut c = Console::from_bytes(&[0x01, b'q']);
        let (guest, actions) = c.poll();
        assert_eq!(guest, vec![0x01, b'q']);
        assert!(actions.is_empty());
    }

    #[test]
    fn escape_split_across_polls() {
        let (tx, rx) = mpsc::channel();
        let mut c = Console {
            rx: Some(rx),
            armed: false,
        };
        tx.send(0x01).unwrap();
        let (g1, a1) = c.poll();
        assert!(g1.is_empty() && a1.is_empty());
        assert!(c.armed);
        tx.send(b's').unwrap();
        let (g2, a2) = c.poll();
        assert!(g2.is_empty());
        assert_eq!(a2, vec![ConsoleAction::Snapshot]);
    }
}
