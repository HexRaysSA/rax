//! Process console routing shared by embedded OS personalities.
//!
//! Captured consoles never touch host standard streams. Input is finite (an
//! empty queue reads as EOF), may be appended between runs, and output is
//! retained until drained. Input and combined stdout/stderr each have the
//! configured byte bound. Exhaustion reports an I/O error without dropping
//! accepted bytes. Clones deliberately refer to the same console.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// Guest output stream identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct Buffers {
    input: VecDeque<u8>,
    stdout: VecDeque<u8>,
    stderr: VecDeque<u8>,
    capacity: usize,
}

/// A bounded, nonblocking console owned by the caller of an embedded process.
#[derive(Clone, Debug)]
pub struct CapturedConsole(Arc<Mutex<Buffers>>);

fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

impl CapturedConsole {
    /// `capacity` bounds unread input and combined unread output separately.
    pub fn new(input: Vec<u8>, capacity: usize) -> io::Result<Self> {
        if input.len() > capacity {
            return Err(error("console input exceeds capacity"));
        }
        Ok(Self(Arc::new(Mutex::new(Buffers {
            input: input.into(),
            stdout: VecDeque::new(),
            stderr: VecDeque::new(),
            capacity,
        }))))
    }

    /// Appends input atomically, or leaves it unchanged if the bound is exceeded.
    pub fn feed(&self, bytes: &[u8]) -> io::Result<()> {
        let mut b = self.0.lock().map_err(|_| error("console lock poisoned"))?;
        if bytes.len() > b.capacity - b.input.len() {
            return Err(error("console input capacity exhausted"));
        }
        b.input
            .try_reserve(bytes.len())
            .map_err(|_| error("console allocation failed"))?;
        b.input.extend(bytes);
        Ok(())
    }

    /// Copies and consumes at most `out.len()` bytes, with no allocation.
    pub fn drain(&self, stream: OutputStream, out: &mut [u8]) -> io::Result<usize> {
        let mut b = self.0.lock().map_err(|_| error("console lock poisoned"))?;
        Ok(pop(
            match stream {
                OutputStream::Stdout => &mut b.stdout,
                OutputStream::Stderr => &mut b.stderr,
            },
            out,
        ))
    }

    /// Unread byte counts `(stdin, stdout, stderr)`.
    pub fn pending(&self) -> io::Result<(usize, usize, usize)> {
        let b = self.0.lock().map_err(|_| error("console lock poisoned"))?;
        Ok((b.input.len(), b.stdout.len(), b.stderr.len()))
    }

    fn read(&self, out: &mut [u8]) -> io::Result<usize> {
        let mut b = self.0.lock().map_err(|_| error("console lock poisoned"))?;
        Ok(pop(&mut b.input, out))
    }

    fn write(&self, stream: OutputStream, bytes: &[u8]) -> io::Result<usize> {
        let mut b = self.0.lock().map_err(|_| error("console lock poisoned"))?;
        let available = b.capacity - b.stdout.len() - b.stderr.len();
        // Accept complete writes or no bytes, so Win32 synchronous WriteFile
        // and chunked CRT transfers can preserve their precise prefix counts.
        if bytes.len() > available {
            return Err(error("console output capacity exhausted"));
        }
        let queue = match stream {
            OutputStream::Stdout => &mut b.stdout,
            OutputStream::Stderr => &mut b.stderr,
        };
        queue
            .try_reserve(bytes.len())
            .map_err(|_| error("console allocation failed"))?;
        queue.extend(bytes);
        Ok(bytes.len())
    }
}

fn pop(queue: &mut VecDeque<u8>, out: &mut [u8]) -> usize {
    let count = queue.len().min(out.len());
    for slot in &mut out[..count] {
        *slot = queue.pop_front().expect("length checked");
    }
    count
}

/// Console routing. Host mode preserves CLI behavior; captured mode is suitable
/// for an embedder that supplies input and consumes bounded output explicitly.
#[derive(Clone, Debug, Default)]
pub enum Console {
    #[default]
    Host,
    Captured(CapturedConsole),
}

impl Console {
    /// Reads finite captured input or invokes the host stdin reader.
    pub fn read(&self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Host => io::stdin().read(out),
            Self::Captured(c) => c.read(out),
        }
    }

    /// Writes all bytes or reports an error. Captured writes are atomic.
    /// Host writes can have partial external effects before an error.
    pub fn write_all(&self, stream: OutputStream, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Captured(c) => c.write(stream, bytes).map(|_| ()),
            Self::Host => match stream {
                OutputStream::Stdout => io::stdout().write_all(bytes),
                OutputStream::Stderr => io::stderr().write_all(bytes),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_input_eof_refill_and_bounds() {
        assert!(CapturedConsole::new(vec![1, 2], 1).is_err());
        let c = CapturedConsole::new(vec![1, 2], 3).unwrap();
        assert!(c.feed(&[3, 4]).is_err());
        let mut out = [0; 4];
        assert_eq!(c.read(&mut out).unwrap(), 2);
        assert_eq!(&out[..2], &[1, 2]);
        assert_eq!(c.read(&mut out).unwrap(), 0);
        c.feed(&[3]).unwrap();
        assert_eq!(c.clone().read(&mut out).unwrap(), 1);
        assert_eq!(out[0], 3);
    }
    #[test]
    fn combined_output_bound_atomic_failure_and_drain() {
        let c = CapturedConsole::new(vec![], 3).unwrap();
        c.write(OutputStream::Stdout, b"ab").unwrap();
        assert!(c.write(OutputStream::Stderr, b"cd").is_err());
        c.write(OutputStream::Stderr, b"c").unwrap();
        assert_eq!(c.pending().unwrap(), (0, 2, 1));
        let mut out = [0; 1];
        assert_eq!(c.drain(OutputStream::Stdout, &mut out).unwrap(), 1);
        assert_eq!(out, *b"a");
        c.write(OutputStream::Stderr, b"d").unwrap();
        assert_eq!(c.pending().unwrap(), (0, 1, 2));
        let mut out = [0; 4];
        assert_eq!(c.drain(OutputStream::Stderr, &mut out).unwrap(), 2);
        assert_eq!(&out[..2], b"cd");
    }
    #[test]
    fn zero_capacity_accepts_only_empty_transfers() {
        let c = CapturedConsole::new(vec![], 0).unwrap();
        c.feed(&[]).unwrap();
        c.write(OutputStream::Stdout, &[]).unwrap();
        assert!(c.write(OutputStream::Stdout, &[1]).is_err());
        assert_eq!(c.read(&mut [0; 1]).unwrap(), 0);
    }
}
