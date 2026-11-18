//! Guest-owned anonymous byte pipes. An endpoint remains open while a handle
//! table or a pending I/O operation holds a reference to it.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::super::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_PIPE_BROKEN,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Writer {
    Waiting,
    Opening,
    Open,
    Closed,
}

#[derive(Debug)]
struct Channel {
    bytes: VecDeque<u8>,
    capacity: usize,
    reader_open: bool,
    writer: Writer,
}

#[derive(Debug)]
struct End {
    channel: Rc<RefCell<Channel>>,
    write: bool,
}

impl Drop for End {
    fn drop(&mut self) {
        let mut channel = self.channel.borrow_mut();
        if self.write {
            channel.writer = if channel.writer == Writer::Opening {
                Writer::Waiting
            } else {
                Writer::Closed
            };
        } else {
            channel.reader_open = false;
        }
    }
}

/// A reference to an open read or write endpoint.
#[derive(Clone, Debug)]
pub struct PipeEnd(Rc<End>);

impl PartialEq for PipeEnd {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for PipeEnd {}

impl PipeEnd {
    pub(crate) fn reader(capacity: usize) -> Self {
        Self(Rc::new(End {
            channel: Rc::new(RefCell::new(Channel {
                bytes: VecDeque::new(),
                capacity,
                reader_open: true,
                writer: Writer::Waiting,
            })),
            write: false,
        }))
    }

    pub(crate) fn prepare_writer(&self) -> Option<Self> {
        let mut channel = self.0.channel.borrow_mut();
        if self.0.write || channel.writer != Writer::Waiting {
            return None;
        }
        channel.writer = Writer::Opening;
        Some(Self(Rc::new(End {
            channel: self.0.channel.clone(),
            write: true,
        })))
    }

    pub(crate) fn finish_writer_open(&self) {
        let mut channel = self.0.channel.borrow_mut();
        debug_assert!(self.0.write && channel.writer == Writer::Opening);
        channel.writer = Writer::Open;
    }

    pub(crate) fn ready(&self) -> bool {
        let channel = self.0.channel.borrow();
        if self.0.write {
            !channel.reader_open || channel.bytes.len() < channel.capacity
        } else {
            !channel.bytes.is_empty() || channel.writer == Writer::Closed
        }
    }

    /// None denotes a pending read. Buffered bytes are delivered before EOF.
    pub(crate) fn read(&self, requested: usize) -> Result<Option<Vec<u8>>, u32> {
        if self.0.write {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mut channel = self.0.channel.borrow_mut();
        if requested != 0 && channel.bytes.is_empty() {
            return if channel.writer == Writer::Closed {
                Err(STATUS_PIPE_BROKEN)
            } else {
                Ok(None)
            };
        }
        let count = requested.min(channel.bytes.len());
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        output.extend(channel.bytes.drain(..count));
        Ok(Some(output))
    }

    /// Transfers the prefix that fits. The caller retains the remainder
    /// while the thread waits for buffer space.
    pub(crate) fn write(&self, requested: &[u8]) -> Result<usize, u32> {
        if !self.0.write {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mut channel = self.0.channel.borrow_mut();
        if !channel.reader_open {
            return Err(STATUS_PIPE_BROKEN);
        }
        let count = requested.len().min(channel.capacity - channel.bytes.len());
        channel
            .bytes
            .try_reserve(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        channel.bytes.extend(&requested[..count]);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_fifo_backpressure_and_endpoint_lifetime() {
        let reader = PipeEnd::reader(3);
        assert!(!reader.ready());
        assert_eq!(reader.read(1), Ok(None));
        let writer = reader.prepare_writer().unwrap();
        writer.finish_writer_open();
        assert!(reader.prepare_writer().is_none());
        let duplicate = writer.clone();
        assert_eq!(writer.write(b"abcd"), Ok(3));
        assert!(!writer.ready());
        assert_eq!(reader.read(2), Ok(Some(b"ab".to_vec())));
        assert!(writer.ready());
        assert_eq!(writer.write(b"d"), Ok(1));
        drop(writer);
        assert_eq!(reader.read(3), Ok(Some(b"cd".to_vec())));
        assert!(!reader.ready());
        drop(duplicate);
        assert!(reader.ready());
        assert_eq!(reader.read(3), Err(STATUS_PIPE_BROKEN));
    }

    #[test]
    fn unpublished_writer_allows_a_retry() {
        let reader = PipeEnd::reader(4);
        let writer = reader.prepare_writer().unwrap();
        assert!(reader.prepare_writer().is_none());
        drop(writer);
        assert_eq!(reader.read(1), Ok(None));
        let writer = reader.prepare_writer().unwrap();
        writer.finish_writer_open();
        drop(writer);
        assert_eq!(reader.read(1), Err(STATUS_PIPE_BROKEN));
    }

    #[test]
    fn peer_close_wakes_the_writer_with_broken_pipe() {
        let reader = PipeEnd::reader(1);
        let writer = reader.prepare_writer().unwrap();
        writer.finish_writer_open();
        assert_eq!(writer.write(b"a"), Ok(1));
        assert!(!writer.ready());
        drop(reader);
        assert!(writer.ready());
        assert_eq!(writer.write(b"b"), Err(STATUS_PIPE_BROKEN));
    }
}
