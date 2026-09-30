use super::*;
use std::collections::VecDeque;

enum Step {
    Bytes(usize),
    Error(io::ErrorKind),
}

struct Writer {
    steps: VecDeque<Step>,
    accepted: Vec<u8>,
    flush_error: Option<io::ErrorKind>,
    calls: usize,
}

impl Writer {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            accepted: Vec::new(),
            flush_error: None,
            calls: 0,
        }
    }
}
impl Write for Writer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        match self.steps.pop_front().unwrap_or(Step::Bytes(input.len())) {
            Step::Bytes(count) => {
                let count = count.min(input.len());
                self.accepted.extend_from_slice(&input[..count]);
                Ok(count)
            }
            Step::Error(kind) => Err(io::Error::from(kind)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.flush_error {
            Some(kind) => Err(io::Error::from(kind)),
            None => Ok(()),
        }
    }
}

#[test]
fn short_writes_continue_at_the_accepted_frontier_and_retain_error_progress() {
    let mut writer = Writer::new([
        Step::Bytes(2),
        Step::Bytes(1),
        Step::Error(io::ErrorKind::StorageFull),
    ]);
    let result = write_chunk(&mut writer, b"abcdef");
    assert_eq!(result.bytes, 3);
    assert_eq!(writer.accepted, b"abc");
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::StorageFull);
}

#[test]
fn interrupted_operations_retry_only_the_unaccepted_suffix() {
    let mut writer = Writer::new([
        Step::Error(io::ErrorKind::Interrupted),
        Step::Bytes(2),
        Step::Error(io::ErrorKind::Interrupted),
        Step::Bytes(3),
    ]);
    let result = write_chunk(&mut writer, b"abcde");
    assert_eq!(result.bytes, 5);
    assert!(result.error.is_none());
    assert_eq!(writer.accepted, b"abcde");
    assert_eq!(writer.calls, 4);
}

#[test]
fn zero_write_is_an_error_not_an_infinite_progress_loop() {
    let mut writer = Writer::new([Step::Bytes(2), Step::Bytes(0)]);
    let result = write_chunk(&mut writer, b"abcd");
    assert_eq!(result.bytes, 2);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::WriteZero);
    assert_eq!(writer.calls, 2);
}

#[test]
fn scratch_bounds_reject_before_any_host_effect() {
    let mut writer = Writer::new([]);
    let result = write_chunk(&mut writer, &[7; CHUNK * 2 + 1]);
    assert_eq!(result.bytes, 0);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
    assert!(writer.accepted.is_empty());
    assert_eq!(writer.calls, 0);
    let mut reader = io::Cursor::new(vec![9; CHUNK + 1]);
    assert_eq!(
        read_chunk(&mut reader, &mut [0; CHUNK + 1])
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(reader.position(), 0);
}

#[test]
fn console_flush_failure_preserves_the_accepted_byte_count() {
    let mut writer = Writer::new([]);
    writer.flush_error = Some(io::ErrorKind::BrokenPipe);
    let result = console_write(&mut writer, b"no-newline");
    assert_eq!(result.bytes, 10);
    assert_eq!(writer.accepted, b"no-newline");
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn empty_transfer_performs_no_read_or_write() {
    let mut writer = Writer::new([Step::Error(io::ErrorKind::Other)]);
    assert!(write_chunk(&mut writer, &[]).error.is_none());
    assert_eq!(writer.calls, 0);
    let mut reader = io::Cursor::new(b"data");
    assert_eq!(read_chunk(&mut reader, &mut []).unwrap(), 0);
    assert_eq!(reader.position(), 0);
}

#[test]
fn exact_bounded_read_advances_only_the_read_prefix() {
    let mut reader = io::Cursor::new(b"abc");
    let mut output = [0xAA; CHUNK];
    assert_eq!(read_chunk(&mut reader, &mut output).unwrap(), 3);
    assert_eq!(&output[..3], b"abc");
    assert!(output[3..].iter().all(|&byte| byte == 0xAA));
    assert_eq!(read_chunk(&mut reader, &mut output).unwrap(), 0);
}

#[test]
fn captured_crt_backend_preserves_bounds_and_finite_input_all_abis() {
    use crate::user::console::CapturedConsole;
    crate::user::windows::dll::crt::tests::run(|c| {
        let capture = CapturedConsole::new(b"abc".to_vec(), 4).unwrap();
        std::sync::Arc::make_mut(&mut c.p.cfg).console = Console::Captured(capture.clone());
        let input = c.p.objects.create(Object::Console(StdStream::In));
        let output = c.p.objects.create(Object::Console(StdStream::Out));
        let error = c.p.objects.create(Object::Console(StdStream::Err));
        let mut bytes = [0; 4];
        assert_eq!(read(c.p, input, &mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"abc");
        assert_eq!(read(c.p, input, &mut bytes).unwrap(), 0);
        let first = write(c.p, output, b"abcd", false);
        assert_eq!(first.bytes, 4);
        assert!(first.error.is_none());
        let overflow = write(c.p, error, b"e", false);
        assert_eq!(overflow.bytes, 0);
        assert!(overflow.error.is_some());
        assert_eq!(capture.drain(OutputStream::Stdout, &mut bytes).unwrap(), 4);
        assert_eq!(&bytes, b"abcd");
        assert_eq!(write(c.p, error, b"e", false).bytes, 1);
    });
}
