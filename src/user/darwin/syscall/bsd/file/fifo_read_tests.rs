use super::Job;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fifo {
    reader: OwnedFd,
    writer: Option<OwnedFd>,
    path: PathBuf,
}

impl Fifo {
    fn new(writer: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let path = std::env::temp_dir().join(format!(
            "rax-native-read-job-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            assert_eq!(libc::mkfifo(cpath.as_ptr(), 0o600), 0);
            let reader = libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
            assert!(reader >= 0);
            let writer = if writer {
                let fd = libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
                assert!(fd >= 0);
                Some(OwnedFd::from_raw_fd(fd))
            } else {
                None
            };
            assert_eq!(libc::fcntl(reader, libc::F_SETFL, 0), 0);
            Self {
                reader: OwnedFd::from_raw_fd(reader),
                writer,
                path,
            }
        }
    }

    fn write(&self, bytes: &[u8]) {
        unsafe {
            assert_eq!(
                libc::write(
                    self.writer.as_ref().unwrap().as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len()
                ),
                bytes.len() as isize
            );
        }
    }

    fn flags(&self) -> i32 {
        unsafe { libc::fcntl(self.reader.as_raw_fd(), libc::F_GETFL) }
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}

fn ready(job: &Job, milliseconds: i32) -> bool {
    let mut descriptor = libc::pollfd {
        fd: job.fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut descriptor, 1, milliseconds) > 0 }
}

#[test]
fn repeated_eof_reads_complete_without_a_readiness_assumption() {
    let mut fifo = Fifo::new(true);
    fifo.writer = None;
    for _ in 0..4 {
        let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
        assert!(ready(&job, 2000));
        assert_eq!(job.take().unwrap().unwrap(), b"");
        assert_eq!(fifo.flags(), 0);
    }
}

#[test]
fn a_fifo_that_never_had_a_writer_returns_eof() {
    let fifo = Fifo::new(false);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    assert!(ready(&job, 2000));
    assert!(job.take().unwrap().unwrap().is_empty());
}

#[test]
fn a_zero_byte_read_does_not_wait_for_an_open_writer() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 0).unwrap();
    assert!(ready(&job, 2000));
    assert!(job.take().unwrap().unwrap().is_empty());
}

#[test]
fn a_large_request_returns_only_the_prefix_initialized_by_the_native_read() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 32 * 1024 * 1024).unwrap();
    fifo.write(b"abc");
    assert!(ready(&job, 2000));
    assert_eq!(job.take().unwrap().unwrap(), b"abc");
}

#[test]
fn a_new_writer_after_eof_requires_a_real_read() {
    let mut fifo = Fifo::new(false);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    assert!(ready(&job, 2000));
    assert!(job.take().unwrap().unwrap().is_empty());
    drop(job);
    let path = CString::new(fifo.path.as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
    assert!(fd >= 0);
    fifo.writer = Some(unsafe { OwnedFd::from_raw_fd(fd) });
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    assert!(!ready(&job, 5));
    fifo.write(b"abc");
    assert!(ready(&job, 2000));
    assert_eq!(job.take().unwrap().unwrap(), b"abc");
    assert_eq!(fifo.flags(), 0);
}

#[test]
fn cancellation_before_or_during_native_entry_does_not_strand_workers() {
    let fifo = Fifo::new(true);
    for _ in 0..1000 {
        let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
        job.interrupt();
        assert_eq!(
            job.take().unwrap().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(fifo.flags(), 0);
    }
}

#[test]
fn quiescing_an_unperformed_read_can_resume_in_the_parent() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    job.pause();
    assert!(!job.ready());
    job.resume().unwrap();
    assert!(!ready(&job, 5));
    fifo.write(b"p");
    assert!(ready(&job, 2000));
    assert_eq!(job.take().unwrap().unwrap(), b"p");
}

#[test]
fn shared_flag_changes_during_a_pause_do_not_change_the_entered_blocking_read() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    job.pause();
    assert_eq!(
        unsafe { libc::fcntl(fifo.reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    job.resume().unwrap();
    assert!(!ready(&job, 5));
    fifo.write(b"f");
    assert!(ready(&job, 2000));
    assert_eq!(job.take().unwrap().unwrap(), b"f");
    assert_eq!(fifo.flags() & libc::O_NONBLOCK, libc::O_NONBLOCK);
}

#[test]
fn quiescing_a_completed_read_retains_its_bytes_once() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    fifo.write(b"q");
    assert!(ready(&job, 2000));
    job.pause();
    job.resume().unwrap();
    assert_eq!(job.take().unwrap().unwrap(), b"q");
    assert!(job.take().is_none());
}

#[test]
fn cancellation_racing_data_never_discards_a_consumed_byte() {
    for _ in 0..100 {
        let fifo = Fifo::new(true);
        let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
        fifo.write(b"x");
        job.interrupt();
        let completion = job.take().unwrap();
        assert_eq!(fifo.flags(), 0);
        // This observer changes only its owned fixture after the job joined.
        assert_eq!(
            unsafe { libc::fcntl(fifo.reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut byte = [0];
        let count = unsafe { libc::read(fifo.reader.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        match completion {
            Ok(data) => {
                assert_eq!(data, b"x");
                assert_eq!(count, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
            }
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EINTR));
                assert_eq!(count, 1);
                assert_eq!(byte, *b"x");
            }
        }
    }
}

#[test]
fn a_fork_child_drops_only_quiesced_local_resources() {
    let fifo = Fifo::new(true);
    let job = Job::start(fifo.reader.as_fd(), 8).unwrap();
    job.pause();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        drop(job);
        unsafe {
            libc::_exit(0);
        }
    }
    job.resume().unwrap();
    fifo.write(b"f");
    assert!(ready(&job, 2000));
    assert_eq!(job.take().unwrap().unwrap(), b"f");
    let mut status = -1;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    assert_eq!(fifo.flags(), 0);
}
