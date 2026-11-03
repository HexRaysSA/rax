use super::read;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[test]
fn native_fifo_transfer_handles_never_written_data_reopen_and_repeated_eof() {
    let path = std::env::temp_dir().join(format!("rax-splice-{}", std::process::id()));
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the unique temporary path is owned by this serialized fixture.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    assert!(fd >= 0);
    let reader = unsafe { OwnedFd::from_raw_fd(fd) };
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, 0) }, 0);
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    for _ in 0..3 {
        assert_eq!(read(fd, 8).unwrap(), b"");
    }
    let write = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
    assert!(write >= 0);
    let writer = unsafe { OwnedFd::from_raw_fd(write) };
    assert_eq!(unsafe { libc::unlink(path.as_ptr()) }, 0);
    assert_eq!(read(fd, 8).unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert!(read(fd, 0).unwrap().is_empty());
    assert_eq!(
        read(writer.as_raw_fd(), 0).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(unsafe { libc::write(write, b"abc".as_ptr().cast(), 3) }, 3);
    assert_eq!(read(fd, 32 * 1024 * 1024).unwrap(), b"abc");
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
    drop(writer);
    for _ in 0..3 {
        assert!(read(fd, 8).unwrap().is_empty());
    }
    assert_eq!(
        unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) },
        flags
    );
    assert_eq!(read(-1, 0).unwrap_err().raw_os_error(), Some(libc::EBADF));
}

#[test]
fn native_transfer_drains_more_than_one_private_pipe_capacity() {
    let mut pair = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    let (reader, writer) =
        unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
    let size = 128 * 1024;
    let enlarged = unsafe { libc::fcntl(pair[1], libc::F_SETPIPE_SZ, size) };
    assert!(enlarged >= size);
    let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        unsafe { libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
        bytes.len() as isize
    );
    assert_eq!(read(reader.as_raw_fd(), bytes.len()).unwrap(), bytes);
}
