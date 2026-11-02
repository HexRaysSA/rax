//! Real kernel objects with identical FIFO mode bits require different policy.
use super::*;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::fs::read(self.0.join(".owner")).ok().as_deref() == Some(b"rax-pipe-kind-test\n") {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn anonymous_pipe_classification_keeps_linked_and_unlinked_fifos_as_vnodes() {
    let mut raw = [-1; 2];
    // SAFETY: two initialized writable descriptor slots.
    assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
    // SAFETY: pipe created these two exclusive owned descriptors.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(raw[0]), OwnedFd::from_raw_fd(raw[1])) };
    assert!(anonymous_pipe(read.as_raw_fd()));
    assert!(anonymous_pipe(write.as_raw_fd()));
    let root = std::env::temp_dir().join(format!(
        "rax-pipe-kind-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join(".owner"), b"rax-pipe-kind-test\n").unwrap();
    let root = Fixture(root);
    let path = root.0.join("named");
    let native = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: terminated native pathname in this test's exclusively owned directory.
    assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
    let fifo = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    assert_eq!(
        fstat(fifo.as_raw_fd()).unwrap().st_mode & libc::S_IFMT,
        libc::S_IFIFO
    );
    assert_eq!(
        fstat(read.as_raw_fd()).unwrap().st_mode & libc::S_IFMT,
        libc::S_IFIFO
    );
    assert!(!anonymous_pipe(fifo.as_raw_fd()));
    std::fs::remove_file(path).unwrap();
    assert!(
        !anonymous_pipe(fifo.as_raw_fd()),
        "unlink preserves vnode identity"
    );
    let file = File::create(root.0.join("ordinary")).unwrap();
    assert!(!anonymous_pipe(file.as_raw_fd()));
    assert!(!anonymous_pipe(-1));
}
