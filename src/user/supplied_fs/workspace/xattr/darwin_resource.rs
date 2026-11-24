//! Native storage for a reserved guest resource fork. Neither descriptor
//! names an installed file, and the construction path is unlinked at once.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub(super) struct Fork {
    parent: File,
    pub(super) file: File,
    pub(super) len: usize,
    pub(super) reservation: usize,
}

impl Fork {
    pub(super) fn new(data: &[u8]) -> io::Result<Self> {
        let directory = private_directory()?;
        let path = directory.join("storage");
        let files = (|| {
            let parent = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            let fork_path = path.join("..namedfork").join("rsrc");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(fork_path)?;
            Ok::<_, io::Error>((parent, file))
        })();
        let unlink = fs::remove_file(&path);
        let remove_directory = fs::remove_dir(&directory);
        let (parent, file) = files?;
        unlink?;
        remove_directory?;
        file.write_all_at(data, 0)?;
        Ok(Self {
            parent,
            file,
            len: data.len(),
            reservation: 0,
        })
    }

    pub(super) fn blocks(&self) -> io::Result<i64> {
        Ok(self.file.metadata()?.blocks() as i64)
    }

    pub(super) fn parent_blocks(&self) -> io::Result<i64> {
        Ok(self.parent.metadata()?.blocks() as i64)
    }

    pub(super) fn write_xattr(&self, offset: u32, bytes: &[u8]) -> io::Result<()> {
        // SAFETY: the pathless parent and its resource descriptor are owned
        // by this state and the borrowed bytes outlive the native call.
        let result = unsafe {
            libc::fsetxattr(
                self.parent.as_raw_fd(),
                c"com.apple.ResourceFork".as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                offset,
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn private_directory() -> io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir();
    loop {
        let directory = root.join(format!(
            "rax-resource-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}
