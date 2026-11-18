//! A host with files: one directory of the machine as the program's whole
//! file namespace.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use super::host::{Clock, Errno, Host, OpenFlags, Whence};

/// The first handle of a file this host opens. Those below it are the
/// standard streams.
const FIRST_HANDLE: u64 = 3;

/// A host that adds files to another host: the files under one directory.
///
/// The program sees that directory as the root of its namespace, and as the
/// directory its relative paths start from. A path cannot name anything
/// outside it: `..` at the root is the root, as in a file system, and a path
/// that leaves the directory through a symbolic link is refused with
/// `EACCES`. That check and the operation after it are two steps, so this
/// keeps a program inside the directory only as long as nothing else moves
/// links into the program's reach while it runs.
///
/// Whatever is not a file this host opened goes to the host inside, which
/// has the standard streams and the clocks and decides the capabilities.
#[derive(Debug)]
pub struct Directory<H> {
    /// The host for everything but files.
    pub inner: H,
    root: PathBuf,
    open: BTreeMap<u64, File>,
    next: u64,
}

impl<H> Directory<H> {
    /// A host whose files are those under `root`, which must be a directory.
    pub fn new(inner: H, root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotADirectory));
        }
        Ok(Self {
            inner,
            root,
            open: BTreeMap::new(),
            next: FIRST_HANDLE,
        })
    }

    /// The path of the machine that the guest's `path` names.
    fn resolve(&self, path: &str) -> Result<PathBuf, Errno> {
        let mut names: Vec<&str> = Vec::new();
        for name in path.split('/') {
            match name {
                "" | "." => {}
                ".." => {
                    names.pop();
                }
                name => {
                    // One name of the guest is one name here: nothing the
                    // machine reads as a separator, a drive or a parent.
                    let mut parts = Path::new(name).components();
                    if !matches!(
                        (parts.next(), parts.next()),
                        (Some(Component::Normal(_)), None)
                    ) {
                        return Err(Errno::EINVAL);
                    }
                    names.push(name);
                }
            }
        }
        let mut resolved = self.root.clone();
        resolved.extend(names);
        self.contained(&resolved)?;
        Ok(resolved)
    }

    /// Check that `path`, or the directory it would be made in, is under
    /// the root once every link on the way is followed.
    fn contained(&self, path: &Path) -> Result<(), Errno> {
        let existing = if path.symlink_metadata().is_ok() {
            path
        } else {
            path.parent().ok_or(Errno::EACCES)?
        };
        let real = existing
            .canonicalize()
            .map_err(|error| Errno::from(&error))?;
        if real.starts_with(&self.root) {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }
}

impl<H: Host> Host for Directory<H> {
    fn grants(&self, capability: &str) -> bool {
        self.inner.grants(capability)
    }

    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno> {
        match self.open.get_mut(&handle) {
            Some(file) => file.read(buffer).map_err(|error| Errno::from(&error)),
            None => self.inner.read(handle, buffer),
        }
    }

    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        match self.open.get_mut(&handle) {
            Some(file) => file.write(bytes).map_err(|error| Errno::from(&error)),
            None => self.inner.write(handle, bytes),
        }
    }

    fn now(&mut self, clock: Clock) -> Result<u64, Errno> {
        self.inner.now(clock)
    }

    fn open(&mut self, path: &str, flags: OpenFlags, mode: u32) -> Result<u64, Errno> {
        let resolved = self.resolve(path)?;
        if resolved.is_dir() {
            return Err(Errno::EISDIR);
        }
        let mut options = OpenOptions::new();
        options
            .read(flags.read)
            // Appending is a way of writing, which the two exclude here.
            .write(flags.write && !flags.append)
            .append(flags.append)
            .create(flags.create)
            .truncate(flags.truncate);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
        #[cfg(not(unix))]
        let _ = mode;
        let file = options
            .open(&resolved)
            .map_err(|error| Errno::from(&error))?;
        let handle = self.next;
        self.next += 1;
        self.open.insert(handle, file);
        Ok(handle)
    }

    fn close(&mut self, handle: u64) -> Result<(), Errno> {
        match self.open.remove(&handle) {
            Some(_) => Ok(()),
            None => self.inner.close(handle),
        }
    }

    fn seek(&mut self, handle: u64, offset: i64, whence: Whence) -> Result<u64, Errno> {
        let Some(file) = self.open.get_mut(&handle) else {
            return self.inner.seek(handle, offset, whence);
        };
        let position = match whence {
            // A position before the start is none.
            Whence::Start => SeekFrom::Start(u64::try_from(offset).map_err(|_| Errno::EINVAL)?),
            Whence::Current => SeekFrom::Current(offset),
            Whence::End => SeekFrom::End(offset),
        };
        file.seek(position).map_err(|error| Errno::from(&error))
    }

    fn unlink(&mut self, path: &str) -> Result<(), Errno> {
        let resolved = self.resolve(path)?;
        if resolved.is_dir() {
            return Err(Errno::EISDIR);
        }
        std::fs::remove_file(resolved).map_err(|error| Errno::from(&error))
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Errno> {
        let (from, to) = (self.resolve(from)?, self.resolve(to)?);
        std::fs::rename(from, to).map_err(|error| Errno::from(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::NoHost;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh directory with a sibling beside it, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static COUNT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "smir-directory-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("root")).unwrap();
            std::fs::create_dir_all(path.join("outside")).unwrap();
            Self(path)
        }

        fn host(&self) -> Directory<NoHost> {
            Directory::new(NoHost, self.0.join("root")).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const WRITE: OpenFlags = OpenFlags {
        read: false,
        write: true,
        create: true,
        truncate: true,
        append: false,
    };
    const READ: OpenFlags = OpenFlags {
        read: true,
        write: false,
        create: false,
        truncate: false,
        append: false,
    };

    #[test]
    fn a_file_is_written_read_and_found_where_the_root_is() {
        let scratch = Scratch::new();
        let mut host = scratch.host();
        let handle = host.open("notes.txt", WRITE, 0o644).unwrap();
        assert_eq!(handle, FIRST_HANDLE);
        assert_eq!(host.write(handle, b"hello"), Ok(5));
        assert_eq!(host.seek(handle, 1, Whence::Start), Ok(1));
        assert_eq!(host.write(handle, b"u"), Ok(1));
        assert_eq!(host.seek(handle, -1, Whence::End), Ok(4));
        assert_eq!(host.seek(handle, 1, Whence::Current), Ok(5));
        assert_eq!(host.seek(handle, -1, Whence::Start), Err(Errno::EINVAL));
        assert_eq!(host.seek(handle, -9, Whence::Current), Err(Errno::EINVAL));
        assert_eq!(host.close(handle), Ok(()));
        // A closed handle is none, and is not given out again.
        assert_eq!(host.write(handle, b"x"), Err(Errno::EBADF));
        assert_eq!(host.close(handle), Err(Errno::EBADF));
        assert_eq!(
            std::fs::read(scratch.0.join("root/notes.txt")).unwrap(),
            b"hullo"
        );
        // An absolute path starts from the same root as a relative one.
        let again = host.open("/notes.txt", READ, 0).unwrap();
        assert_eq!(again, FIRST_HANDLE + 1);
        let mut buffer = [0_u8; 8];
        assert_eq!(host.read(again, &mut buffer), Ok(5));
        assert_eq!(host.read(again, &mut buffer), Ok(0));
        // It was opened for reading only.
        assert!(host.write(again, b"x").is_err());
    }

    #[test]
    fn appending_writes_at_the_end_wherever_the_position_is() {
        let scratch = Scratch::new();
        let mut host = scratch.host();
        let handle = host.open("log", WRITE, 0o644).unwrap();
        host.write(handle, b"one").unwrap();
        host.close(handle).unwrap();
        let append = OpenFlags {
            append: true,
            truncate: false,
            create: false,
            ..WRITE
        };
        let handle = host.open("log", append, 0).unwrap();
        host.seek(handle, 0, Whence::Start).unwrap();
        host.write(handle, b"two").unwrap();
        assert_eq!(
            std::fs::read(scratch.0.join("root/log")).unwrap(),
            b"onetwo"
        );
    }

    #[test]
    fn no_path_leaves_the_root() {
        let scratch = Scratch::new();
        let mut host = scratch.host();
        std::fs::write(scratch.0.join("outside/secret"), b"secret").unwrap();
        // The parent of the root is the root.
        assert_eq!(host.open("../outside/secret", READ, 0), Err(Errno::ENOENT));
        let made = host.open("a/../../made", WRITE, 0o644).unwrap();
        host.close(made).unwrap();
        assert!(scratch.0.join("root/made").exists());
        assert!(!scratch.0.join("made").exists());
        // A link out of the root is not followed, to a file or to a
        // directory, for reading, making, removing or renaming.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(scratch.0.join("outside"), scratch.0.join("root/door"))
                .unwrap();
            std::os::unix::fs::symlink(
                scratch.0.join("outside/secret"),
                scratch.0.join("root/key"),
            )
            .unwrap();
            assert_eq!(host.open("door/secret", READ, 0), Err(Errno::EACCES));
            assert_eq!(host.open("key", READ, 0), Err(Errno::EACCES));
            assert_eq!(host.open("door/new", WRITE, 0o644), Err(Errno::EACCES));
            assert_eq!(host.unlink("door/secret"), Err(Errno::EACCES));
            assert_eq!(host.rename("made", "door/made"), Err(Errno::EACCES));
            assert!(scratch.0.join("outside/secret").exists());
            assert!(!scratch.0.join("outside/new").exists());
        }
    }

    #[test]
    fn names_are_removed_and_changed() {
        let scratch = Scratch::new();
        let mut host = scratch.host();
        let handle = host.open("first", WRITE, 0o644).unwrap();
        host.close(handle).unwrap();
        assert_eq!(host.rename("first", "second"), Ok(()));
        assert_eq!(host.open("first", READ, 0), Err(Errno::ENOENT));
        assert_eq!(host.unlink("first"), Err(Errno::ENOENT));
        assert_eq!(host.unlink("second"), Ok(()));
        assert_eq!(host.rename("second", "third"), Err(Errno::ENOENT));
        // A directory is no file.
        std::fs::create_dir(scratch.0.join("root/sub")).unwrap();
        assert_eq!(host.open("sub", READ, 0), Err(Errno::EISDIR));
        assert_eq!(host.open("", READ, 0), Err(Errno::EISDIR));
        assert_eq!(host.unlink("sub"), Err(Errno::EISDIR));
        assert_eq!(host.open("sub/none/file", WRITE, 0o644), Err(Errno::ENOENT));
    }

    #[test]
    fn what_is_no_file_goes_to_the_host_inside() {
        let scratch = Scratch::new();
        let mut host = scratch.host();
        assert!(!host.grants("file"));
        assert_eq!(host.write(1, b"x"), Err(Errno::EBADF));
        assert_eq!(host.close(1), Err(Errno::EBADF));
        assert_eq!(host.now(Clock::Utc), Err(Errno::EINVAL));
        assert!(Directory::new(NoHost, scratch.0.join("root/absent")).is_err());
    }
}
