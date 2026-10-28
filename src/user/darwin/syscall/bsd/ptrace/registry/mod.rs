//! Per-host-user rendezvous for independently launched Darwin processes.
//! Discovery is O(1) fixed-size file work; accepting a peer never authorizes
//! tracing. Ptrace/Mach policy must still check the target's guest identity.

mod identity;
mod manager;
pub(super) use manager::{Direction, Event, Registry};
mod session;
mod socket;
mod wake;
pub(super) use session::Session;
#[cfg(test)]
mod tests;

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

const RECORD_SIZE: usize = 32;
// Discovery version gates the complete connected protocol before authority
// can be acquired. Version 2 adds acknowledged reap and signing metadata.
const MAGIC: &[u8; 8] = b"RAXREG02";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub pid: i32,
    pub uid: u32,
    pub instance: [u8; 16],
}

impl Record {
    pub fn encode(self) -> [u8; RECORD_SIZE] {
        let mut out = [0; RECORD_SIZE];
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&self.pid.to_le_bytes());
        out[12..16].copy_from_slice(&self.uid.to_le_bytes());
        out[16..].copy_from_slice(&self.instance);
        out
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RECORD_SIZE || &bytes[..8] != MAGIC {
            return Err(invalid("invalid registry record"));
        }
        let out = Self {
            pid: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            uid: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            instance: bytes[16..].try_into().unwrap(),
        };
        if out.pid <= 0 || out.instance == [0; 16] {
            return Err(invalid("invalid registry process instance"));
        }
        Ok(out)
    }

    fn socket_name(self) -> String {
        let hex: String = self.instance.iter().map(|v| format!("{v:02x}")).collect();
        format!("s{}-{hex}", self.pid)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Debug)]
pub(super) struct Root {
    path: PathBuf,
    uid: u32,
    device: u64,
    inode: u64,
}

impl Root {
    pub fn open(base: &Path) -> io::Result<Self> {
        // SAFETY: geteuid has no arguments or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let base = base.canonicalize()?;
        // A foreign account must not be able to replace an ancestor. Root's
        // sticky /tmp is permitted; account-owned private directories are too.
        for ancestor in base.ancestors() {
            let m = fs::metadata(ancestor)?;
            if !m.is_dir() || ![0, uid].contains(&m.uid()) {
                return Err(denied("untrusted registry ancestor"));
            }
            if m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0) {
                return Err(denied("writable registry ancestor"));
            }
        }
        let path = base.join(format!("rax-darwin-{uid}"));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let m = fs::symlink_metadata(&path)?;
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
            return Err(denied(
                "registry directory must be private and owned by this account",
            ));
        }
        Ok(Self {
            path,
            uid,
            device: m.dev(),
            inode: m.ino(),
        })
    }

    fn verify(&self) -> io::Result<()> {
        let m = fs::symlink_metadata(&self.path)?;
        if !m.is_dir()
            || m.uid() != self.uid
            || m.mode() & 0o777 != 0o700
            || m.dev() != self.device
            || m.ino() != self.inode
        {
            return Err(denied("registry directory changed"));
        }
        Ok(())
    }

    fn open_file(&self, name: &str, create: bool) -> io::Result<File> {
        self.verify()?;
        let file = OpenOptions::new()
            .read(true)
            .write(create)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.path.join(name))?;
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != self.uid || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
            return Err(denied("invalid registry file ownership or type"));
        }
        self.verify()?;
        Ok(file)
    }

    pub fn lookup(&self, pid: i32) -> io::Result<Record> {
        self.lookup_record(pid, false)
    }

    fn lookup_record(&self, pid: i32, replace_previous: bool) -> io::Result<Record> {
        if pid <= 0 {
            return Err(invalid("invalid registry pid"));
        }
        let mut file = self.open_file(&format!("p{pid}.entry"), false)?;
        if file.metadata()?.len() != RECORD_SIZE as u64 {
            return Err(invalid("invalid registry record size"));
        }
        let mut bytes = [0; RECORD_SIZE];
        file.read_exact(&mut bytes)?;
        // Only the publisher holding this PID's exclusive lease may replace
        // a well-formed stale version-1 record. Discovery never admits it.
        if replace_previous && &bytes[..8] == b"RAXREG01" {
            bytes[..8].copy_from_slice(MAGIC);
        }
        let record = Record::decode(&bytes)?;
        if record.pid != pid || record.uid != self.uid {
            return Err(denied("registry record identity mismatch"));
        }
        Ok(record)
    }

    pub fn publish(&self) -> io::Result<Endpoint> {
        self.verify()?;
        // SAFETY: getpid has no memory preconditions.
        let pid = unsafe { libc::getpid() };
        let lease = self.open_file(&format!("p{pid}.lock"), true)?;
        // A separate lease inode survives atomic replacement of the record.
        // It is deliberately not unlinked on drop: replacing a locked inode
        // would allow two publishers to acquire unrelated locks for one PID.
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        match self.lookup_record(pid, true) {
            Ok(_) => {} // A valid stale record may be replaced under the lease.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut instance = [0; 16];
        getrandom::fill(&mut instance).map_err(|e| io::Error::other(e.to_string()))?;
        if instance == [0; 16] {
            return Err(io::Error::other("zero registry instance"));
        }
        let record = Record {
            pid,
            uid: self.uid,
            instance,
        };
        let socket_path = self.path.join(record.socket_name());
        let listener = UnixListener::bind(&socket_path)?;
        let socket = fs::symlink_metadata(&socket_path)?;
        let mut endpoint = Endpoint {
            root: self.clone(),
            record,
            listener,
            socket_device: socket.dev(),
            socket_inode: socket.ino(),
            _lease: lease,
            published: false,
        };
        endpoint.listener.set_nonblocking(true)?;
        self.verify()?;
        let temporary = self.path.join(format!("{}.new", record.socket_name()));
        let mut created = false;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)?;
            created = true;
            file.write_all(&record.encode())?;
            fs::rename(&temporary, self.path.join(format!("p{pid}.entry")))?;
            Ok::<_, io::Error>(())
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        endpoint.published = true;
        Ok(endpoint)
    }

    pub fn connect(&self, pid: i32) -> io::Result<socket::Dial> {
        let record = self.lookup(pid)?;
        socket::Dial::start(&self.path.join(record.socket_name()), record)
    }
}

#[derive(Debug)]
pub(super) struct Endpoint {
    root: Root,
    pub record: Record,
    listener: UnixListener,
    socket_device: u64,
    socket_inode: u64,
    _lease: File,
    published: bool,
}

impl Endpoint {
    pub fn fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn accept(&self) -> io::Result<Option<(Record, UnixStream)>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        };
        stream.set_nonblocking(true)?;
        let peer = identity::peer(&stream)?;
        if peer.uid != self.root.uid {
            return Err(denied("foreign registry account"));
        }
        let record = self.root.lookup(peer.pid)?;
        Ok(Some((record, stream)))
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // An inherited descriptor in a forked child must never unlink its
        // parent's publication. The child must publish its own PID instance.
        if unsafe { libc::getpid() } != self.record.pid || self.root.verify().is_err() {
            return;
        }
        if self.published && self.root.lookup(self.record.pid).ok() == Some(self.record) {
            let _ = fs::remove_file(self.root.path.join(format!("p{}.entry", self.record.pid)));
        }
        let socket = self.root.path.join(self.record.socket_name());
        if let Ok(m) = fs::symlink_metadata(&socket) {
            if m.file_type().is_socket()
                && m.dev() == self.socket_device
                && m.ino() == self.socket_inode
            {
                let _ = fs::remove_file(socket);
            }
        }
    }
}
