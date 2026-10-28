use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

pub(super) struct Temporary(PathBuf);
impl Temporary {
    pub(super) fn new() -> Self {
        let mut token = [0u8; 8];
        getrandom::fill(&mut token).unwrap();
        let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
        let path = PathBuf::from("/tmp").join(format!("rgr-{token}"));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    pub(super) fn root(&self) -> Root {
        Root::open(&self.0).unwrap()
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        // Only this test's freshly created, randomly named directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn fixed_record_rejects_truncation_reserved_version_and_invalid_identity() {
    let record = Record {
        pid: 0x12345678,
        uid: 0xa1b2c3d4,
        instance: [0x5a; 16],
    };
    let bytes = record.encode();
    assert_eq!(&bytes[..16], b"RAXREG02\x78\x56\x34\x12\xd4\xc3\xb2\xa1");
    assert_eq!(Record::decode(&bytes).unwrap(), record);
    for length in 0..32 {
        assert!(Record::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(Record::decode(&extra).is_err());
    let mut bad = bytes;
    bad[7] = b'1';
    assert!(Record::decode(&bad).is_err());
    let mut bad = bytes;
    bad[8..12].copy_from_slice(&0i32.to_le_bytes());
    assert!(Record::decode(&bad).is_err());
    let mut bad = bytes;
    bad[8..12].copy_from_slice(&(-1i32).to_le_bytes());
    assert!(Record::decode(&bad).is_err());
    let mut bad = bytes;
    bad[16..].fill(0);
    assert!(Record::decode(&bad).is_err());
}

#[test]
fn publication_lease_and_generation_follow_one_host_process_instance() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let endpoint = root.publish().unwrap();
    let first = endpoint.record;
    assert_eq!(root.lookup(first.pid).unwrap(), first);
    assert!(
        root.publish().is_err(),
        "two listeners must not publish one PID"
    );
    let socket = root.path.join(first.socket_name());
    assert!(socket.exists());
    drop(endpoint);
    assert_eq!(
        root.lookup(first.pid).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!socket.exists());
    let replacement = root.publish().unwrap();
    assert_eq!(replacement.record.pid, first.pid);
    assert_ne!(replacement.record.instance, first.instance);
}

#[test]
fn unknown_files_are_not_overwritten_or_truncated() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let pid = unsafe { libc::getpid() };
    let entry = root.path.join(format!("p{pid}.entry"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&entry)
        .unwrap();
    file.write_all(b"unrelated user file").unwrap();
    assert!(root.publish().is_err());
    assert_eq!(fs::read(entry).unwrap(), b"unrelated user file");
}

#[test]
fn symlinks_and_hardlinks_are_rejected_before_any_write() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let pid = unsafe { libc::getpid() };
    let sentinel = temporary.0.join("sentinel");
    fs::write(&sentinel, b"keep").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let lease = root.path.join(format!("p{pid}.lock"));
    symlink(&sentinel, &lease).unwrap();
    assert!(root.publish().is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
    fs::remove_file(&lease).unwrap();
    fs::hard_link(&sentinel, &lease).unwrap();
    assert!(root.publish().is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
}

#[test]
fn public_or_symlinked_registry_directories_are_not_accepted() {
    let temporary = Temporary::new();
    let root = temporary.root();
    fs::set_permissions(&root.path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Root::open(&temporary.0).is_err());
    fs::set_permissions(&root.path, fs::Permissions::from_mode(0o700)).unwrap();
    let old = temporary.0.join("old");
    fs::rename(&root.path, &old).unwrap();
    symlink(&old, &root.path).unwrap();
    assert!(Root::open(&temporary.0).is_err());
}

#[test]
fn a_fifo_record_cannot_block_discovery() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let pid = unsafe { libc::getpid() };
    let name = root.path.join(format!("p{pid}.entry"));
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert_eq!(
        root.lookup(pid).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn connected_sockets_supply_the_pid_and_uid_from_the_host_kernel() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let endpoint = root.publish().unwrap();
    assert!(endpoint.accept().unwrap().is_none());
    let mut dial = root.connect(endpoint.record.pid).unwrap();
    let client = dial.finish().unwrap().expect("local connection ready");
    let (record, server) = endpoint.accept().unwrap().expect("accepted");
    assert_eq!(record, endpoint.record);
    let peer = identity::peer(&server).unwrap();
    assert_eq!((peer.pid, peer.uid), (record.pid, record.uid));
    assert!(identity::require(&client, record.pid + 1, record.uid).is_err());
    assert!(identity::require(&client, record.pid, record.uid.wrapping_add(1)).is_err());
}

#[test]
fn a_record_cannot_substitute_for_the_connected_socket_identity() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let endpoint = root.publish().unwrap();
    for wrong_uid in [false, true] {
        let mut expected = endpoint.record;
        if wrong_uid {
            expected.uid = expected.uid.wrapping_add(1);
        } else {
            expected.pid += 1;
        }
        let mut dial =
            socket::Dial::start(&root.path.join(endpoint.record.socket_name()), expected).unwrap();
        let _accepted = endpoint.accept().unwrap().unwrap();
        assert_eq!(
            dial.finish().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

#[test]
fn replacing_the_directory_never_deletes_the_replacement_publication() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let endpoint = root.publish().unwrap();
    let pid = endpoint.record.pid;
    let old = temporary.0.join("old");
    fs::rename(&root.path, &old).unwrap();
    DirBuilder::new().mode(0o700).create(&root.path).unwrap();
    let replacement = root.path.join(format!("p{pid}.entry"));
    fs::write(&replacement, b"replacement").unwrap();
    assert!(root.lookup(pid).is_err());
    drop(endpoint);
    assert_eq!(fs::read(replacement).unwrap(), b"replacement");
}

#[test]
fn stale_prior_protocol_record_can_be_replaced_only_under_the_publishers_lease() {
    let temporary = Temporary::new();
    let root = temporary.root();
    let pid = unsafe { libc::getpid() };
    let old = Record {
        pid,
        uid: root.uid,
        instance: [7; 16],
    };
    let mut bytes = old.encode();
    bytes[..8].copy_from_slice(b"RAXREG01");
    let path = root.path.join(format!("p{pid}.entry"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    assert!(
        root.lookup(pid).is_err(),
        "discovery must reject incompatible peers"
    );
    let endpoint = root.publish().unwrap();
    assert_ne!(endpoint.record.instance, old.instance);
    assert_eq!(root.lookup(pid).unwrap(), endpoint.record);
    assert_eq!(&fs::read(&path).unwrap()[..8], b"RAXREG02");
    assert!(
        root.publish().is_err(),
        "a second publisher cannot replace an active lease"
    );
}
