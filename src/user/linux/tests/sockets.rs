//! Sockets against `net/socket.c`, `net/unix/af_unix.c`,
//! `net/ipv4/af_inet.c`, `net/core/sock.c`, and `net/core/scm.c` (Linux
//! 6.19): creation checks, names and their copies out, the message headers,
//! descriptor and credential passing, blocking with timeouts and signals,
//! options, `SIGPIPE` by protocol, the batch calls, and readiness. The
//! sockets are real host sockets on the loopback and in temporary
//! directories.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::restart::ERESTARTSYS;
use crate::user::linux::signal::*;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const SEQPACKET: u64 = 5;
const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PRIORITY: u64 = 12;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_RCVTIMEO: u64 = 20;
const SO_ACCEPTCONN: u64 = 30;
const SO_RCVBUFFORCE: u64 = 33;
const SO_PROTOCOL: u64 = 38;
const SO_COOKIE: u64 = 57;
const SO_DEBUG: u64 = 1;
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_WAITFORONE: u64 = 0x10000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const AT_FDCWD: u64 = -100i64 as u64;

/// A scratch area of 16 pages.
fn area(h: &mut Harness) -> u64 {
    h.anon(16 * P, 3, false)
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    u32::from_le_bytes(get(h, at, 4).try_into().unwrap())
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(get(h, at, 8).try_into().unwrap())
}

fn sock(h: &mut Harness, domain: u64, kind: u64) -> u64 {
    h.ok(Sysno::Socket, &[domain, kind, 0])
}

fn pair(h: &mut Harness, kind: u64, at: u64) -> (u64, u64) {
    h.ok(Sysno::Socketpair, &[AF_UNIX, kind, 0, at]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

/// A `sockaddr_un` naming path `p` (its length through the NUL).
fn sun(p: &[u8]) -> Vec<u8> {
    let mut b = (AF_UNIX as u16).to_le_bytes().to_vec();
    b.extend_from_slice(p);
    b.push(0);
    b
}

/// A `sockaddr_un` naming abstract name `n`.
fn sun_abstract(n: &[u8]) -> Vec<u8> {
    let mut b = (AF_UNIX as u16).to_le_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(n);
    b
}

/// A `sockaddr_in` for 127.0.0.1:`port`.
fn sin(port: u16) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&[127, 0, 0, 1]);
    b
}

/// Places an address at `at` for a call: `(pointer, length)`.
fn addr(h: &Harness, at: u64, a: &[u8]) -> (u64, u64) {
    put(h, at, a);
    (at, a.len() as u64)
}

fn bind(h: &mut Harness, fd: u64, a: &[u8], at: u64) -> i64 {
    let (p, l) = addr(h, at, a);
    h.call(Sysno::Bind, &[fd, p, l])
}

fn connect(h: &mut Harness, fd: u64, a: &[u8], at: u64) -> i64 {
    let (p, l) = addr(h, at, a);
    h.call(Sysno::Connect, &[fd, p, l])
}

/// `getsockname` (or `getpeername`) with a 128-byte buffer.
fn name(h: &mut Harness, fd: u64, peer: bool, at: u64) -> Result<Vec<u8>, i32> {
    put(h, at + 0x100, &128u32.to_le_bytes());
    let s = if peer {
        Sysno::Getpeername
    } else {
        Sysno::Getsockname
    };
    let r = h.call(s, &[fd, at, at + 0x100]);
    if r < 0 {
        return Err(-r as i32);
    }
    let n = u32_at(h, at + 0x100) as usize;
    Ok(get(h, at, n.min(128)))
}

/// The port of a bound IP socket.
fn port_of(h: &mut Harness, fd: u64, at: u64) -> u16 {
    let a = name(h, fd, false, at).unwrap();
    u16::from_be_bytes([a[2], a[3]])
}

/// A TCP listener on the loopback: `(listener, port)`.
fn listener(h: &mut Harness, at: u64) -> (u64, u16) {
    let l = sock(h, AF_INET, STREAM);
    assert_eq!(bind(h, l, &sin(0), at), 0);
    h.ok(Sysno::Listen, &[l, 8]);
    let port = port_of(h, l, at);
    (l, port)
}

/// A connected TCP pair on the loopback: `(client, server)`.
fn tcp_pair(h: &mut Harness, at: u64) -> (u64, u64, u64) {
    let (l, port) = listener(h, at);
    let c = sock(h, AF_INET, STREAM);
    assert_eq!(connect(h, c, &sin(port), at), 0);
    let s = h.ok(Sysno::Accept4, &[l, 0, 0, 0]);
    (c, s, l)
}

fn getopt(
    h: &mut Harness,
    fd: u64,
    level: u64,
    opt: u64,
    len: u32,
    at: u64,
) -> Result<Vec<u8>, i32> {
    put(h, at + 0x100, &len.to_le_bytes());
    let r = h.call(Sysno::Getsockopt, &[fd, level, opt, at, at + 0x100]);
    if r < 0 {
        return Err(-r as i32);
    }
    let n = u32_at(h, at + 0x100) as usize;
    Ok(get(h, at, n))
}

fn opt_int(h: &mut Harness, fd: u64, level: u64, opt: u64, at: u64) -> i32 {
    let v = getopt(h, fd, level, opt, 4, at).unwrap();
    assert_eq!(v.len(), 4);
    i32::from_le_bytes(v.try_into().unwrap())
}

fn setopt(h: &mut Harness, fd: u64, level: u64, opt: u64, v: &[u8], at: u64) -> i64 {
    put(h, at, v);
    h.call(Sysno::Setsockopt, &[fd, level, opt, at, v.len() as u64])
}

fn setopt_int(h: &mut Harness, fd: u64, level: u64, opt: u64, v: i32, at: u64) -> i64 {
    setopt(h, fd, level, opt, &v.to_le_bytes(), at)
}

fn send(h: &mut Harness, fd: u64, data: &[u8], flags: u64, at: u64) -> i64 {
    put(h, at, data);
    h.call(Sysno::Sendto, &[fd, at, data.len() as u64, flags, 0, 0])
}

fn recv(h: &mut Harness, fd: u64, n: u64, flags: u64, at: u64) -> Result<Vec<u8>, i32> {
    let r = h.call(Sysno::Recvfrom, &[fd, at, n, flags, 0, 0]);
    if r < 0 {
        return Err(-r as i32);
    }
    Ok(get(h, at, (r as u64).min(n) as usize))
}

/// A unique temporary directory for a test and ABI.
fn tmpdir(tag: &str, abi: LinuxAbi) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rax-sk-{}-{tag}-{abi:?}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    // The guest's view: symbolic links resolved (Darwin's /var).
    std::fs::canonicalize(d).unwrap()
}

fn path_bytes(p: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

fn chdir(h: &mut Harness, dir: &std::path::Path, at: u64) {
    let mut b = path_bytes(dir);
    b.push(0);
    put(h, at, &b);
    h.ok(Sysno::Chdir, &[at]);
}

/// Installs a handler for `sig` so sending it is not fatal.
fn handle(h: &mut Harness, sig: i32) {
    let act = h.scratch + 0xf00;
    let mut words = vec![0x40_1000u64];
    if h.abi().has_sa_restorer() {
        words.extend([sa::RESTORER, 0x40_1100]);
    } else {
        words.push(0);
    }
    words.push(0);
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    put(h, act, &b);
    h.ok(Sysno::RtSigaction, &[sig as u64, act, 0, 8]);
}

fn raise(h: &mut Harness, sig: i32) {
    handle(h, sig);
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, sig as u64]);
}

/// Discards the first thread's pending signals (the harness delivers
/// none).
fn unraise(h: &mut Harness) {
    h.proc.threads[0].pending = SigPending::new();
    h.proc.threads[0].sigpending = false;
}

/// A `struct timeval` of `ms` milliseconds.
fn timeval_ms(ms: i64) -> Vec<u8> {
    let mut b = (ms / 1000).to_le_bytes().to_vec();
    b.extend_from_slice(&((ms % 1000) * 1000).to_le_bytes());
    b
}

#[test]
fn creation_checks_follow_sock_create() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        assert_eq!(h.err(Sysno::Socket, &[999, STREAM, 0]), EAFNOSUPPORT);
        assert_eq!(h.err(Sysno::Socket, &[u64::MAX, STREAM, 0]), EAFNOSUPPORT);
        // AF_PACKET is not provided (netlink is, in tests/netlink.rs).
        assert_eq!(h.err(Sysno::Socket, &[17, 3, 0]), EAFNOSUPPORT);
        // SOCK_MAX, flag bits, and the type switch.
        assert_eq!(h.err(Sysno::Socket, &[AF_INET, 11, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Socket, &[AF_INET, STREAM | 0x100, 0]), EINVAL);
        assert_eq!(
            h.err(Sysno::Socket, &[AF_INET, SEQPACKET, 0]),
            ESOCKTNOSUPPORT
        );
        assert_eq!(h.err(Sysno::Socket, &[AF_INET, STREAM, 263]), EINVAL);
        assert_eq!(h.err(Sysno::Socket, &[AF_INET, STREAM, u64::MAX]), EINVAL);
        assert_eq!(h.err(Sysno::Socket, &[AF_INET, DGRAM, 6]), EPROTONOSUPPORT);
        assert_eq!(h.err(Sysno::Socket, &[AF_UNIX, 4, 0]), ESOCKTNOSUPPORT);
        assert_eq!(h.err(Sysno::Socket, &[AF_UNIX, STREAM, 2]), EPROTONOSUPPORT);
        if h.proc.state.creds.1 != 0 {
            assert_eq!(h.err(Sysno::Socket, &[AF_INET, 3, 1]), EPERM);
        }
        // PF_UNIX as the protocol is accepted and not kept; SOCK_RAW Unix
        // sockets are datagram ones.
        let u = h.ok(Sysno::Socket, &[AF_UNIX, STREAM, 1]);
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_PROTOCOL, m), 0);
        let r = h.ok(Sysno::Socket, &[AF_UNIX, 3, 0]);
        assert_eq!(opt_int(&mut h, r, SOL_SOCKET, SO_TYPE, m), 2);
        let t = h.ok(Sysno::Socket, &[AF_INET, STREAM | NONBLOCK | CLOEXEC, 0]);
        assert_eq!(opt_int(&mut h, t, SOL_SOCKET, SO_PROTOCOL, m), 6);
        // f_flags: O_RDWR, and O_NONBLOCK when asked.
        assert_eq!(h.ok(Sysno::Fcntl, &[t, 3, 0]), 0o4002);
        assert_eq!(h.ok(Sysno::Fcntl, &[t, 1, 0]), 1);
        assert_eq!(h.ok(Sysno::Fcntl, &[u, 3, 0]), 0o2);
        assert_eq!(h.err(Sysno::Lseek, &[u, 0, 0]), ESPIPE);
        // statx: a socket inode with every permission; the descriptor's
        // link names the same inode.
        put(&h, m, b"\0");
        h.ok(Sysno::Statx, &[u, m, 0x1000, 0xfff, m + 0x100]);
        let mode = u16::from_le_bytes(get(&h, m + 0x100 + 0x1c, 2).try_into().unwrap());
        let ino = u64_at(&h, m + 0x100 + 0x20);
        assert_eq!(u32::from(mode), 0o140777, "{abi:?}");
        put(&h, m, format!("/proc/self/fd/{u}\0").as_bytes());
        let n = h.ok(Sysno::Readlinkat, &[AT_FDCWD, m, m + 0x400, 64]);
        assert_eq!(
            get(&h, m + 0x400, n as usize),
            format!("socket:[{ino}]").as_bytes()
        );
        // Not a socket.
        assert_eq!(h.err(Sysno::Listen, &[0, 1]), ENOTSOCK);
        assert_eq!(h.err(Sysno::Listen, &[77, 1]), EBADF);
    });
}

#[test]
fn socketpair_reserves_and_writes_its_descriptors_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (a, b) = pair(&mut h, STREAM | CLOEXEC, m);
        assert_eq!(h.ok(Sysno::Fcntl, &[b, 1, 0]), 1);
        // The pair of another family: refused after the descriptors were
        // chosen and written.
        put(&h, m, &[0xff; 8]);
        assert_eq!(
            h.err(Sysno::Socketpair, &[AF_INET, STREAM, 0, m]),
            EOPNOTSUPP
        );
        let (x, y) = (u32_at(&h, m), u32_at(&h, m + 4));
        assert_eq!((u64::from(x), u64::from(y)), (b + 1, b + 2));
        // An unwritable vector: EFAULT, nothing created.
        assert_eq!(
            h.err(Sysno::Socketpair, &[AF_UNIX, STREAM, 0, 0x10]),
            EFAULT
        );
        assert_eq!(sock(&mut h, AF_UNIX, STREAM), b + 1);
        // Connected, unnamed, and two-way.
        assert_eq!(
            name(&mut h, a, true, m).unwrap(),
            (AF_UNIX as u16).to_le_bytes()
        );
        assert_eq!(
            name(&mut h, a, false, m).unwrap(),
            (AF_UNIX as u16).to_le_bytes()
        );
        assert_eq!(send(&mut h, a, b"hi", 0, m), 2);
        assert_eq!(recv(&mut h, b, 8, 0, m).unwrap(), b"hi");
        assert_eq!(send(&mut h, b, b"yo", 0, m), 2);
        assert_eq!(recv(&mut h, a, 8, 0, m).unwrap(), b"yo");
    });
}

#[test]
fn unix_names_bind_resolve_and_report() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let dir = tmpdir("names", abi);
        chdir(&mut h, &dir, m);
        // A relative path, in the guest's directory; its node takes the
        // permissions the umask leaves.
        let l = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(bind(&mut h, l, &sun(b"s.sock"), m), 0);
        assert_eq!(name(&mut h, l, false, m).unwrap(), sun(b"s.sock"));
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(dir.join("s.sock")).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
        // Bound already: another path is EINVAL and leaves nothing; an
        // existing one is EADDRINUSE.
        assert_eq!(bind(&mut h, l, &sun(b"other"), m), -(EINVAL as i64));
        assert!(!dir.join("other").exists());
        assert_eq!(bind(&mut h, l, &sun(b"s.sock"), m), -(EADDRINUSE as i64));
        let x = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(bind(&mut h, x, &sun(b"s.sock"), m), -(EADDRINUSE as i64));
        // Not listening: refused; listening: connected, the peer named by
        // its absolute path.
        let abs = path_bytes(&dir.join("s.sock"));
        assert_eq!(connect(&mut h, x, &sun(&abs), m), -(ECONNREFUSED as i64));
        h.ok(Sysno::Listen, &[l, 4]);
        let c = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(connect(&mut h, c, &sun(&abs), m), 0);
        assert_eq!(connect(&mut h, c, &sun(&abs), m), -(EISCONN as i64));
        assert_eq!(name(&mut h, c, true, m).unwrap(), sun(&abs));
        let s = h.ok(Sysno::Accept4, &[l, 0, 0, 0]);
        // The accepted socket has the listener's name.
        assert_eq!(name(&mut h, s, false, m).unwrap(), sun(b"s.sock"));
        // A path within Linux's sun_path but longer than the host's once
        // resolved: bound and reached through its directory.
        let deep = dir.join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&deep).unwrap();
        chdir(&mut h, &deep, m);
        let long = "f".repeat(60).into_bytes();
        let ll = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(bind(&mut h, ll, &sun(&long), m), 0);
        assert!(deep.join(std::str::from_utf8(&long).unwrap()).exists());
        h.ok(Sysno::Listen, &[ll, 1]);
        let lc = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(connect(&mut h, lc, &sun(&long), m), 0);
        // A bare family is refused by connect, and a missing path is
        // ENOENT.
        let z = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(
            connect(&mut h, z, &(AF_UNIX as u16).to_le_bytes(), m),
            -(EINVAL as i64)
        );
        assert_eq!(connect(&mut h, z, &sun(b"missing"), m), -(ENOENT as i64));
        // A file that is no socket refuses the connection.
        std::fs::write(deep.join("plain"), b"").unwrap();
        assert_eq!(
            connect(&mut h, z, &sun(b"plain"), m),
            -(ECONNREFUSED as i64)
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn abstract_names_and_autobind() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let tag = format!("rax-abs-{}-{abi:?}", std::process::id()).into_bytes();
        let a = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(bind(&mut h, a, &sun_abstract(&tag), m), 0);
        assert_eq!(name(&mut h, a, false, m).unwrap(), sun_abstract(&tag));
        // In use while its socket lives; free once closed.
        let b = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(
            bind(&mut h, b, &sun_abstract(&tag), m),
            -(EADDRINUSE as i64)
        );
        // Bound already.
        assert_eq!(bind(&mut h, a, &sun_abstract(b"x"), m), -(EINVAL as i64));
        // Not listening, or no such name: refused.
        let c = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(
            connect(&mut h, c, &sun_abstract(&tag), m),
            -(ECONNREFUSED as i64)
        );
        let none = [tag.as_slice(), b"-none"].concat();
        assert_eq!(
            connect(&mut h, c, &sun_abstract(&none), m),
            -(ECONNREFUSED as i64)
        );
        h.ok(Sysno::Listen, &[a, 1]);
        assert_eq!(connect(&mut h, c, &sun_abstract(&tag), m), 0);
        assert_eq!(name(&mut h, c, true, m).unwrap(), sun_abstract(&tag));
        h.ok(Sysno::Close, &[a]);
        // Darwin's emulated name is released with its socket.
        #[cfg(not(target_os = "linux"))]
        assert!(
            !crate::user::linux::net::name::abstract_path(&tag)
                .unwrap()
                .exists()
        );
        assert_eq!(bind(&mut h, b, &sun_abstract(&tag), m), 0);
        #[cfg(not(target_os = "linux"))]
        assert!(
            crate::user::linux::net::name::abstract_path(&tag)
                .unwrap()
                .exists()
        );
        // Autobind: five hex digits in the abstract namespace; binding
        // again is a no-op.
        let d = sock(&mut h, AF_UNIX, DGRAM);
        assert_eq!(bind(&mut h, d, &(AF_UNIX as u16).to_le_bytes(), m), 0);
        let n = name(&mut h, d, false, m).unwrap();
        assert_eq!(n.len(), 8, "{abi:?}");
        assert_eq!(n[2], 0);
        assert!(n[3..].iter().all(u8::is_ascii_hexdigit), "{n:?}");
        assert_eq!(bind(&mut h, d, &(AF_UNIX as u16).to_le_bytes(), m), 0);
        assert_eq!(name(&mut h, d, false, m).unwrap(), n);
        // A datagram from the autobound socket names it.
        let r = sock(&mut h, AF_UNIX, DGRAM);
        let rn = [tag.as_slice(), b"-r"].concat();
        assert_eq!(bind(&mut h, r, &sun_abstract(&rn), m), 0);
        let (p, l) = addr(&h, m + 0x200, &sun_abstract(&rn));
        put(&h, m, b"ping");
        assert_eq!(h.call(Sysno::Sendto, &[d, m, 4, 0, p, l]), 4);
        put(&h, m + 0x300, &128u32.to_le_bytes());
        assert_eq!(
            h.call(Sysno::Recvfrom, &[r, m, 16, 0, m + 0x400, m + 0x300]),
            4
        );
        let from_len = u32_at(&h, m + 0x300) as usize;
        assert_eq!(get(&h, m + 0x400, from_len), n);
    });
}

#[test]
fn addresses_copy_out_as_move_addr_to_user() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let u = sock(&mut h, AF_INET, DGRAM);
        assert_eq!(bind(&mut h, u, &sin(0), m), 0);
        // A short buffer takes the start; the length reports the whole.
        put(&h, m + 0x100, &4u32.to_le_bytes());
        put(&h, m, &[0xee; 16]);
        h.ok(Sysno::Getsockname, &[u, m, m + 0x100]);
        assert_eq!(u32_at(&h, m + 0x100), 16);
        assert_eq!(get(&h, m, 2), (AF_INET as u16).to_le_bytes());
        assert_eq!(get(&h, m + 4, 2), [0xee, 0xee]);
        put(&h, m + 0x100, &u32::MAX.to_le_bytes());
        assert_eq!(h.err(Sysno::Getsockname, &[u, m, m + 0x100]), EINVAL);
        assert_eq!(h.err(Sysno::Getsockname, &[u, m, 0x10]), EFAULT);
        assert_eq!(name(&mut h, u, true, m), Err(ENOTCONN));
        // TCP reports no source; a Unix datagram from an unnamed sender
        // neither; from a named one, its name.
        let (c, s, _) = tcp_pair(&mut h, m);
        assert_eq!(send(&mut h, c, b"t", 0, m), 1);
        put(&h, m + 0x100, &128u32.to_le_bytes());
        assert_eq!(
            h.call(Sysno::Recvfrom, &[s, m, 8, 0, m + 0x200, m + 0x100]),
            1
        );
        assert_eq!(u32_at(&h, m + 0x100), 0, "{abi:?}: TCP");
        let (d0, d1) = pair(&mut h, DGRAM, m);
        assert_eq!(send(&mut h, d0, b"u", 0, m), 1);
        put(&h, m + 0x100, &128u32.to_le_bytes());
        assert_eq!(
            h.call(Sysno::Recvfrom, &[d1, m, 8, 0, m + 0x200, m + 0x100]),
            1
        );
        assert_eq!(u32_at(&h, m + 0x100), 0, "{abi:?}: unnamed");
        // UDP names the sender, as a whole sockaddr_in.
        let v = sock(&mut h, AF_INET, DGRAM);
        let port = port_of(&mut h, u, m);
        let (p, l) = addr(&h, m + 0x300, &sin(port));
        put(&h, m, b"x");
        assert_eq!(h.call(Sysno::Sendto, &[v, m, 1, 0, p, l]), 1);
        put(&h, m + 0x100, &128u32.to_le_bytes());
        assert_eq!(
            h.call(Sysno::Recvfrom, &[u, m, 8, 0, m + 0x200, m + 0x100]),
            1
        );
        assert_eq!(u32_at(&h, m + 0x100), 16);
        let vport = port_of(&mut h, v, m + 0x800);
        assert_eq!(get(&h, m + 0x200, 16), sin(vport));
        // accept4 names the connecting peer.
        let (l, lport) = listener(&mut h, m);
        let k = sock(&mut h, AF_INET, STREAM);
        assert_eq!(connect(&mut h, k, &sin(lport), m), 0);
        put(&h, m + 0x100, &128u32.to_le_bytes());
        let a = h.ok(Sysno::Accept4, &[l, m + 0x200, m + 0x100, CLOEXEC]);
        assert_eq!(h.ok(Sysno::Fcntl, &[a, 1, 0]), 1);
        assert_eq!(u32_at(&h, m + 0x100), 16);
        let kport = port_of(&mut h, k, m + 0x800);
        assert_eq!(get(&h, m + 0x200, 16), sin(kport));
        assert_eq!(h.err(Sysno::Accept4, &[l, 0, 0, 0x1]), EINVAL);
    });
}

#[test]
fn inet_bind_and_connect_check_their_addresses() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let t = sock(&mut h, AF_INET, STREAM);
        assert_eq!(bind(&mut h, t, &sin(0)[..15], m), -(EINVAL as i64));
        let mut other = sin(0);
        other[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        assert_eq!(bind(&mut h, t, &other, m), -(EAFNOSUPPORT as i64));
        // AF_UNSPEC with the any address is AF_INET; with another address
        // it is refused.
        let mut unspec = vec![0u8; 16];
        assert_eq!(bind(&mut h, t, &unspec, m), 0);
        assert_eq!(
            name(&mut h, t, false, m).unwrap()[..2],
            (AF_INET as u16).to_le_bytes()
        );
        assert_eq!(
            bind(&mut h, t, &sin(0), m),
            -(EINVAL as i64),
            "bound already"
        );
        let t2 = sock(&mut h, AF_INET, STREAM);
        unspec[4] = 127;
        assert_eq!(bind(&mut h, t2, &unspec, m), -(EAFNOSUPPORT as i64));
        if h.proc.state.creds.1 != 0 {
            assert_eq!(bind(&mut h, t2, &sin(80), m), -(EACCES as i64));
        }
        assert_eq!(h.err(Sysno::Bind, &[t2, m, 129]), EINVAL);
        assert_eq!(h.err(Sysno::Bind, &[t2, m, u64::MAX]), EINVAL);
        // connect: the family's size, then the family.
        assert_eq!(connect(&mut h, t2, &[2], m), -(EINVAL as i64));
        assert_eq!(connect(&mut h, t2, &sin(1)[..8], m), -(EINVAL as i64));
        assert_eq!(connect(&mut h, t2, &other, m), -(EAFNOSUPPORT as i64));
        // A datagram socket connects, and AF_UNSPEC dissolves it.
        let (l, port) = listener(&mut h, m);
        let _ = l;
        let u = sock(&mut h, AF_INET, DGRAM);
        assert_eq!(connect(&mut h, u, &sin(port), m), 0);
        assert!(name(&mut h, u, true, m).is_ok());
        assert_eq!(connect(&mut h, u, &[0, 0], m), 0);
        assert_eq!(name(&mut h, u, true, m), Err(ENOTCONN));
        // A blocking TCP connect completes before it returns.
        let c = sock(&mut h, AF_INET, STREAM);
        assert_eq!(connect(&mut h, c, &sin(port), m), 0);
        assert_eq!(opt_int(&mut h, c, SOL_SOCKET, SO_ERROR, m), 0);
    });
}

/// Writes a `struct msghdr` at `at`.
#[allow(clippy::too_many_arguments)]
fn msghdr(
    h: &Harness,
    at: u64,
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
    ctl: u64,
    ctllen: u64,
) {
    let mut b = vec![0u8; 56];
    b[..8].copy_from_slice(&name.to_le_bytes());
    b[8..12].copy_from_slice(&namelen.to_le_bytes());
    b[16..24].copy_from_slice(&iov.to_le_bytes());
    b[24..32].copy_from_slice(&iovlen.to_le_bytes());
    b[32..40].copy_from_slice(&ctl.to_le_bytes());
    b[40..48].copy_from_slice(&ctllen.to_le_bytes());
    put(h, at, &b);
}

/// One `struct iovec` at `at` for `len` bytes at `base`.
fn iovec(h: &Harness, at: u64, base: u64, len: u64) {
    let mut b = base.to_le_bytes().to_vec();
    b.extend_from_slice(&len.to_le_bytes());
    put(h, at, &b);
}

/// A control message.
fn cmsg(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
    let mut b = ((16 + data.len()) as u64).to_le_bytes().to_vec();
    b.extend_from_slice(&level.to_le_bytes());
    b.extend_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(data);
    b.resize((b.len() + 7) & !7, 0);
    b
}

fn fds_bytes(fds: &[u64]) -> Vec<u8> {
    fds.iter().flat_map(|&f| (f as i32).to_le_bytes()).collect()
}

/// `sendmsg` of `data` with control data `ctl` on `fd`.
fn sendmsg(h: &mut Harness, fd: u64, data: &[u8], ctl: &[u8], flags: u64, m: u64) -> i64 {
    put(h, m + 0x1000, data);
    iovec(h, m + 0x900, m + 0x1000, data.len() as u64);
    put(h, m + 0xa00, ctl);
    let c = if ctl.is_empty() { 0 } else { m + 0xa00 };
    msghdr(h, m + 0x800, 0, 0, m + 0x900, 1, c, ctl.len() as u64);
    h.call(Sysno::Sendmsg, &[fd, m + 0x800, flags])
}

/// `recvmsg` on `fd` into 64 bytes with `room` bytes of control space:
/// `(result, data, control, msg_flags)`.
fn recvmsg(
    h: &mut Harness,
    fd: u64,
    room: u64,
    flags: u64,
    m: u64,
) -> (i64, Vec<u8>, Vec<u8>, u32) {
    iovec(h, m + 0x900, m + 0x1000, 64);
    put(h, m + 0xa00, &[0u8; 512]);
    let c = if room == u64::MAX { 0 } else { m + 0xa00 };
    msghdr(h, m + 0x800, 0, 0, m + 0x900, 1, c, room.min(512));
    let r = h.call(Sysno::Recvmsg, &[fd, m + 0x800, flags]);
    if r < 0 {
        return (r, Vec::new(), Vec::new(), 0);
    }
    let clen = u64_at(h, m + 0x800 + 40) as usize;
    (
        r,
        get(h, m + 0x1000, (r as usize).min(64)),
        get(h, m + 0xa00, clen),
        u32_at(h, m + 0x800 + 48),
    )
}

#[test]
fn message_headers_are_checked_as_copy_msghdr_does() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (a, b) = pair(&mut h, DGRAM, m);
        // MSG_CMSG_COMPAT is 0 without CONFIG_COMPAT: an ordinary bit.
        assert_eq!(h.err(Sysno::Recvmsg, &[a, 0x10, MSG_CMSG_COMPAT]), EFAULT);
        assert_eq!(h.err(Sysno::Sendmsg, &[99, m, 0]), EBADF);
        assert_eq!(h.err(Sysno::Sendmsg, &[1, m, 0]), ENOTSOCK);
        assert_eq!(h.err(Sysno::Sendmsg, &[a, 0x10, 0]), EFAULT);
        // A negative name length (with a name), too many vectors, too much
        // control data.
        msghdr(&h, m, m + 0x100, u32::MAX, m + 0x200, 1, 0, 0);
        assert_eq!(h.err(Sysno::Sendmsg, &[a, m, 0]), EINVAL);
        msghdr(&h, m, 0, 0, m + 0x200, 1025, 0, 0);
        assert_eq!(h.err(Sysno::Sendmsg, &[a, m, 0]), EMSGSIZE);
        iovec(&h, m + 0x200, m + 0x300, 1);
        msghdr(&h, m, 0, 0, m + 0x200, 1, m + 0x400, 1 << 31);
        assert_eq!(h.err(Sysno::Sendmsg, &[a, m, 0]), ENOBUFS);
        // A truncated datagram: MSG_TRUNC in msg_flags, the requested
        // MSG_CMSG_CLOEXEC echoed, no control data.
        assert_eq!(send(&mut h, a, &[7u8; 100], 0, m), 100);
        let (r, data, ctl, flags) = recvmsg(&mut h, b, 0, MSG_CMSG_CLOEXEC, m);
        assert_eq!((r, data.len(), ctl.len()), (64, 64, 0), "{abi:?}");
        assert_eq!(flags, 0x20 | 0x4000_0000);
        // MSG_TRUNC asked for: the datagram's whole length.
        assert_eq!(send(&mut h, a, &[7u8; 100], 0, m), 100);
        assert_eq!(h.call(Sysno::Recvfrom, &[b, m, 10, MSG_TRUNC, 0, 0]), 100);
        // MSG_PEEK leaves it.
        assert_eq!(send(&mut h, a, b"abc", 0, m), 3);
        assert_eq!(recv(&mut h, b, 8, MSG_PEEK, m).unwrap(), b"abc");
        assert_eq!(recv(&mut h, b, 8, 0, m).unwrap(), b"abc");
        assert_eq!(recv(&mut h, b, 8, MSG_DONTWAIT, m), Err(EAGAIN));
    });
}

#[test]
fn descriptors_pass_as_scm_detach_fds_installs_them() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (a, b) = pair(&mut h, STREAM, m);
        h.ok(Sysno::Pipe2, &[m, 0]);
        let (pr, pw) = (u64::from(u32_at(&h, m)), u64::from(u32_at(&h, m + 4)));
        let ev = h.ok(Sysno::Eventfd2, &[5, 0]);
        // Two descriptors, room for one (CMSG_LEN(4)): one installed, the
        // other closed, MSG_CTRUNC.
        let ctl = cmsg(1, SCM_RIGHTS, &fds_bytes(&[pw, ev]));
        assert_eq!(sendmsg(&mut h, a, b"x", &ctl, 0, m), 1);
        let (r, data, got, flags) = recvmsg(&mut h, b, 20, MSG_CMSG_CLOEXEC, m);
        assert_eq!((r, data.as_slice()), (1, b"x".as_slice()));
        assert_eq!(got.len(), 20, "{abi:?}");
        assert_eq!(u64::from_le_bytes(got[..8].try_into().unwrap()), 20);
        assert_eq!(
            i32::from_le_bytes(got[12..16].try_into().unwrap()),
            SCM_RIGHTS
        );
        assert_ne!(flags & MSG_CTRUNC, 0);
        let fd = u64::from(u32::from_le_bytes(got[16..20].try_into().unwrap()));
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, 1, 0]), 1, "MSG_CMSG_CLOEXEC");
        // The same pipe: written through the received descriptor.
        put(&h, m, b"z");
        assert_eq!(h.ok(Sysno::Write, &[fd, m, 1]), 1);
        assert_eq!(h.ok(Sysno::Read, &[pr, m + 8, 1]), 1);
        assert_eq!(get(&h, m + 8, 1), b"z");
        // Within the process, the same description: its status flags are
        // shared (an eventfd, which has no host descriptor, too).
        let ctl = cmsg(1, SCM_RIGHTS, &fds_bytes(&[ev]));
        assert_eq!(sendmsg(&mut h, a, b"y", &ctl, 0, m), 1);
        let (_, _, got, flags) = recvmsg(&mut h, b, 64, 0, m);
        assert_eq!(flags & MSG_CTRUNC, 0);
        let ev2 = u64::from(u32::from_le_bytes(got[16..20].try_into().unwrap()));
        h.ok(Sysno::Fcntl, &[ev2, 4, NONBLOCK]);
        assert_eq!(h.ok(Sysno::Fcntl, &[ev, 3, 0]) & NONBLOCK, NONBLOCK);
        assert_eq!(h.ok(Sysno::Read, &[ev2, m, 8]), 8);
        assert_eq!(u64_at(&h, m), 5);
        // A null control pointer takes nothing: MSG_CTRUNC, and the
        // descriptor is not installed.
        let ctl = cmsg(1, SCM_RIGHTS, &fds_bytes(&[pr]));
        assert_eq!(sendmsg(&mut h, a, b"w", &ctl, 0, m), 1);
        let next = sock(&mut h, AF_UNIX, STREAM);
        h.ok(Sysno::Close, &[next]);
        let (r, _, got, flags) = recvmsg(&mut h, b, u64::MAX, 0, m);
        assert_eq!((r, got.len()), (1, 0));
        assert_ne!(flags & MSG_CTRUNC, 0);
        assert_eq!(sock(&mut h, AF_UNIX, STREAM), next, "nothing installed");
        // Refused control data.
        let bad = cmsg(1, SCM_RIGHTS, &fds_bytes(&[999]));
        assert_eq!(sendmsg(&mut h, a, b"v", &bad, 0, m), -(EBADF as i64));
        let many = cmsg(1, SCM_RIGHTS, &fds_bytes(&[pr; 254]));
        assert_eq!(sendmsg(&mut h, a, b"v", &many, 0, m), -(EINVAL as i64));
        let mut short = cmsg(1, SCM_RIGHTS, &fds_bytes(&[pr]));
        short[..8].copy_from_slice(&15u64.to_le_bytes());
        assert_eq!(sendmsg(&mut h, a, b"v", &short, 0, m), -(EINVAL as i64));
        let unknown = cmsg(1, 99, &[0; 4]);
        assert_eq!(sendmsg(&mut h, a, b"v", &unknown, 0, m), -(EINVAL as i64));
        // Another level is ignored by a Unix socket.
        let other = cmsg(0, 1, &[0; 4]);
        assert_eq!(sendmsg(&mut h, a, b"v", &other, 0, m), 1);
        assert_eq!(recv(&mut h, b, 8, 0, m).unwrap(), b"v");
        // An IP socket passed within the process is the same host socket
        // (Darwin gives IP sockets no inode to recognize the description
        // by).
        let ip = sock(&mut h, AF_INET, DGRAM);
        assert_eq!(bind(&mut h, ip, &sin(0), m), 0);
        let port = port_of(&mut h, ip, m);
        let ctl = cmsg(1, SCM_RIGHTS, &fds_bytes(&[ip]));
        assert_eq!(sendmsg(&mut h, a, b"i", &ctl, 0, m), 1);
        let (_, _, got, _) = recvmsg(&mut h, b, 64, 0, m);
        let ip2 = u64::from(u32::from_le_bytes(got[16..20].try_into().unwrap()));
        assert_eq!(port_of(&mut h, ip2, m), port);
        assert_eq!(opt_int(&mut h, ip2, SOL_SOCKET, SO_TYPE, m), 2);
        // SCM_RIGHTS on an IP socket is EINVAL.
        let u = sock(&mut h, AF_INET, DGRAM);
        let ctl = cmsg(1, SCM_RIGHTS, &fds_bytes(&[pr]));
        assert_eq!(sendmsg(&mut h, u, b"v", &ctl, 0, m), -(EINVAL as i64));
    });
}

#[test]
fn credentials_are_checked_and_delivered_with_so_passcred() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (a, b) = pair(&mut h, DGRAM, m);
        let pid = h.proc.state.pid;
        let (uid, gid) = (h.proc.state.creds.0, h.proc.state.creds.2);
        let creds = |p: i32, u: u32, g: u32| {
            let mut d = p.to_le_bytes().to_vec();
            d.extend_from_slice(&u.to_le_bytes());
            d.extend_from_slice(&g.to_le_bytes());
            d
        };
        if h.proc.state.creds.1 != 0 {
            let other = cmsg(1, SCM_CREDENTIALS, &creds(pid + 1, uid, gid));
            assert_eq!(sendmsg(&mut h, a, b"c", &other, 0, m), -(EPERM as i64));
        }
        let invalid = cmsg(1, SCM_CREDENTIALS, &creds(pid, u32::MAX, gid));
        assert_eq!(sendmsg(&mut h, a, b"c", &invalid, 0, m), -(EINVAL as i64));
        let short = cmsg(1, SCM_CREDENTIALS, &creds(pid, uid, gid)[..8]);
        assert_eq!(sendmsg(&mut h, a, b"c", &short, 0, m), -(EINVAL as i64));
        let own = cmsg(1, SCM_CREDENTIALS, &creds(pid, uid, gid));
        assert_eq!(sendmsg(&mut h, a, b"c", &own, 0, m), 1);
        // Without SO_PASSCRED, no credentials.
        let (_, _, got, _) = recvmsg(&mut h, b, 64, 0, m);
        assert!(got.is_empty());
        // With it, the peer's.
        assert_eq!(setopt_int(&mut h, b, SOL_SOCKET, SO_PASSCRED, 1, m), 0);
        assert_eq!(opt_int(&mut h, b, SOL_SOCKET, SO_PASSCRED, m), 1);
        assert_eq!(send(&mut h, a, b"d", 0, m), 1);
        let (_, _, got, _) = recvmsg(&mut h, b, 64, 0, m);
        assert_eq!(got.len(), 32, "{abi:?}");
        assert_eq!(
            i32::from_le_bytes(got[12..16].try_into().unwrap()),
            SCM_CREDENTIALS
        );
        let host_pid = std::process::id() as i32;
        // SAFETY: getuid and getgid cannot fail.
        let (hu, hg) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(got[16..28], creds(host_pid, hu, hg)[..]);
        // IP sockets have no SO_PASSCRED.
        let u = sock(&mut h, AF_INET, DGRAM);
        assert_eq!(
            setopt_int(&mut h, u, SOL_SOCKET, SO_PASSCRED, 1, m),
            -(EOPNOTSUPP as i64)
        );
        assert_eq!(
            getopt(&mut h, u, SOL_SOCKET, SO_PASSCRED, 4, m),
            Err(EOPNOTSUPP)
        );
    });
}

#[test]
fn blocking_calls_end_by_timeout_or_signal() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (_a, b) = pair(&mut h, STREAM, m);
        // SO_RCVTIMEO: EAGAIN once it passes.
        assert_eq!(
            setopt(&mut h, b, SOL_SOCKET, SO_RCVTIMEO, &timeval_ms(30), m),
            0
        );
        let start = Instant::now();
        assert_eq!(recv(&mut h, b, 8, 0, m), Err(EAGAIN));
        assert!(start.elapsed() >= Duration::from_millis(25), "{abi:?}");
        // A signal: EINTR with a timeout set, -ERESTARTSYS without.
        raise(&mut h, SIGUSR1);
        assert_eq!(recv(&mut h, b, 8, 0, m), Err(EINTR));
        unraise(&mut h);
        let (_c, d) = pair(&mut h, STREAM, m);
        raise(&mut h, SIGUSR1);
        assert_eq!(recv(&mut h, d, 8, 0, m), Err(ERESTARTSYS));
        unraise(&mut h);
        // A negative timeout never waits, and reads back as none.
        let neg = [(-1i64).to_le_bytes(), 0i64.to_le_bytes()].concat();
        assert_eq!(setopt(&mut h, d, SOL_SOCKET, SO_RCVTIMEO, &neg, m), 0);
        assert_eq!(recv(&mut h, d, 8, 0, m), Err(EAGAIN));
        assert_eq!(
            getopt(&mut h, d, SOL_SOCKET, SO_RCVTIMEO, 16, m).unwrap(),
            [0u8; 16]
        );
        // accept waits for a connection until the receive timeout.
        let (l, _) = listener(&mut h, m);
        assert_eq!(
            setopt(&mut h, l, SOL_SOCKET, SO_RCVTIMEO, &timeval_ms(20), m),
            0
        );
        assert_eq!(h.err(Sysno::Accept4, &[l, 0, 0, 0]), EAGAIN);
        // Without data or a timeout the thread sleeps.
        let (_e, f) = pair(&mut h, DGRAM, m);
        assert_eq!(h.start(0, Sysno::Recvfrom, &[f, m, 8, 0, 0, 0]), None);
    });
}

#[test]
fn options_follow_sk_setsockopt_and_sk_getsockopt() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let admin = h.proc.state.creds.1 == 0;
        let u = sock(&mut h, AF_INET, DGRAM);
        // An int at least; microseconds in range; a timeval at least.
        assert_eq!(
            setopt(&mut h, u, SOL_SOCKET, SO_REUSEADDR, &[1, 0, 0], m),
            -(EINVAL as i64)
        );
        assert_eq!(
            setopt(&mut h, u, SOL_SOCKET, 12345, &[1, 0, 0], m),
            -(EINVAL as i64)
        );
        let bad = [0i64.to_le_bytes(), 1_000_000i64.to_le_bytes()].concat();
        assert_eq!(
            setopt(&mut h, u, SOL_SOCKET, SO_RCVTIMEO, &bad, m),
            -(EDOM as i64)
        );
        assert_eq!(
            setopt(&mut h, u, SOL_SOCKET, SO_RCVTIMEO, &bad[..8], m),
            -(EINVAL as i64)
        );
        assert_eq!(
            h.err(
                Sysno::Setsockopt,
                &[u, SOL_SOCKET, SO_REUSEADDR, m, u64::MAX]
            ),
            EINVAL
        );
        // Booleans read back as 0 or 1.
        assert_eq!(setopt_int(&mut h, u, SOL_SOCKET, SO_REUSEADDR, 5, m), 0);
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_REUSEADDR, m), 1);
        // A short buffer takes the start of the value; a negative length is
        // EINVAL.
        assert_eq!(
            getopt(&mut h, u, SOL_SOCKET, SO_TYPE, 2, m).unwrap(),
            [2, 0]
        );
        assert_eq!(
            getopt(&mut h, u, SOL_SOCKET, SO_TYPE, u32::MAX, m),
            Err(EINVAL)
        );
        // Read-only and unknown options.
        assert_eq!(
            setopt_int(&mut h, u, SOL_SOCKET, SO_TYPE, 1, m),
            -(ENOPROTOOPT as i64)
        );
        assert_eq!(
            setopt_int(&mut h, u, SOL_SOCKET, SO_ACCEPTCONN, 1, m),
            -(ENOPROTOOPT as i64)
        );
        assert_eq!(getopt(&mut h, u, SOL_SOCKET, 12345, 4, m), Err(ENOPROTOOPT));
        // Privileges.
        if !admin {
            assert_eq!(
                setopt_int(&mut h, u, SOL_SOCKET, SO_PRIORITY, 7, m),
                -(EPERM as i64)
            );
            assert_eq!(
                setopt_int(&mut h, u, SOL_SOCKET, SO_DEBUG, 1, m),
                -(EACCES as i64)
            );
            assert_eq!(
                setopt_int(&mut h, u, SOL_SOCKET, SO_RCVBUFFORCE, 1, m),
                -(EPERM as i64)
            );
        }
        assert_eq!(setopt_int(&mut h, u, SOL_SOCKET, SO_PRIORITY, 3, m), 0);
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_PRIORITY, m), 3);
        assert_eq!(setopt_int(&mut h, u, SOL_SOCKET, SO_DEBUG, 0, m), 0);
        // Buffer sizes: Linux's defaults, doubled, capped, at least the
        // minimum.
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_RCVBUF, m), 212_992);
        assert_eq!(setopt_int(&mut h, u, SOL_SOCKET, SO_RCVBUF, -1, m), 0);
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_RCVBUF, m), 425_984);
        assert_eq!(setopt_int(&mut h, u, SOL_SOCKET, SO_SNDBUF, 0, m), 0);
        assert_eq!(opt_int(&mut h, u, SOL_SOCKET, SO_SNDBUF, m), 4608);
        // Levels: another protocol's is EOPNOTSUPP, an unknown option of
        // the protocol's own ENOPROTOOPT; SOL_UDP options are kept.
        assert_eq!(getopt(&mut h, u, 6, 1, 4, m), Err(EOPNOTSUPP));
        assert_eq!(setopt_int(&mut h, u, 17, 1, 1, m), 0);
        assert_eq!(opt_int(&mut h, u, 17, 1, m), 1);
        assert_eq!(getopt(&mut h, u, 17, 99, 4, m), Err(ENOPROTOOPT));
        // IP byte options read back as a byte into a short buffer.
        assert_eq!(setopt_int(&mut h, u, 0, 2, 33, m), 0);
        assert_eq!(getopt(&mut h, u, 0, 2, 1, m).unwrap(), [33]);
        // No peer: PID 0, IDs of -1.
        let v = getopt(&mut h, u, SOL_SOCKET, SO_PEERCRED, 12, m).unwrap();
        assert_eq!(
            v,
            [0u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        // Cookies differ.
        let w = sock(&mut h, AF_INET, DGRAM);
        let c1 = getopt(&mut h, u, SOL_SOCKET, SO_COOKIE, 8, m).unwrap();
        let c2 = getopt(&mut h, w, SOL_SOCKET, SO_COOKIE, 8, m).unwrap();
        assert_ne!(c1, c2);
        // TCP: defaults, SO_LINGER, unknown options, and an accepted
        // socket inheriting the listener's timeout.
        let (l, port) = listener(&mut h, m);
        assert_eq!(opt_int(&mut h, l, SOL_SOCKET, SO_ACCEPTCONN, m), 1);
        let t = sock(&mut h, AF_INET, STREAM);
        assert_eq!(opt_int(&mut h, t, SOL_SOCKET, SO_ACCEPTCONN, m), 0);
        assert_eq!(opt_int(&mut h, t, SOL_SOCKET, SO_RCVBUF, m), 131_072);
        assert_eq!(opt_int(&mut h, t, SOL_SOCKET, SO_SNDBUF, m), 16_384);
        assert_eq!(getopt(&mut h, t, 6, 99, 4, m), Err(ENOPROTOOPT));
        let linger = [1i32.to_le_bytes(), 5i32.to_le_bytes()].concat();
        assert_eq!(setopt(&mut h, t, SOL_SOCKET, SO_LINGER, &linger, m), 0);
        assert_eq!(
            getopt(&mut h, t, SOL_SOCKET, SO_LINGER, 8, m).unwrap()[4..],
            5i32.to_le_bytes()
        );
        assert_eq!(
            setopt(&mut h, l, SOL_SOCKET, SO_RCVTIMEO, &timeval_ms(1500), m),
            0
        );
        assert_eq!(connect(&mut h, t, &sin(port), m), 0);
        let s = h.ok(Sysno::Accept4, &[l, 0, 0, 0]);
        assert_eq!(
            getopt(&mut h, s, SOL_SOCKET, SO_RCVTIMEO, 16, m).unwrap(),
            timeval_ms(1500)
        );
        // SO_REUSEPORT is for IP sockets.
        let x = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(
            setopt_int(&mut h, x, SOL_SOCKET, SO_REUSEPORT, 1, m),
            -(EOPNOTSUPP as i64)
        );
        // Unix sockets have only SOL_SOCKET.
        assert_eq!(getopt(&mut h, x, 0, 2, 4, m), Err(EOPNOTSUPP));
    });
}

#[test]
fn sigpipe_follows_the_protocol() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        handle(&mut h, SIGPIPE);
        let pending = |h: &Harness| h.proc.threads[0].pending.contains(SIGPIPE);
        let clear = |h: &mut Harness| h.proc.threads[0].pending = SigPending::new();
        // A Unix stream: SIGPIPE, unless MSG_NOSIGNAL; write() too.
        let (a, _b) = pair(&mut h, STREAM, m);
        h.ok(Sysno::Shutdown, &[a, 1]);
        assert_eq!(send(&mut h, a, b"x", MSG_NOSIGNAL, m), -(EPIPE as i64));
        assert!(!pending(&h), "{abi:?}");
        assert_eq!(send(&mut h, a, b"x", 0, m), -(EPIPE as i64));
        assert!(pending(&h));
        clear(&mut h);
        put(&h, m, b"x");
        assert_eq!(h.call(Sysno::Write, &[a, m, 1]), -(EPIPE as i64));
        assert!(pending(&h));
        clear(&mut h);
        // A Unix datagram socket: EPIPE without SIGPIPE, even by write().
        let (d, _e) = pair(&mut h, DGRAM, m);
        h.ok(Sysno::Shutdown, &[d, 1]);
        assert_eq!(send(&mut h, d, b"x", 0, m), -(EPIPE as i64));
        assert_eq!(h.call(Sysno::Write, &[d, m, 1]), -(EPIPE as i64));
        assert!(!pending(&h), "{abi:?}: datagram");
        // TCP without a connection: EPIPE and SIGPIPE.
        let t = sock(&mut h, AF_INET, STREAM);
        assert_eq!(send(&mut h, t, b"x", 0, m), -(EPIPE as i64));
        assert!(pending(&h));
        clear(&mut h);
        // Shutdown's how; a Unix socket without a peer shuts down.
        assert_eq!(h.err(Sysno::Shutdown, &[a, 3]), EINVAL);
        assert_eq!(h.err(Sysno::Shutdown, &[a, u64::MAX]), EINVAL);
        let lone = sock(&mut h, AF_UNIX, STREAM);
        assert_eq!(h.ok(Sysno::Shutdown, &[lone, 2]), 0);
        assert_eq!(h.err(Sysno::Shutdown, &[t, 2]), ENOTCONN);
        // A Unix stream without a connection: EINVAL to receive, ENOTCONN
        // to send; a Unix datagram socket without a peer: ENOTCONN.
        assert_eq!(recv(&mut h, lone, 1, MSG_DONTWAIT, m), Err(EINVAL));
        let ud = sock(&mut h, AF_UNIX, DGRAM);
        assert_eq!(send(&mut h, ud, b"x", 0, m), -(ENOTCONN as i64));
        // A destination on a Unix stream.
        let (p, l) = addr(&h, m + 0x200, &sun(b"/nowhere"));
        put(&h, m, b"x");
        assert_eq!(
            h.call(Sysno::Sendto, &[lone, m, 1, 0, p, l]),
            -(EOPNOTSUPP as i64)
        );
        let (s1, _s2) = pair(&mut h, STREAM, m);
        assert_eq!(
            h.call(Sysno::Sendto, &[s1, m, 1, 0, p, l]),
            -(EISCONN as i64)
        );
    });
}

/// Writes `n` `struct mmsghdr` at `at`, message `i` of `lens[i]` bytes at
/// `buf + 0x100 * i`.
fn mmsghdrs(h: &Harness, at: u64, buf: u64, lens: &[u64]) {
    for (i, &len) in lens.iter().enumerate() {
        let i = i as u64;
        let iov = at + 0x800 + 16 * i;
        iovec(h, iov, buf + 0x100 * i, len);
        msghdr(h, at + 64 * i, 0, 0, iov, 1, 0, 0);
        put(h, at + 64 * i + 56, &[0xff; 8]);
    }
}

#[test]
fn batches_send_and_receive_until_done() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let (a, b) = pair(&mut h, DGRAM, m);
        let vec = m + 0x2000;
        let buf = m + 0x4000;
        put(&h, buf, b"a");
        put(&h, buf + 0x100, b"bb");
        put(&h, buf + 0x200, b"ccc");
        mmsghdrs(&h, vec, buf, &[1, 2, 3]);
        assert_eq!(h.ok(Sysno::Sendmmsg, &[a, vec, 3, 0]), 3);
        assert_eq!(
            (0..3)
                .map(|i| u32_at(&h, vec + 64 * i + 56))
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(h.ok(Sysno::Sendmmsg, &[a, vec, 0, 0]), 0);
        // All three, with room for five, without waiting.
        mmsghdrs(&h, vec, buf + 0x1000, &[16; 5]);
        assert_eq!(h.ok(Sysno::Recvmmsg, &[b, vec, 5, MSG_DONTWAIT, 0]), 3);
        assert_eq!(
            (0..3)
                .map(|i| u32_at(&h, vec + 64 * i + 56))
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(get(&h, buf + 0x1200, 3), b"ccc");
        assert_eq!(
            h.err(Sysno::Recvmmsg, &[b, vec, 5, MSG_DONTWAIT, 0]),
            EAGAIN
        );
        // MSG_WAITFORONE: after the first, no waiting.
        assert_eq!(send(&mut h, a, b"q", 0, m), 1);
        assert_eq!(h.ok(Sysno::Recvmmsg, &[b, vec, 3, MSG_WAITFORONE, 0]), 1);
        // An invalid timeout; a valid one written back.
        let ts = m + 0x100;
        put(
            &h,
            ts,
            &[0i64.to_le_bytes(), 1_000_000_000i64.to_le_bytes()].concat(),
        );
        assert_eq!(h.err(Sysno::Recvmmsg, &[b, vec, 1, 0, ts]), EINVAL);
        assert_eq!(send(&mut h, a, b"r", 0, m), 1);
        put(&h, ts, &[5i64.to_le_bytes(), 0i64.to_le_bytes()].concat());
        assert_eq!(h.ok(Sysno::Recvmmsg, &[b, vec, 1, 0, ts]), 1);
        let left = u64_at(&h, ts);
        assert!(left <= 5, "{left}");
        assert_eq!(
            h.err(
                Sysno::Recvmmsg,
                &[b, vec, 1, MSG_CMSG_COMPAT | MSG_DONTWAIT, 0]
            ),
            EAGAIN
        );
    });
}

/// `revents` of one descriptor from a non-blocking `ppoll`.
fn poll_one(h: &mut Harness, fd: u64, events: u16, m: u64) -> u16 {
    let mut rec = [0u8; 8];
    rec[..4].copy_from_slice(&(fd as i32).to_le_bytes());
    rec[4..6].copy_from_slice(&events.to_le_bytes());
    put(h, m, &rec);
    put(h, m + 0x40, &[0u8; 16]);
    h.ok(Sysno::Ppoll, &[m, 1, m + 0x40, 0, 8]);
    u16::from_le_bytes(get(h, m + 6, 2).try_into().unwrap())
}

#[test]
fn sockets_poll_and_answer_their_ioctls() {
    const IN: u16 = 0x1;
    const OUT: u16 = 0x4;
    const RDNORM: u16 = 0x40;
    const RDHUP: u16 = 0x2000;
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        // A listener is readable with a connection waiting.
        let (l, port) = listener(&mut h, m);
        assert_eq!(poll_one(&mut h, l, IN, m) & IN, 0);
        let c = sock(&mut h, AF_INET, STREAM);
        assert_eq!(connect(&mut h, c, &sin(port), m), 0);
        let start = Instant::now();
        while poll_one(&mut h, l, IN, m) & IN == 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
        }
        // A Unix stream whose peer shut down writing: readable and hung up
        // for reading.
        let (a, b) = pair(&mut h, STREAM, m);
        assert_eq!(poll_one(&mut h, b, IN | OUT | RDHUP, m), OUT);
        h.ok(Sysno::Shutdown, &[a, 1]);
        assert_eq!(poll_one(&mut h, b, IN | RDHUP, m), IN | RDHUP, "{abi:?}");
        assert_eq!(poll_one(&mut h, b, RDNORM, m), RDNORM);
        // SIOCINQ: a stream's bytes, a datagram socket's next datagram.
        let (x, y) = pair(&mut h, STREAM, m);
        assert_eq!(send(&mut h, x, b"abcde", 0, m), 5);
        h.ok(Sysno::Ioctl, &[y, 0x541B, m + 0x400]);
        assert_eq!(u32_at(&h, m + 0x400), 5);
        let (d, e) = pair(&mut h, DGRAM, m);
        assert_eq!(send(&mut h, d, b"12", 0, m), 2);
        assert_eq!(send(&mut h, d, b"345", 0, m), 3);
        h.ok(Sysno::Ioctl, &[e, 0x541B, m + 0x400]);
        assert_eq!(u32_at(&h, m + 0x400), 2);
        // A listening TCP socket has none; interfaces are unknown;
        // terminal requests are not socket ones.
        assert_eq!(h.err(Sysno::Ioctl, &[l, 0x541B, m + 0x400]), EINVAL);
        assert_eq!(h.err(Sysno::Ioctl, &[e, 0x8933, m + 0x400]), ENODEV);
        assert_eq!(h.err(Sysno::Ioctl, &[e, 0x5401, m + 0x400]), ENOTTY);
        // FIONBIO sets O_NONBLOCK.
        put(&h, m + 0x400, &1u32.to_le_bytes());
        h.ok(Sysno::Ioctl, &[e, 0x5421, m + 0x400]);
        assert_eq!(h.ok(Sysno::Fcntl, &[e, 3, 0]) & NONBLOCK, NONBLOCK);
    });
}

#[test]
fn ipv6_loopback_carries_whole_addresses() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = area(&mut h);
        let v6 = |port: u16| {
            let mut b = vec![0u8; 28];
            b[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[23] = 1;
            b
        };
        let l = sock(&mut h, AF_INET6, STREAM);
        match bind(&mut h, l, &v6(0), m) {
            0 => {}
            // A host without IPv6 loopback.
            e if e == -(EADDRNOTAVAIL as i64) || e == -(EAFNOSUPPORT as i64) => return,
            e => panic!("bind ::1: {e}"),
        }
        assert_eq!(bind(&mut h, l, &v6(0)[..23], m), -(EINVAL as i64));
        let n = name(&mut h, l, false, m).unwrap();
        assert_eq!(n.len(), 28);
        assert_eq!(n[..2], (AF_INET6 as u16).to_le_bytes());
        let port = u16::from_be_bytes([n[2], n[3]]);
        h.ok(Sysno::Listen, &[l, 1]);
        // tcp_v6_connect: the IPv6 size, then the family.
        let c = sock(&mut h, AF_INET6, STREAM);
        assert_eq!(connect(&mut h, c, &sin(port), m), -(EINVAL as i64));
        let mut v4_long = sin(port);
        v4_long.resize(28, 0);
        assert_eq!(connect(&mut h, c, &v4_long, m), -(EAFNOSUPPORT as i64));
        assert_eq!(connect(&mut h, c, &v6(port), m), 0);
        let s = h.ok(Sysno::Accept4, &[l, 0, 0, 0]);
        assert_eq!(send(&mut h, c, b"six", 0, m), 3);
        assert_eq!(recv(&mut h, s, 8, 0, m).unwrap(), b"six");
    });
}
