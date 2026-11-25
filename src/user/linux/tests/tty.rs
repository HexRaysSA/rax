use super::harness::Harness;
use crate::user::linux::abi::errno_table::EFAULT;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AT_FDCWD: u64 = -100i64 as u64;
const O_RDWR: u64 = 2;
const O_NOCTTY: u64 = 0x100;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;

#[test]
fn pty_window_size_round_trips_through_guest_ioctls() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let path = h.scratch;
    let requested = path + 0x100;
    let actual = path + 0x200;
    h.proc.state.space.write_raw(path, b"/dev/ptmx\0").unwrap();
    let fd = h.ok(Sysno::Openat, &[AT_FDCWD, path, O_RDWR | O_NOCTTY, 0]) as u64;
    let size = [37u16, 91, 123, 456];
    let bytes: Vec<u8> = size.iter().flat_map(|v| v.to_le_bytes()).collect();
    h.proc.state.space.write_raw(requested, &bytes).unwrap();

    h.ok(Sysno::Ioctl, &[fd, TIOCSWINSZ, requested]);
    h.proc.state.space.write_raw(actual, &[0; 8]).unwrap();
    h.ok(Sysno::Ioctl, &[fd, TIOCGWINSZ, actual]);
    let mut observed = [0u8; 8];
    h.proc.state.space.read_raw(actual, &mut observed).unwrap();
    assert_eq!(observed.as_slice(), bytes);

    assert_eq!(h.err(Sysno::Ioctl, &[fd, TIOCSWINSZ, 0x10]), EFAULT);
    h.proc.state.space.write_raw(actual, &[0; 8]).unwrap();
    h.ok(Sysno::Ioctl, &[fd, TIOCGWINSZ, actual]);
    h.proc.state.space.read_raw(actual, &mut observed).unwrap();
    assert_eq!(observed.as_slice(), bytes);
    h.ok(Sysno::Close, &[fd]);
}
