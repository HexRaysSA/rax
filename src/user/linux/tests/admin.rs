//! Machine administration and clock setting (Linux 6.19): each call's
//! checks in the kernel's order, `EPERM` at the capability check for an
//! unprivileged caller, and for root the checks after it and then
//! `EOPNOTSUPP` for the change (`mm/swapfile.c`, `kernel/reboot.c`,
//! `kernel/acct.c`, `kernel/sys.c`, `fs/open.c`,
//! `arch/x86/kernel/ioport.c`, `kernel/module/main.c`,
//! `kernel/printk/printk.c`, `kernel/time/time.c`,
//! `kernel/time/posix-timers.c`, `kernel/time/timekeeping.c`,
//! `kernel/time/ntp.c`).

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::restart::ERESTARTSYS;

const NOBODY: u32 = 65534;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;
const AT_FDCWD: u64 = -100i64 as u64;

fn creds(h: &mut Harness, id: u32) {
    h.proc.state.creds = (id, id, id, id);
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn cstr(h: &Harness, at: u64, s: &str) -> u64 {
    put(h, at, &[s.as_bytes(), &[0]].concat());
    at
}

fn words(h: &Harness, at: u64, w: &[i64]) -> u64 {
    let b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
    put(h, at, &b);
    at
}

fn bytes(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

/// A host file outside the guest's view of any directory it could search.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, abi: LinuxAbi) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-user-admin-{}-{name}-{abi:?}",
            std::process::id()
        ));
        std::fs::write(&p, b"x").unwrap();
        TempFile(p)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// `linux/reboot.h`.
const MAGIC1: u64 = 0xfee1_dead;
const MAGIC2: u64 = 672_274_793;
const MAGIC2C: u64 = 537_993_216;
const CMD_POWER_OFF: u64 = 0x4321_fedc;
const CMD_RESTART2: u64 = 0xa1b2_c3d4;
const CMD_CAD_OFF: u64 = 0;
const CMD_KEXEC: u64 = 0x4558_4543;

#[test]
fn an_unprivileged_caller_fails_each_call_at_its_capability_check() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(4 * P, 3, false);
        let slash = cstr(&h, m, "/");
        // swapon checks its flags first (SWAP_FLAGS_VALID is 0x7ffff).
        assert_eq!(h.err(Sysno::Swapon, &[slash, 0x8_0000]), EINVAL);
        assert_eq!(h.err(Sysno::Swapon, &[slash, 0x7_ffff]), EPERM);
        assert_eq!(
            h.err(Sysno::Swapon, &[BAD, u64::from(u32::MAX >> 13)]),
            EPERM
        );
        // The rest check the capability before any argument.
        assert_eq!(h.err(Sysno::Swapoff, &[BAD]), EPERM);
        assert_eq!(h.err(Sysno::Reboot, &[0, 0, 0, BAD]), EPERM);
        assert_eq!(h.err(Sysno::Acct, &[BAD]), EPERM);
        assert_eq!(h.err(Sysno::Acct, &[0]), EPERM);
        for s in [Sysno::Sethostname, Sysno::Setdomainname] {
            assert_eq!(h.err(s, &[BAD, u64::MAX]), EPERM);
        }
        assert_eq!(h.err(Sysno::Vhangup, &[]), EPERM);
        assert_eq!(h.err(Sysno::InitModule, &[BAD, 0, BAD]), EPERM);
        assert_eq!(h.err(Sysno::FinitModule, &[u64::MAX, BAD, u64::MAX]), EPERM);
        assert_eq!(h.err(Sysno::DeleteModule, &[BAD, 0]), EPERM);
        // dmesg_restrict: every action, a bad one too.
        for action in [0, 3, 10, 99, u64::MAX] {
            assert_eq!(h.err(Sysno::Syslog, &[action, BAD, 0]), EPERM);
        }
        // Without kexec in the kernel.
        assert_eq!(h.err(Sysno::KexecLoad, &[0, 0, 0, 0]), ENOSYS);
        assert_eq!(h.err(Sysno::KexecFileLoad, &[0, 0, 0, 0, 0]), ENOSYS);
    });
}

#[test]
fn root_passes_the_capability_check_and_is_refused_the_change() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, 0);
        let m = h.anon(4 * P, 3, false);
        // [m, m + 3 pages) mapped, the page after it not.
        h.ok(Sysno::Munmap, &[m + 3 * P, P]);
        let slash = cstr(&h, m, "/");
        assert_eq!(h.err(Sysno::Swapon, &[slash, 0x8_0000]), EINVAL);
        assert_eq!(h.err(Sysno::Swapon, &[slash, 0]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::Swapoff, &[slash]), EOPNOTSUPP);
        // reboot: the magic numbers, then the command.
        assert_eq!(h.err(Sysno::Reboot, &[0, MAGIC2, CMD_POWER_OFF, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Reboot, &[MAGIC1, 1, CMD_POWER_OFF, 0]), EINVAL);
        // The magic numbers are ints: the upper halves do not matter.
        let hi = 0xffff_ffff_0000_0000;
        assert_eq!(
            h.err(Sysno::Reboot, &[MAGIC1 | hi, MAGIC2C | hi, CMD_CAD_OFF, 0]),
            EOPNOTSUPP
        );
        assert_eq!(h.err(Sysno::Reboot, &[MAGIC1, MAGIC2, 0x1234, 0]), EINVAL);
        // LINUX_REBOOT_CMD_KEXEC is unknown without CONFIG_KEXEC_CORE.
        assert_eq!(
            h.err(Sysno::Reboot, &[MAGIC1, MAGIC2, CMD_KEXEC, 0]),
            EINVAL
        );
        assert_eq!(
            h.err(Sysno::Reboot, &[MAGIC1, MAGIC2, CMD_RESTART2, BAD]),
            EFAULT
        );
        // RESTART2's string is cut at 255 bytes, not refused.
        put(&h, m + 0x100, &[b'a'; 400]);
        assert_eq!(
            h.err(Sysno::Reboot, &[MAGIC1, MAGIC2, CMD_RESTART2, m + 0x100]),
            EOPNOTSUPP
        );
        assert_eq!(
            h.err(Sysno::Reboot, &[MAGIC1, MAGIC2, CMD_POWER_OFF, 0]),
            EOPNOTSUPP
        );
        // Accounting is off: turning it off succeeds.
        assert_eq!(h.call(Sysno::Acct, &[0]), 0);
        assert_eq!(h.err(Sysno::Acct, &[slash]), EOPNOTSUPP);
        for s in [Sysno::Sethostname, Sysno::Setdomainname] {
            assert_eq!(h.err(s, &[slash, 65]), EINVAL);
            assert_eq!(h.err(s, &[slash, u64::MAX]), EINVAL);
            assert_eq!(h.err(s, &[BAD, 4]), EFAULT);
            // Nothing is read for an empty name.
            assert_eq!(h.err(s, &[BAD, 0]), EOPNOTSUPP);
            assert_eq!(h.err(s, &[slash, 64]), EOPNOTSUPP);
        }
        assert_eq!(h.err(Sysno::Vhangup, &[]), EOPNOTSUPP);
        // init_module: the image's length, size, and bytes.
        assert_eq!(h.err(Sysno::InitModule, &[m, 63, 0]), ENOEXEC);
        assert_eq!(h.err(Sysno::InitModule, &[m, 1 << 60, 0]), ENOMEM);
        assert_eq!(h.err(Sysno::InitModule, &[m + 2 * P, P + 1, 0]), EFAULT);
        assert_eq!(h.err(Sysno::InitModule, &[m, 64, 0]), EOPNOTSUPP);
        // finit_module: the flags, then the descriptor.
        let f = TempFile::new("module", abi);
        let path = cstr(&h, m + 0x800, f.path());
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, path, 0, 0]);
        assert_eq!(h.err(Sysno::FinitModule, &[fd, 0, 8]), EINVAL);
        assert_eq!(
            h.err(Sysno::FinitModule, &[fd, 0, u64::from(u32::MAX)]),
            EINVAL
        );
        assert_eq!(h.err(Sysno::FinitModule, &[99, 0, 7]), EBADF);
        assert_eq!(h.err(Sysno::FinitModule, &[fd, 0, 7]), EOPNOTSUPP);
        // delete_module: no module is loaded.
        assert_eq!(h.err(Sysno::DeleteModule, &[BAD, 0]), EFAULT);
        assert_eq!(
            h.err(Sysno::DeleteModule, &[cstr(&h, m + 0x200, ""), 0]),
            ENOENT
        );
        assert_eq!(
            h.err(Sysno::DeleteModule, &[cstr(&h, m + 0x200, "ext4"), 0]),
            ENOENT
        );
        // An unterminated name is ENOENT too, even when the page after its
        // 56 bytes is unmapped.
        let edge = m + 3 * P - 56;
        put(&h, edge, &[b'm'; 56]);
        assert_eq!(h.err(Sysno::DeleteModule, &[edge, 0]), ENOENT);
        // One byte more and the name runs into it.
        assert_eq!(h.err(Sysno::DeleteModule, &[edge + 1, 0]), EFAULT);
    });
}

#[test]
fn chroot_looks_up_a_searchable_directory_before_the_capability() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let f = TempFile::new("chroot", abi);
        let file = cstr(&h, m, f.path());
        let missing = cstr(&h, m + 0x400, "/nonexistent-rax-user-dir");
        let slash = cstr(&h, m + 0x800, "/");
        let proc_self = cstr(&h, m + 0x900, "/proc/self");
        let proc_file = cstr(&h, m + 0xa00, "/proc/self/stat");
        for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
            creds(&mut h, id);
            assert_eq!(h.err(Sysno::Chroot, &[BAD]), EFAULT);
            assert_eq!(h.err(Sysno::Chroot, &[missing]), ENOENT);
            assert_eq!(h.err(Sysno::Chroot, &[file]), ENOTDIR);
            assert_eq!(h.err(Sysno::Chroot, &[proc_file]), ENOTDIR);
            assert_eq!(h.err(Sysno::Chroot, &[slash]), last);
            assert_eq!(h.err(Sysno::Chroot, &[proc_self]), last);
        }
    });
}

#[test]
fn x86_io_ports() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
        creds(&mut h, id);
        // iopl: the level (an unsigned int), then raising it.
        assert_eq!(h.err(Sysno::Iopl, &[4]), EINVAL);
        assert_eq!(h.err(Sysno::Iopl, &[u64::from(u32::MAX)]), EINVAL);
        assert_eq!(h.call(Sysno::Iopl, &[0]), 0);
        assert_eq!(h.call(Sysno::Iopl, &[1 << 32]), 0);
        assert_eq!(h.err(Sysno::Iopl, &[3]), last);
        // ioperm: the range, then granting ports.
        assert_eq!(h.err(Sysno::Ioperm, &[0x80, 0, 1]), EINVAL);
        assert_eq!(h.err(Sysno::Ioperm, &[0xffff, 2, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Ioperm, &[u64::MAX, 1, 1]), EINVAL);
        assert_eq!(h.call(Sysno::Ioperm, &[0, 65536, 0]), 0);
        assert_eq!(h.call(Sysno::Ioperm, &[0x80, 1, 1 << 32]), 0);
        assert_eq!(h.err(Sysno::Ioperm, &[0xffff, 1, 1]), last);
    }
}

// `SYSLOG_ACTION_*`.
const READ: u64 = 2;
const READ_ALL: u64 = 3;
const READ_CLEAR: u64 = 4;
const CONSOLE_LEVEL: u64 = 8;
const SIZE_BUFFER: u64 = 10;

#[test]
fn root_reads_an_empty_kernel_log() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, 0);
        let m = h.anon(P, 3, false);
        for action in [0, 1, 5, 6, 7, 9] {
            assert_eq!(h.call(Sysno::Syslog, &[action, BAD, u64::MAX]), 0);
        }
        for action in [READ, READ_ALL, READ_CLEAR] {
            assert_eq!(h.err(Sysno::Syslog, &[action, 0, 8]), EINVAL);
            assert_eq!(h.err(Sysno::Syslog, &[action, m, u64::MAX]), EINVAL);
            assert_eq!(h.call(Sysno::Syslog, &[action, m, 0]), 0);
            // access_ok: only the range's place in the address space.
            assert_eq!(h.err(Sysno::Syslog, &[action, u64::MAX - 7, 8]), EFAULT);
        }
        // Nothing to copy: an unmapped buffer is no fault.
        assert_eq!(h.call(Sysno::Syslog, &[READ_ALL, BAD, 64]), 0);
        assert_eq!(h.call(Sysno::Syslog, &[READ_CLEAR, m, 64]), 0);
        assert_eq!(h.err(Sysno::Syslog, &[CONSOLE_LEVEL, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Syslog, &[CONSOLE_LEVEL, 0, 9]), EINVAL);
        assert_eq!(h.call(Sysno::Syslog, &[CONSOLE_LEVEL, 0, 1]), 0);
        assert_eq!(h.call(Sysno::Syslog, &[CONSOLE_LEVEL, 0, 8]), 0);
        assert_eq!(h.call(Sysno::Syslog, &[SIZE_BUFFER, 0, 0]), 1 << 17);
        assert_eq!(h.err(Sysno::Syslog, &[11, m, 8]), EINVAL);
        assert_eq!(h.err(Sysno::Syslog, &[u64::MAX, m, 8]), EINVAL);
        // A read waits for a message, until a signal.
        assert_eq!(h.start(0, Sysno::Syslog, &[READ, m, 8]), None);
        h.proc.threads[0].blocked.take().unwrap();
        h.proc.threads[0].sigpending = true;
        assert_eq!(
            h.start(0, Sysno::Syslog, &[READ, m, 8]),
            Some(-(ERESTARTSYS as i64))
        );
        h.proc.threads[0].sigpending = false;
        // The log's setting.
        let path = cstr(&h, m, "/proc/sys/kernel/dmesg_restrict");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, path, 0, 0]);
        assert_eq!(h.call(Sysno::Read, &[fd, m + 0x100, 16]), 2);
        assert_eq!(bytes(&h, m + 0x100, 2), b"1\n");
    });
}

/// `TIME_SETTOD_SEC_MAX`: `KTIME_MAX / NSEC_PER_SEC` less 30 years.
const SETTOD_SEC_MAX: i64 = 9_223_372_036 - 946_080_000;

#[test]
fn settimeofday_checks_the_time_then_the_capability_then_the_zone() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(P, 3, false);
        let tv = |h: &Harness, sec: i64, usec: i64| words(h, m, &[sec, usec]);
        let tz = |h: &Harness, west: i32| {
            put(
                h,
                m + 0x100,
                &[west.to_le_bytes(), 0i32.to_le_bytes()].concat(),
            );
            m + 0x100
        };
        // Neither: only the capability.
        assert_eq!(h.err(Sysno::Settimeofday, &[0, 0]), EPERM);
        assert_eq!(h.err(Sysno::Settimeofday, &[BAD, 0]), EFAULT);
        for usec in [-1, 1_000_001] {
            let t = tv(&h, 1, usec);
            assert_eq!(h.err(Sysno::Settimeofday, &[t, BAD]), EINVAL);
        }
        // A whole second of microseconds passes the first check, and the
        // zone is read before the time's validity.
        let t = tv(&h, 1, 1_000_000);
        assert_eq!(h.err(Sysno::Settimeofday, &[t, BAD]), EFAULT);
        assert_eq!(h.err(Sysno::Settimeofday, &[t, 0]), EINVAL);
        let t = tv(&h, 1, 999_999);
        assert_eq!(h.err(Sysno::Settimeofday, &[t, BAD]), EFAULT);
        for sec in [-1, SETTOD_SEC_MAX, i64::MAX] {
            let t = tv(&h, sec, 0);
            assert_eq!(h.err(Sysno::Settimeofday, &[t, 0]), EINVAL);
        }
        let t = tv(&h, SETTOD_SEC_MAX - 1, 0);
        assert_eq!(h.err(Sysno::Settimeofday, &[t, 0]), EPERM);
        // The zone's range is checked after the capability.
        let z = tz(&h, 15 * 60 + 1);
        assert_eq!(h.err(Sysno::Settimeofday, &[0, z]), EPERM);
        creds(&mut h, 0);
        assert_eq!(h.err(Sysno::Settimeofday, &[0, z]), EINVAL);
        let z = tz(&h, -15 * 60 - 1);
        assert_eq!(h.err(Sysno::Settimeofday, &[0, z]), EINVAL);
        let z = tz(&h, -15 * 60);
        assert_eq!(h.err(Sysno::Settimeofday, &[0, z]), EOPNOTSUPP);
        let t = tv(&h, 1_700_000_000, 0);
        assert_eq!(h.err(Sysno::Settimeofday, &[t, 0]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::Settimeofday, &[0, 0]), EOPNOTSUPP);
    });
}

/// A process ID no test process has (`PID_MAX_LIMIT` less 1).
const NO_PID: i32 = 4_194_303;

/// `MAKE_PROCESS_CPUCLOCK`: `~pid << 3 | clock`.
fn cpu_clock(pid: i32, which: i32) -> u64 {
    (((!(pid as u32)) << 3) as i32 | which) as i64 as u64
}

#[test]
fn clock_settime_sets_only_the_realtime_clock() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let ts = words(&h, m, &[1_700_000_000, 0]);
        let pid = h.proc.state.pid;
        let tid = h.proc.threads[0].tid;
        for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
            creds(&mut h, id);
            // Clocks without a setter, before the time is read.
            for clock in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 0x7fff_ffff] {
                assert_eq!(h.err(Sysno::ClockSettime, &[clock, BAD]), EINVAL);
            }
            assert_eq!(h.err(Sysno::ClockSettime, &[0, BAD]), EFAULT);
            let bad = words(&h, m + 0x100, &[1, 1_000_000_000]);
            assert_eq!(h.err(Sysno::ClockSettime, &[0, bad]), EINVAL);
            assert_eq!(h.err(Sysno::ClockSettime, &[0, ts]), last);
            // A CPU-time clock that exists is never set, not even by root.
            for clock in [
                cpu_clock(0, 0),
                cpu_clock(0, 2),
                cpu_clock(pid, 1),
                cpu_clock(0, 4),
                cpu_clock(tid, 4 | 2),
            ] {
                assert_eq!(h.err(Sysno::ClockSettime, &[clock, BAD]), EFAULT);
                assert_eq!(h.err(Sysno::ClockSettime, &[clock, ts]), EPERM);
            }
            // One that does not, and a clock device, are EINVAL.
            assert!(NO_PID != pid && NO_PID != tid);
            for clock in [cpu_clock(NO_PID, 0), cpu_clock(0, 7), cpu_clock(0, 3)] {
                assert_eq!(h.err(Sysno::ClockSettime, &[clock, ts]), EINVAL);
            }
        }
    });
}

/// `struct __kernel_timex` offsets (`linux/timex.h`).
mod tx {
    pub const OFFSET: u64 = 8;
    pub const FREQ: u64 = 16;
    pub const MAXERROR: u64 = 24;
    pub const ESTERROR: u64 = 32;
    pub const STATUS: u64 = 40;
    pub const CONSTANT: u64 = 48;
    pub const PRECISION: u64 = 56;
    pub const TOLERANCE: u64 = 64;
    pub const TIME: u64 = 72;
    pub const TICK: u64 = 88;
    pub const SHIFT: u64 = 112;
    pub const TAI: u64 = 160;
    pub const SIZE: usize = 208;
}

fn i64_at(h: &Harness, at: u64) -> i64 {
    i64::from_le_bytes(bytes(h, at, 8).try_into().unwrap())
}

fn i32_at(h: &Harness, at: u64) -> i32 {
    i32::from_le_bytes(bytes(h, at, 4).try_into().unwrap())
}

/// A `struct timex` at `at` filled with `0x5a`, with `modes` and the words
/// `w` (offset, value).
fn timex(h: &Harness, at: u64, modes: u32, w: &[(u64, i64)]) -> u64 {
    put(h, at, &[0x5a; tx::SIZE]);
    put(h, at, &modes.to_le_bytes());
    for &(off, v) in w {
        put(h, at + off, &v.to_le_bytes());
    }
    at
}

// `ADJ_*` (`linux/timex.h`).
const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;
/// `TIME_ERROR`.
const TIME_ERROR: i64 = 5;

#[test]
fn adjtimex_reads_an_unsynchronized_clock() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(P, 3, false);
        for modes in [0, ADJ_OFFSET_SS_READ, ADJ_OFFSET_SS_READ | ADJ_FREQUENCY] {
            let t = timex(&h, m, modes, &[(tx::FREQ, 0)]);
            let before = crate::user::linux::host::clock_gettime(
                crate::user::linux::host::HostClock::Realtime,
            );
            assert_eq!(h.call(Sysno::Adjtimex, &[t]), TIME_ERROR);
            assert_eq!(
                u32::from_le_bytes(bytes(&h, t, 4).try_into().unwrap()),
                modes
            );
            // The padding after modes is left as it was.
            assert_eq!(bytes(&h, t + 4, 4), [0x5a; 4]);
            assert_eq!(i64_at(&h, t + tx::OFFSET), 0);
            assert_eq!(i64_at(&h, t + tx::FREQ), 0);
            // NTP_PHASE_LIMIT: (MAXPHASE / NSEC_PER_USEC) << 5.
            assert_eq!(i64_at(&h, t + tx::MAXERROR), 16_000_000);
            assert_eq!(i64_at(&h, t + tx::ESTERROR), 16_000_000);
            // STA_UNSYNC, and the padding after it as it was.
            assert_eq!(i32_at(&h, t + tx::STATUS), 0x40);
            assert_eq!(bytes(&h, t + tx::STATUS + 4, 4), [0x5a; 4]);
            assert_eq!(i64_at(&h, t + tx::CONSTANT), 2);
            assert_eq!(i64_at(&h, t + tx::PRECISION), 1);
            // MAXFREQ_SCALED / PPM_SCALE: 500 ppm << 16.
            assert_eq!(i64_at(&h, t + tx::TOLERANCE), 500 << 16);
            let sec = i64_at(&h, t + tx::TIME);
            let usec = i64_at(&h, t + tx::TIME + 8);
            assert!((before.0..=before.0 + 5).contains(&sec), "{sec} {before:?}");
            assert!((0..1_000_000).contains(&usec));
            // USER_TICK_USEC at USER_HZ 100.
            assert_eq!(i64_at(&h, t + tx::TICK), 10_000);
            // No PPS: zeros from ppsfreq through stbcnt (but for the
            // padding after shift), and no TAI offset; the padding after
            // it as it was.
            assert!(bytes(&h, t + 96, 16).iter().all(|&b| b == 0));
            assert_eq!(i32_at(&h, t + tx::SHIFT), 0);
            assert_eq!(bytes(&h, t + tx::SHIFT + 4, 4), [0x5a; 4]);
            assert!(bytes(&h, t + 120, 40).iter().all(|&b| b == 0));
            assert_eq!(i32_at(&h, t + tx::TAI), 0);
            assert_eq!(bytes(&h, t + tx::TAI + 4, 44), [0x5a; 44]);
        }
        // The same through clock_adjtime on the realtime clock.
        let t = timex(&h, m, 0, &[]);
        assert_eq!(h.call(Sysno::ClockAdjtime, &[0, t]), TIME_ERROR);
        assert_eq!(i64_at(&h, t + tx::TICK), 10_000);
    });
}

#[test]
fn adjtimex_checks_modes_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(2 * P, 3, false);
        let ro = h.anon(P, 1, false);
        let checks = |h: &mut Harness, modes: u32, w: &[(u64, i64)]| {
            let t = timex(h, m, modes, w);
            let e = h.err(Sysno::Adjtimex, &[t]);
            // Refused structures come back as they went.
            let mut want = vec![0x5a; tx::SIZE];
            want[..4].copy_from_slice(&modes.to_le_bytes());
            for &(off, v) in w {
                want[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
            }
            assert_eq!(bytes(h, t, tx::SIZE), want, "modes {modes:#x}");
            e
        };
        creds(&mut h, NOBODY);
        assert_eq!(h.err(Sysno::Adjtimex, &[BAD]), EFAULT);
        // Single-shot adjtime must not be mixed with other modes.
        assert_eq!(checks(&mut h, 0x8000, &[]), EINVAL);
        assert_eq!(checks(&mut h, 0x8000 | ADJ_NANO, &[]), EINVAL);
        assert_eq!(checks(&mut h, ADJ_OFFSET_SINGLESHOT, &[]), EPERM);
        assert_eq!(checks(&mut h, ADJ_OFFSET, &[]), EPERM);
        // The capability comes before the tick's range.
        assert_eq!(checks(&mut h, ADJ_TICK, &[(tx::TICK, 5)]), EPERM);
        // A read-only adjtime that sets an offset needs it too.
        assert_eq!(
            checks(&mut h, ADJ_OFFSET_SS_READ | ADJ_SETOFFSET, &[]),
            EPERM
        );
        // A read-only adjtime still checks the frequency's range.
        let huge = i64::MAX / (1000 << 16) + 1;
        assert_eq!(
            checks(
                &mut h,
                ADJ_OFFSET_SS_READ | ADJ_FREQUENCY,
                &[(tx::FREQ, huge)]
            ),
            EINVAL
        );
        // The structure is written back whatever the result: a refusal on
        // a read-only page is a fault.
        put(&h, ro, &ADJ_OFFSET.to_le_bytes());
        assert_eq!(h.err(Sysno::Adjtimex, &[ro]), EFAULT);
        creds(&mut h, 0);
        assert_eq!(h.err(Sysno::Adjtimex, &[ro]), EFAULT);
        assert_eq!(checks(&mut h, ADJ_TICK, &[(tx::TICK, 8999)]), EINVAL);
        assert_eq!(checks(&mut h, ADJ_TICK, &[(tx::TICK, 11001)]), EINVAL);
        assert_eq!(checks(&mut h, ADJ_TICK, &[(tx::TICK, 9000)]), EOPNOTSUPP);
        assert_eq!(checks(&mut h, ADJ_TICK, &[(tx::TICK, 11000)]), EOPNOTSUPP);
        // An adjtime tick is not checked.
        assert_eq!(
            checks(&mut h, ADJ_OFFSET_SINGLESHOT | ADJ_TICK, &[(tx::TICK, 5)]),
            EOPNOTSUPP
        );
        let usec = tx::TIME + 8;
        assert_eq!(checks(&mut h, ADJ_SETOFFSET, &[(usec, -1)]), EINVAL);
        assert_eq!(checks(&mut h, ADJ_SETOFFSET, &[(usec, 1_000_000)]), EINVAL);
        assert_eq!(
            checks(&mut h, ADJ_SETOFFSET, &[(usec, 999_999)]),
            EOPNOTSUPP
        );
        assert_eq!(
            checks(&mut h, ADJ_SETOFFSET | ADJ_NANO, &[(usec, 999_999_999)]),
            EOPNOTSUPP
        );
        assert_eq!(
            checks(&mut h, ADJ_SETOFFSET | ADJ_NANO, &[(usec, 1_000_000_000)]),
            EINVAL
        );
        assert_eq!(checks(&mut h, ADJ_FREQUENCY, &[(tx::FREQ, huge)]), EINVAL);
        assert_eq!(checks(&mut h, ADJ_FREQUENCY, &[(tx::FREQ, -huge)]), EINVAL);
        assert_eq!(
            checks(&mut h, ADJ_FREQUENCY, &[(tx::FREQ, huge - 1)]),
            EOPNOTSUPP
        );
        // ADJ_OFFSET_READONLY is ADJ_NANO's bit: the offset is checked in
        // nanoseconds.
        let ss_set = ADJ_OFFSET_SS_READ | ADJ_SETOFFSET;
        assert_eq!(checks(&mut h, ss_set, &[(usec, 1_000_000_000)]), EINVAL);
        assert_eq!(checks(&mut h, ss_set, &[(usec, 999_999_999)]), EOPNOTSUPP);
        // So is a successful read.
        put(&h, ro, &0u32.to_le_bytes());
        assert_eq!(h.err(Sysno::Adjtimex, &[ro]), EFAULT);
    });
}

#[test]
fn clock_adjtime_adjusts_only_the_realtime_clock() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(P, 3, false);
        let ro = h.anon(P, 1, false);
        let unchanged = |h: &Harness, t: u64| {
            assert!(bytes(h, t, tx::SIZE).iter().all(|&b| b == 0x5a));
        };
        assert_eq!(h.err(Sysno::ClockAdjtime, &[0, BAD]), EFAULT);
        assert_eq!(h.err(Sysno::ClockAdjtime, &[1, BAD]), EFAULT);
        let t = timex(&h, m, 0x5a5a_5a5a, &[]);
        // Clocks without an adjuster, and ones that do not exist.
        for clock in [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            11,
            cpu_clock(0, 0),
            cpu_clock(NO_PID, 4),
        ] {
            assert_eq!(h.err(Sysno::ClockAdjtime, &[clock, t]), EOPNOTSUPP);
            unchanged(&h, t);
        }
        for clock in [10, 12, 16, 0x7fff_ffff, cpu_clock(0, 3)] {
            assert_eq!(h.err(Sysno::ClockAdjtime, &[clock, t]), EINVAL);
            unchanged(&h, t);
        }
        // A refusal is not written back: no fault on a read-only page.
        let t = timex(&h, m, ADJ_OFFSET, &[]);
        h.ok(Sysno::Mprotect, &[m, P, 1]);
        assert_eq!(h.err(Sysno::ClockAdjtime, &[0, t]), EPERM);
        assert_eq!(h.err(Sysno::Adjtimex, &[t]), EFAULT);
        assert_eq!(h.err(Sysno::ClockAdjtime, &[0, ro]), EFAULT);
    });
}
