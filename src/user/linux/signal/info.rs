//! `siginfo_t` records.
//!
//! The kernel keeps `struct kernel_siginfo`: `si_signo`, `si_errno`, and
//! `si_code` (three `int`s, padded to 16 bytes on 64-bit ABIs) followed by
//! the 32-byte `_sifields` union. `copy_siginfo_to_user` writes those 48
//! bytes and zeroes the rest of the 128-byte user `siginfo_t`
//! (`asm-generic/siginfo.h`, `SI_MAX_SIZE`). Union layouts used here, at
//! offsets within `_sifields`:
//!
//! | Layout | Fields |
//! |---|---|
//! | kill (`SI_USER`, `SI_TKILL`) | `si_pid` @0 (int), `si_uid` @4 (u32) |
//! | rt / timer (`SI_QUEUE`, ...) | `si_pid`/`si_tid` @0, `si_uid`/`si_overrun` @4, `si_value` @8 |
//! | sigchld | `si_pid` @0, `si_uid` @4, `si_status` @8, `si_utime` @16, `si_stime` @24 |
//! | sigfault | `si_addr` @0 |
//! | sigpoll | `si_band` @0 (long), `si_fd` @8 |
//! | sigsys | `si_call_addr` @0, `si_syscall` @8, `si_arch` @12 |

use super::code;

/// Size of the user `siginfo_t`.
pub const SIGINFO_SIZE: usize = 128;

/// Size of `struct kernel_siginfo` (header and union).
pub const KERNEL_SIGINFO_SIZE: usize = 48;

/// The `_sifields` member a record uses (`enum siginfo_layout`). The
/// fault variants for bounds, protection keys, and perf events carry only
/// the address here, as `signalfd` reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `_kill`: `si_pid`, `si_uid`.
    Kill,
    /// `_timer`: `si_tid`, `si_overrun`, `si_value`.
    Timer,
    /// `_sigpoll`: `si_band`, `si_fd`.
    Poll,
    /// `_sigfault`: `si_addr`.
    Fault,
    /// `_sigfault` with `si_addr_lsb`.
    FaultMceErr,
    /// `_sigchld`.
    Chld,
    /// `_rt`: `si_pid`, `si_uid`, `si_value`.
    Rt,
    /// `_sigsys`.
    Sys,
}

/// A `siginfo_t` as the kernel stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    /// `si_signo`.
    pub signo: i32,
    /// `si_errno`.
    pub errno: i32,
    /// `si_code`.
    pub code: i32,
    /// The `_sifields` union.
    pub fields: [u8; 32],
}

impl SigInfo {
    fn with(signo: i32, code: i32) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            fields: [0; 32],
        }
    }

    fn put(mut self, at: usize, bytes: &[u8]) -> Self {
        self.fields[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// A signal sent by a process (`kill`: `SI_USER`, `tgkill`:
    /// `SI_TKILL`) with the sender's thread-group ID and real UID.
    pub fn kill(signo: i32, code: i32, pid: i32, uid: u32) -> Self {
        Self::with(signo, code)
            .put(0, &pid.to_le_bytes())
            .put(4, &uid.to_le_bytes())
    }

    /// A signal the kernel sends without further information
    /// (`SEND_SIG_PRIV`: `SI_KERNEL`, zero PID and UID).
    pub fn kernel(signo: i32) -> Self {
        Self::with(signo, code::SI_KERNEL)
    }

    /// A fault (`force_sig_fault`) with `si_addr`.
    pub fn fault(signo: i32, code: i32, addr: u64) -> Self {
        Self::with(signo, code).put(0, &addr.to_le_bytes())
    }

    /// A queued real-time-style signal with `si_value` (`sigqueue`).
    pub fn queued(signo: i32, code: i32, pid: i32, uid: u32, value: u64) -> Self {
        Self::kill(signo, code, pid, uid).put(8, &value.to_le_bytes())
    }

    /// A POSIX timer's signal (`SI_TIMER`) with its ID (`si_tid`), a zero
    /// overrun count, and its `sigev_value`, as `do_timer_create`
    /// prepares the preallocated record.
    pub fn timer(signo: i32, id: i32, value: u64) -> Self {
        Self::with(signo, code::SI_TIMER)
            .put(0, &id.to_le_bytes())
            .put(8, &value.to_le_bytes())
    }

    /// Sets `si_overrun` of a timer signal.
    pub fn set_overrun(&mut self, n: i32) {
        self.fields[4..8].copy_from_slice(&n.to_le_bytes());
    }

    /// `SIGCHLD` for a child's state change.
    pub fn child(code: i32, pid: i32, uid: u32, status: i32, utime: i64, stime: i64) -> Self {
        Self::kill(super::SIGCHLD, code, pid, uid)
            .put(8, &status.to_le_bytes())
            .put(16, &utime.to_le_bytes())
            .put(24, &stime.to_le_bytes())
    }

    fn i32_at(&self, at: usize) -> i32 {
        i32::from_le_bytes(self.fields[at..at + 4].try_into().unwrap())
    }

    /// `si_addr` (the first union word).
    pub fn addr(&self) -> u64 {
        u64::from_le_bytes(self.fields[..8].try_into().unwrap())
    }

    /// `si_pid`.
    pub fn pid(&self) -> i32 {
        self.i32_at(0)
    }

    /// `si_uid`.
    pub fn uid(&self) -> u32 {
        self.i32_at(4) as u32
    }

    /// `si_value` / `si_status` word (union offset 8).
    pub fn value(&self) -> u64 {
        u64::from_le_bytes(self.fields[8..16].try_into().unwrap())
    }

    /// Whether the kernel generated the signal (`SI_FROMKERNEL`: a positive
    /// `si_code`), as the synchronous-signal dequeue requires.
    pub fn from_kernel(&self) -> bool {
        self.code > code::SI_USER
    }

    /// The 128-byte user `siginfo_t`.
    pub fn encode(&self) -> [u8; SIGINFO_SIZE] {
        let mut b = [0u8; SIGINFO_SIZE];
        b[0..4].copy_from_slice(&self.signo.to_le_bytes());
        b[4..8].copy_from_slice(&self.errno.to_le_bytes());
        b[8..12].copy_from_slice(&self.code.to_le_bytes());
        b[16..KERNEL_SIGINFO_SIZE].copy_from_slice(&self.fields);
        b
    }

    /// Decodes the first 48 bytes of a user `siginfo_t`
    /// (`copy_siginfo_from_user`).
    pub fn decode(b: &[u8]) -> Self {
        let i = |at: usize| i32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        SigInfo {
            signo: i(0),
            errno: i(4),
            code: i(8),
            fields: b[16..KERNEL_SIGINFO_SIZE].try_into().unwrap(),
        }
    }

    /// `siginfo_layout`: which union member `si_signo`/`si_code` select.
    pub fn layout(&self) -> Layout {
        use super::*;
        const NSIGPOLL: i32 = 6;
        let (sig, c) = (self.signo, self.code);
        if c > code::SI_USER && c < code::SI_KERNEL {
            let own = match sig {
                SIGILL => Some((11, Layout::Fault)),
                SIGFPE => Some((15, Layout::Fault)),
                SIGSEGV => Some((10, Layout::Fault)),
                SIGBUS => Some((5, Layout::Fault)),
                SIGTRAP => Some((6, Layout::Fault)),
                SIGCHLD => Some((6, Layout::Chld)),
                SIGIO => Some((NSIGPOLL, Layout::Poll)),
                SIGSYS => Some((2, Layout::Sys)),
                _ => None,
            };
            return match own {
                // BUS_MCEERR_AR, BUS_MCEERR_AO.
                Some((limit, _)) if c <= limit && sig == SIGBUS && (4..=5).contains(&c) => {
                    Layout::FaultMceErr
                }
                Some((limit, layout)) if c <= limit => layout,
                _ if c <= NSIGPOLL => Layout::Poll,
                _ => Layout::Kill,
            };
        }
        match c {
            code::SI_TIMER => Layout::Timer,
            // SI_SIGIO.
            -5 => Layout::Poll,
            c if c < 0 => Layout::Rt,
            _ => Layout::Kill,
        }
    }

    /// Whether `si_signo`/`si_code` select a union layout the kernel knows
    /// (`known_siginfo_layout`); for an unknown one `rt_sigqueueinfo`
    /// requires bytes 48-127 of the user record to be zero.
    pub fn known_layout(&self) -> bool {
        use super::*;
        // NSIG* limits of the signals with their own si_code sets
        // (asm-generic/siginfo.h); positive codes of any other signal are
        // known up to NSIGPOLL.
        const NSIGPOLL: i32 = 6;
        let c = self.code;
        if c == code::SI_KERNEL {
            return true;
        }
        if c > code::SI_USER {
            let limit = match self.signo {
                SIGILL => 11,
                SIGFPE => 15,
                SIGSEGV => 10,
                SIGBUS => 5,
                SIGTRAP => 6,
                SIGCHLD => 6,
                SIGIO => NSIGPOLL,
                SIGSYS => 2,
                _ => NSIGPOLL,
            };
            return c <= limit;
        }
        // SI_DETHREAD (-7) through SI_USER, and SI_ASYNCNL (-60).
        c >= -7 || c == -60
    }
}
