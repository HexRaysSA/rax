//! Resource limits, CPU masks, and `uname` against Linux 6.19 on every
//! 64-bit ABI: `prlimit64` and `setrlimit` read the new `struct rlimit`
//! before `do_prlimit` checks the resource (`kernel/sys.c`);
//! `sched_getaffinity` checks the length before the task and
//! `sched_setaffinity` reads the mask before it (`kernel/sched/syscalls.c`);
//! and on x86 `PER_LINUX32` shows the machine as `i686`
//! (`override_architecture`).

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

#[test]
fn a_new_limit_is_read_before_the_resource_is_checked() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // x86-64 has setrlimit; every ABI has prlimit64.
        if abi == LinuxAbi::X86_64 {
            assert_eq!(h.err(Sysno::Setrlimit, &[99, 8]), EFAULT);
            assert_eq!(h.err(Sysno::Setrlimit, &[99, h.scratch]), EINVAL);
        }
        assert_eq!(h.err(Sysno::Prlimit64, &[0, 99, 8, 0]), EFAULT, "{abi:?}");
        assert_eq!(h.err(Sysno::Prlimit64, &[0, 99, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Prlimit64, &[99_999, 0, h.scratch, 0]), ESRCH);
    });
}

#[test]
fn affinity_checks_the_length_before_the_task() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.scratch;
        assert_eq!(
            h.err(Sysno::SchedGetaffinity, &[99_999, 4, m]),
            EINVAL,
            "{abi:?}"
        );
        assert_eq!(h.err(Sysno::SchedGetaffinity, &[99_999, 0, m]), EINVAL);
        assert_eq!(h.err(Sysno::SchedGetaffinity, &[99_999, 8, m]), ESRCH);
        assert_eq!(h.call(Sysno::SchedGetaffinity, &[0, 64, m]), 8);
        // The length is an unsigned int.
        assert_eq!(h.call(Sysno::SchedGetaffinity, &[0, (1 << 32) | 8, m]), 8);
        // setaffinity reads the mask first: EFAULT before ESRCH.
        assert_eq!(h.err(Sysno::SchedSetaffinity, &[99_999, 8, 8]), EFAULT);
        assert_eq!(h.err(Sysno::SchedSetaffinity, &[99_999, 8, m]), ESRCH);
        h.proc.state.space.write_raw(m, &[2]).unwrap();
        assert_eq!(
            h.err(Sysno::SchedSetaffinity, &[0, 8, m]),
            EINVAL,
            "no CPU 0"
        );
        assert_eq!(
            h.err(Sysno::SchedSetaffinity, &[0, 0, m]),
            EINVAL,
            "no CPUs"
        );
        h.proc.state.space.write_raw(m, &[3]).unwrap();
        assert_eq!(h.call(Sysno::SchedSetaffinity, &[0, 8, m]), 0);
    });
}

/// `override_architecture` (`kernel/sys.c`): `COMPAT_UTS_MACHINE` for
/// `PER_LINUX32`, `i686` on x86-64 and `armv8l` on arm64
/// (`asm/compat.h`); RISC-V defines none.
#[test]
fn per_linux32_shows_the_32_bit_machine() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.scratch;
        h.ok(Sysno::Personality, &[8]);
        h.ok(Sysno::Uname, &[m]);
        let mut b = [0u8; 8];
        h.proc.state.space.read_raw(m + 4 * 65, &mut b).unwrap();
        let machine = std::str::from_utf8(&b).unwrap().trim_end_matches('\0');
        let want = match abi {
            LinuxAbi::X86_64 => "i686",
            LinuxAbi::Aarch64 => "armv8l",
            _ => abi.machine(),
        };
        assert_eq!(machine, want, "{abi:?}");
    });
}
