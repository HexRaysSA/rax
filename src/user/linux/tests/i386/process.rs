//! A compatibility task's process calls against Linux 6.19: the 16-bit
//! ID calls (`kernel/uid16.c`: `low2highuid`, `high2lowuid`), `struct
//! compat_rlimit` and the old `getrlimit` (`kernel/sys.c`), `struct
//! compat_rusage` for `getrusage`, `wait4`, `waitpid`, and `waitid`
//! (`put_compat_rusage`, `kernel/exit.c`), `struct compat_tms`
//! (`compat_sys_times`), `struct compat_sysinfo`, the 32-bit CPU masks
//! (`kernel/compat.c`), the old `uname`s, `nice`, and `arch_prctl`'s
//! 32-bit options (`arch/x86/kernel/process.c`).

use super::super::harness::Harness;
use super::{cstr, put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

fn reg(v: i32) -> u64 {
    u64::from(v as u32)
}

fn fresh(h: &mut Harness) -> u64 {
    let m = h.ok(Sysno::Mmap2, &[0, 0x2000, 3, 0x22, reg(-1), 0]);
    put(h, m, &[0xAA; 0x2000]);
    m
}

fn u16_at(h: &Harness, at: u64) -> u16 {
    u32_at(h, at) as u16
}

#[test]
fn sixteen_bit_ids_read_as_overflow_and_minus_one_widens() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // A 32-bit ID past 16 bits reads as 65534 through the 16-bit calls.
    h.proc.state.creds = (70_000, 70_001, 1000, 1001);
    assert_eq!(h.call(Sysno::Getuid, &[]), 65534);
    assert_eq!(h.call(Sysno::Geteuid, &[]), 65534);
    assert_eq!(h.call(Sysno::Getgid, &[]), 1000);
    assert_eq!(h.call(Sysno::Getegid, &[]), 1001);
    assert_eq!(h.call(Sysno::Getuid32, &[]), 70_000);
    assert_eq!(h.call(Sysno::Getresuid, &[m, m + 2, m + 4]), 0);
    assert_eq!(
        (u16_at(&h, m), u16_at(&h, m + 2), u16_at(&h, m + 4)),
        (65534, 65534, 65534)
    );
    assert_eq!(u16_at(&h, m + 6), 0xAAAA, "three old_uid_t");
    assert_eq!(h.call(Sysno::Getresgid, &[m, m + 2, 8]), -i64::from(EFAULT));
    // setresuid16: 0xFFFF is -1 (unchanged); only the low 16 bits count.
    h.proc.state.creds = (0, 0, 0, 0);
    assert_eq!(h.call(Sysno::Setresuid, &[0xFFFF, 0x1_0005, 0xFFFF]), 0);
    assert_eq!(h.proc.state.creds.1, 5);
    assert_eq!(h.proc.state.creds.0, 0);
    // getgroups16 and setgroups16: old_gid_t lists.
    h.proc.state.creds = (0, 0, 0, 0);
    put(&h, m, &[3, 0, 70, 0x11, 2, 0]);
    assert_eq!(h.call(Sysno::Setgroups, &[3, m]), 0);
    assert_eq!(h.proc.state.groups, [2, 3, 0x1146]);
    h.proc.state.groups.push(90_000);
    assert_eq!(h.call(Sysno::Getgroups, &[1, m]), -i64::from(EINVAL));
    assert_eq!(h.call(Sysno::Getgroups, &[0, m]), 4);
    assert_eq!(h.call(Sysno::Getgroups, &[4, m + 0x100]), 4);
    let got: Vec<u16> = (0..4).map(|i| u16_at(&h, m + 0x100 + 2 * i)).collect();
    assert_eq!(got, [2, 3, 0x1146, 65534]);
    assert_eq!(u16_at(&h, m + 0x108), 0xAAAA);
    // setgroups16 of 0xFFFF: an invalid group.
    put(&h, m, &[0xFF, 0xFF]);
    assert_eq!(h.call(Sysno::Setgroups, &[1, m]), -i64::from(EINVAL));
    // chown16 with -1 for both leaves a file as it is.
    let path = std::env::temp_dir().join(format!("rax-i386-chown-{}", std::process::id()));
    std::fs::write(&path, b"x").unwrap();
    let mut s = path.to_str().unwrap().as_bytes().to_vec();
    s.push(0);
    put(&h, m + 0x200, &s);
    assert_eq!(h.call(Sysno::Chown, &[m + 0x200, 0xFFFF, 0xFFFF]), 0);
    assert_eq!(h.call(Sysno::Lchown, &[m + 0x200, 0xFFFF, 0xFFFF]), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resource_limits_clamp_to_the_32_bit_infinities() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_CORE: u64 = 4;
    h.proc.state.rlimits[RLIMIT_CORE as usize] = (u64::MAX, u64::MAX);
    h.proc.state.rlimits[RLIMIT_STACK as usize] = (8 << 20, 5 << 30);
    // ugetrlimit: COMPAT_RLIM_INFINITY; the old getrlimit: 2^31 - 1.
    assert_eq!(h.call(Sysno::Ugetrlimit, &[RLIMIT_CORE, m]), 0);
    assert_eq!((u32_at(&h, m), u32_at(&h, m + 4)), (u32::MAX, u32::MAX));
    assert_eq!(u32_at(&h, m + 8), 0xAAAA_AAAA, "struct compat_rlimit");
    assert_eq!(h.call(Sysno::Ugetrlimit, &[RLIMIT_STACK, m]), 0);
    assert_eq!((u32_at(&h, m), u32_at(&h, m + 4)), (8 << 20, u32::MAX));
    assert_eq!(h.call(Sysno::Getrlimit, &[RLIMIT_STACK, m]), 0);
    assert_eq!((u32_at(&h, m), u32_at(&h, m + 4)), (8 << 20, 0x7FFF_FFFF));
    assert_eq!(h.call(Sysno::Getrlimit, &[16, m]), -i64::from(EINVAL));
    assert_eq!(h.call(Sysno::Ugetrlimit, &[16, m]), -i64::from(EINVAL));
    // setrlimit: 0xFFFFFFFF is RLIM_INFINITY; the structure is read first.
    put(
        &h,
        m,
        &[&1000u32.to_le_bytes()[..], &u32::MAX.to_le_bytes()].concat(),
    );
    h.proc.state.creds = (0, 0, 0, 0);
    assert_eq!(h.call(Sysno::Setrlimit, &[RLIMIT_CORE, m]), 0);
    assert_eq!(h.proc.state.rlimits[RLIMIT_CORE as usize], (1000, u64::MAX));
    assert_eq!(h.call(Sysno::Setrlimit, &[16, 8]), -i64::from(EFAULT));
    // prlimit64 stays 64-bit.
    assert_eq!(h.call(Sysno::Prlimit64, &[0, RLIMIT_CORE, 0, m + 0x100]), 0);
    assert_eq!(u32_at(&h, m + 0x104), 0);
    assert_eq!(
        (u32_at(&h, m + 0x108), u32_at(&h, m + 0x10C)),
        (u32::MAX, u32::MAX)
    );
}

#[test]
fn usage_times_and_system_information_have_the_32_bit_layouts() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // struct compat_rusage: 72 bytes, the times as old_timeval32s.
    assert_eq!(h.call(Sysno::Getrusage, &[0, m]), 0);
    assert!(u32_at(&h, m + 4) < 1_000_000, "ru_utime.tv_usec");
    assert!(u32_at(&h, m + 12) < 1_000_000, "ru_stime.tv_usec");
    assert_ne!(u32_at(&h, m + 16), 0, "ru_maxrss");
    assert_eq!(u32_at(&h, m + 68), 0);
    assert_eq!(u32_at(&h, m + 72), 0xAAAA_AAAA, "72 bytes");
    assert_eq!(h.call(Sysno::Getrusage, &[5, m]), -i64::from(EINVAL));
    // struct compat_tms: four compat_clock_ts.
    assert!(h.call(Sysno::Times, &[m + 0x100]) >= 0);
    assert_eq!((u32_at(&h, m + 0x108), u32_at(&h, m + 0x10C)), (0, 0));
    assert_eq!(u32_at(&h, m + 0x110), 0xAAAA_AAAA, "16 bytes");
    // struct compat_sysinfo: 64 bytes; memory scaled into 32 bits.
    assert_eq!(h.call(Sysno::Sysinfo, &[m + 0x200]), 0);
    let total = u64::from(u32_at(&h, m + 0x210));
    let unit = u64::from(u32_at(&h, m + 0x234));
    assert_eq!(total * unit, h.proc.state.config.arena_bytes);
    assert_eq!(u16_at(&h, m + 0x228), 1, "procs");
    assert_eq!(u32_at(&h, m + 0x240), 0xAAAA_AAAA, "64 bytes");
}

#[test]
fn a_waited_child_reports_compat_rusage_and_siginfo() {
    use crate::user::linux::host;
    const SIGCHLD: i32 = 17;
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // No children: ECHILD, nothing written.
    assert_eq!(
        h.call(Sysno::Wait4, &[reg(-1), m, 1, m + 0x100]),
        -i64::from(ECHILD)
    );
    assert_eq!(h.call(Sysno::Waitpid, &[reg(-1), m, 1]), -i64::from(ECHILD));
    assert_eq!(u32_at(&h, m + 0x100), 0xAAAA_AAAA);
    // Zombie records no host process has: exited with 3 after 1.5 s of
    // user time and 0.25 s of system time, 4096 KiB at most.
    const Z1: i32 = i32::MAX - 5;
    const Z2: i32 = i32::MAX - 6;
    h.proc.state.config.processes = true;
    for (z, code) in [(Z1, 3), (Z2, 4)] {
        let (status, _) = host::status_pipe().unwrap();
        let pid = h.proc.state.pid;
        h.proc.state.children.add(z, status, None, SIGCHLD, pid, 0);
        let ch = h.proc.state.children.get_mut(z).unwrap();
        ch.zombie = Some((code << 8, (1_500_000, 250_000, 4096)));
    }
    // wait4: the status, and struct compat_rusage (72 bytes).
    let (stat, ru) = (m + 0x200, m + 0x300);
    assert_eq!(
        h.call(Sysno::Wait4, &[Z1 as u64, stat, 0, ru]),
        i64::from(Z1)
    );
    assert_eq!(u32_at(&h, stat), 3 << 8);
    let tv: Vec<u32> = (0..4).map(|i| u32_at(&h, ru + 4 * i)).collect();
    assert_eq!(tv, [1, 500_000, 0, 250_000]);
    assert_eq!(u32_at(&h, ru + 16), 4096, "ru_maxrss");
    assert_eq!(u32_at(&h, ru + 68), 0);
    assert_eq!(u32_at(&h, ru + 72), 0xAAAA_AAAA, "72 bytes");
    // waitid(P_PID, WEXITED): struct compat_siginfo, the union at 12.
    let (info, ru) = (m + 0x400, m + 0x500);
    assert_eq!(h.call(Sysno::Waitid, &[1, Z2 as u64, info, 4, ru]), 0);
    assert_eq!(u32_at(&h, info), SIGCHLD as u32, "si_signo");
    assert_eq!(u32_at(&h, info + 8), 1, "si_code: CLD_EXITED");
    assert_eq!(u32_at(&h, info + 12), Z2 as u32, "si_pid");
    assert_eq!(u32_at(&h, info + 16), h.proc.state.creds.0, "si_uid");
    assert_eq!(u32_at(&h, info + 20), 4, "si_status");
    assert_eq!(u32_at(&h, ru + 16), 4096, "compat_rusage");
    assert_eq!(u32_at(&h, ru + 72), 0xAAAA_AAAA);
}

#[test]
fn affinity_masks_are_32_bit_words() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // A compat_ulong_t is enough; the length is checked before the task.
    assert_eq!(h.call(Sysno::SchedGetaffinity, &[0, 4, m]), 4);
    assert_eq!(u32_at(&h, m), 1, "CPU 0");
    assert_eq!(u32_at(&h, m + 4), 0xAAAA_AAAA);
    assert_eq!(h.call(Sysno::SchedGetaffinity, &[0, 16, m]), 8);
    assert_eq!(
        h.call(Sysno::SchedGetaffinity, &[99_999, 2, m]),
        -i64::from(EINVAL)
    );
    assert_eq!(
        h.call(Sysno::SchedGetaffinity, &[99_999, 4, m]),
        -i64::from(ESRCH)
    );
    // setaffinity reads whole words: a 1-byte mask reads 4 bytes, which
    // must all be mapped.
    let g = h.ok(Sysno::Mmap2, &[0, 0x2000, 3, 0x22, reg(-1), 0]);
    h.ok(Sysno::Munmap, &[g + 0x1000, 0x1000]);
    put(&h, g + 0xFFC, &[1]);
    assert_eq!(h.call(Sysno::SchedSetaffinity, &[0, 1, g + 0xFFC]), 0);
    assert_eq!(
        h.call(Sysno::SchedSetaffinity, &[0, 1, g + 0xFFE]),
        -i64::from(EFAULT)
    );
    put(&h, m, &[2, 0, 0, 0]);
    assert_eq!(
        h.call(Sysno::SchedSetaffinity, &[0, 4, m]),
        -i64::from(EINVAL)
    );
}

#[test]
fn the_old_unames_nice_and_arch_prctl() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // olduname: struct old_utsname, five 65-byte fields.
    assert_eq!(h.call(Sysno::Olduname, &[m]), 0);
    assert_eq!(cstr(&h, m), "Linux");
    assert_eq!(cstr(&h, m + 4 * 65), "x86_64");
    assert_eq!(u32_at(&h, m + 5 * 65), 0xAAAA_AAAA, "no domain name");
    // oldolduname: five 9-byte fields, 8 bytes of each and a NUL.
    assert_eq!(h.call(Sysno::Oldolduname, &[m + 0x200]), 0);
    assert_eq!(cstr(&h, m + 0x200), "Linux");
    assert_eq!(cstr(&h, m + 0x200 + 4 * 9), "x86_64");
    assert_eq!(h.call(Sysno::Olduname, &[0]), -i64::from(EFAULT));
    // PER_LINUX32: machine i686 in every uname.
    h.ok(Sysno::Personality, &[8]);
    assert_eq!(h.call(Sysno::Uname, &[m + 0x400]), 0);
    assert_eq!(cstr(&h, m + 0x400 + 4 * 65), "i686");
    assert_eq!(h.call(Sysno::Oldolduname, &[m + 0x200]), 0);
    assert_eq!(cstr(&h, m + 0x200 + 4 * 9), "i686");
    // nice: relative, clamped; raising the priority needs the right.
    assert_eq!(h.call(Sysno::Nice, &[5]), 0);
    assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 20 - 5);
    assert_eq!(h.call(Sysno::Nice, &[100]), 0);
    assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 20 - 19);
    // arch_prctl: CPUID and XCOMP only (in_ia32_syscall).
    assert_eq!(h.call(Sysno::ArchPrctl, &[0x1011, 0]), 1, "ARCH_GET_CPUID");
    assert_eq!(
        h.call(Sysno::ArchPrctl, &[0x1002, m]),
        -i64::from(EINVAL),
        "ARCH_SET_FS"
    );
    assert_eq!(
        h.call(Sysno::ArchPrctl, &[0x5005, m]),
        -i64::from(EINVAL),
        "ARCH_SHSTK_STATUS"
    );
}
