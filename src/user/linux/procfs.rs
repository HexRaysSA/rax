//! Synthesized `/proc` and `/sys` entries describing the emulated process.
//!
//! The host's `/proc` describes the emulator (on Linux) or does not exist
//! (on macOS), so every entry a guest reads about itself is generated from
//! the personality's state: `/proc/self` and `/proc/<pid>` for the guest's
//! process (as its leader thread shows it), `/proc/self/task/<tid>`,
//! `/proc/thread-self`, and `/proc/<tid>` for each thread, and the handful
//! of system-wide files C libraries and language runtimes consult. Formats
//! follow `fs/proc/task_mmu.c`, `fs/proc/array.c`, and `fs/proc/base.c`.

use std::fmt::Write as _;

use super::abi::LinuxAbi;
use super::fs::fd::DirEntry;
use super::process::{ProcState, Thread};
use crate::user::mm::{Backing, Perms};

/// A synthesized entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcEntry {
    /// A regular file with this content.
    File(Vec<u8>),
    /// A thread's `comm` file: its name and a newline, writable by the
    /// process's threads (`comm_write`).
    Comm {
        /// The thread.
        tid: i32,
        /// Current content.
        text: Vec<u8>,
    },
    /// A symbolic link with this target.
    Link(String),
    /// A directory with these entries.
    Dir(Vec<DirEntry>),
}

/// Well-known inode numbers for synthesized entries (stable, nonzero).
const PROC_INO: u64 = 0x5241_5800;

fn dir(names: &[&str]) -> ProcEntry {
    let mut v = vec![
        DirEntry {
            ino: PROC_INO,
            dtype: super::fs::fd::dt::DT_DIR,
            name: b".".to_vec(),
        },
        DirEntry {
            ino: PROC_INO,
            dtype: super::fs::fd::dt::DT_DIR,
            name: b"..".to_vec(),
        },
    ];
    use super::fs::fd::dt::{DT_DIR, DT_LNK, DT_REG};
    for (i, n) in names.iter().enumerate() {
        let dtype = match *n {
            "fd" | "fdinfo" | "task" | "self" | "thread-self" => DT_DIR,
            "exe" | "cwd" | "root" => DT_LNK,
            _ => DT_REG,
        };
        v.push(DirEntry {
            ino: PROC_INO + 1 + i as u64,
            dtype,
            name: n.as_bytes().to_vec(),
        });
    }
    ProcEntry::Dir(v)
}

/// `/proc/self/maps`.
pub fn maps(p: &ProcState) -> Vec<u8> {
    let mut out = String::new();
    for v in p.space.vma_snapshot() {
        let id = v.backing.identity();
        let offset = v.backing.offset();
        let (major, minor) = match &v.backing {
            // Anonymous shared memory is a shmem inode (device 0:1).
            Backing::Shared { object, .. } if object.is_anonymous() => (0, 1),
            _ => (((id.dev >> 8) & 0xfff) as u32, (id.dev & 0xff) as u32),
        };
        let mut line = format!(
            "{:08x}-{:08x} {}{}{}{} {:08x} {:02x}:{:02x} {} ",
            v.start,
            v.end,
            if v.perms.contains(Perms::READ) {
                'r'
            } else {
                '-'
            },
            if v.perms.contains(Perms::WRITE) {
                'w'
            } else {
                '-'
            },
            if v.perms.contains(Perms::EXEC) {
                'x'
            } else {
                '-'
            },
            if v.shared { 's' } else { 'p' },
            offset,
            major,
            minor,
            id.ino,
        );
        let name = v.name.as_deref();
        if let Some(name) = name {
            // seq_pad() pads the prefix to 72 columns, then a space.
            while line.len() < 72 {
                line.push(' ');
            }
            line.push(' ');
            line.push_str(name);
        }
        line.push('\n');
        out.push_str(&line);
    }
    out.into_bytes()
}

/// `/proc/self/auxv`: the saved vector as native-endian words.
pub fn auxv(p: &ProcState) -> Vec<u8> {
    p.auxv
        .iter()
        .flat_map(|&(k, v)| k.to_le_bytes().into_iter().chain(v.to_le_bytes()))
        .collect()
}

/// A thread's scheduler state letter (`task_state_array`): sleeping in a
/// system call, or runnable.
fn state(t: &Thread) -> (&'static str, &'static str) {
    if t.blocked.is_some() {
        ("S", "S (sleeping)")
    } else {
        ("R", "R (running)")
    }
}

/// `/proc/<pid>/stat` (`do_task_stat`), 52 fields, for thread `t` of a
/// process with `threads` threads.
pub fn stat(p: &ProcState, t: &Thread, threads: usize) -> Vec<u8> {
    let comm = String::from_utf8_lossy(&t.comm);
    let mm = &p.mm;
    let st = &mm.stack;
    let prog = &mm.program;
    let vsize: u64 = p.space.vma_snapshot().iter().map(|v| v.end - v.start).sum();
    let rss = p.space.resident_pages();
    let fields: Vec<String> = vec![
        t.tid.to_string(),
        format!("({comm})"),
        state(t).0.into(),
        p.ppid.to_string(),
        p.pid.to_string(), // pgrp
        p.pid.to_string(), // session
        "0".into(),        // tty_nr
        "-1".into(),       // tpgid
        "4194304".into(),  // flags (PF_RANDOMIZE clear)
        "0".into(),
        "0".into(),
        "0".into(),
        "0".into(), // min/maj faults
        "0".into(),
        "0".into(),
        "0".into(),
        "0".into(), // utime stime cutime cstime
        "20".into(),
        "0".into(),          // priority nice
        threads.to_string(), // num_threads
        "0".into(),          // itrealvalue
        "0".into(),          // starttime
        vsize.to_string(),
        rss.to_string(),
        u64::MAX.to_string(), // rsslim
        prog.start_code.to_string(),
        prog.end_code.to_string(),
        st.stack_bottom.max(st.sp & !0xFFF).to_string(), // startstack
        t.cpu.sp().to_string(),
        t.cpu.pc().to_string(),
        "0".into(),
        "0".into(),
        "0".into(),
        "0".into(), // signal blocked sigignore sigcatch
        "0".into(), // wchan
        "0".into(),
        "0".into(),
        "17".into(), // exit_signal
        "0".into(),  // processor
        "0".into(),
        "0".into(), // rt_priority policy
        "0".into(), // delayacct
        "0".into(),
        "0".into(), // guest times
        prog.start_data.to_string(),
        prog.end_data.to_string(),
        mm.start_brk.to_string(),
        st.arg_start.to_string(),
        st.arg_end.to_string(),
        st.env_start.to_string(),
        st.env_end.to_string(),
        "0".into(), // exit_code
    ];
    let mut s = fields.join(" ");
    s.push('\n');
    s.into_bytes()
}

/// `/proc/<pid>/status` (the fields programs commonly parse) for thread
/// `t` of a process with `threads` threads.
pub fn status(p: &ProcState, t: &Thread, threads: usize) -> Vec<u8> {
    let comm = String::from_utf8_lossy(&t.comm);
    let (uid, euid, gid, egid) = p.creds;
    let vsize: u64 = p.space.vma_snapshot().iter().map(|v| v.end - v.start).sum();
    let rss_kb = p.space.resident_pages() * 4;
    let mut s = String::new();
    let _ = writeln!(s, "Name:\t{comm}");
    let _ = writeln!(s, "Umask:\t{:04o}", p.umask);
    let _ = writeln!(s, "State:\t{}", state(t).1);
    let _ = writeln!(s, "Tgid:\t{}", p.pid);
    let _ = writeln!(s, "Ngid:\t0");
    let _ = writeln!(s, "Pid:\t{}", t.tid);
    let _ = writeln!(s, "PPid:\t{}", p.ppid);
    let _ = writeln!(s, "TracerPid:\t0");
    let _ = writeln!(s, "Uid:\t{uid}\t{euid}\t{euid}\t{euid}");
    let _ = writeln!(s, "Gid:\t{gid}\t{egid}\t{egid}\t{egid}");
    let _ = writeln!(s, "FDSize:\t64");
    let _ = writeln!(s, "Groups:\t");
    let _ = writeln!(s, "VmPeak:\t{:8} kB", vsize / 1024);
    let _ = writeln!(s, "VmSize:\t{:8} kB", vsize / 1024);
    let _ = writeln!(s, "VmRSS:\t{:8} kB", rss_kb);
    let _ = writeln!(s, "Threads:\t{threads}");
    // task_sig: queued records against RLIMIT_SIGPENDING, then the pending,
    // blocked, ignored, and caught sets.
    let queued = t.pending.queued() + p.shared_pending.queued();
    let _ = writeln!(s, "SigQ:\t{queued}/{}", p.rlimits[11].0);
    let (mut ignored, mut caught) = (0u64, 0u64);
    for (i, a) in p.sigactions.iter().enumerate() {
        match a.handler {
            super::signal::SIG_DFL => {}
            super::signal::SIG_IGN => ignored |= 1 << i,
            _ => caught |= 1 << i,
        }
    }
    let _ = writeln!(s, "SigPnd:\t{:016x}", t.pending.set());
    let _ = writeln!(s, "ShdPnd:\t{:016x}", p.shared_pending.set());
    let _ = writeln!(s, "SigBlk:\t{:016x}", t.sigmask);
    let _ = writeln!(s, "SigIgn:\t{ignored:016x}");
    let _ = writeln!(s, "SigCgt:\t{caught:016x}");
    let _ = writeln!(s, "Seccomp:\t0");
    let _ = writeln!(s, "Cpus_allowed:\t1");
    let _ = writeln!(s, "Cpus_allowed_list:\t0");
    s.into_bytes()
}

/// `/proc/cpuinfo` for the single emulated CPU.
pub fn cpuinfo(abi: LinuxAbi) -> Vec<u8> {
    match abi {
        LinuxAbi::X86_64 => concat!(
            "processor\t: 0\n",
            "vendor_id\t: GenuineIntel\n",
            "cpu family\t: 6\n",
            "model\t\t: 15\n",
            "model name\t: RAX x86-64 user-mode CPU\n",
            "stepping\t: 1\n",
            "cpu MHz\t\t: 3000.000\n",
            "physical id\t: 0\n",
            "siblings\t: 1\n",
            "core id\t\t: 0\n",
            "cpu cores\t: 1\n",
            "fpu\t\t: yes\n",
            "flags\t\t: fpu de pse tsc msr pae cx8 apic sep pge cmov clflush mmx fxsr sse sse2 ",
            "syscall nx rdtscp lm pni pclmulqdq monitor ssse3 fma cx16 pcid sse4_1 sse4_2 movbe ",
            "popcnt aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch fsgsbase bmi1 avx2 bmi2 ",
            "erms invpcid avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd ",
            "sha_ni avx512bw avx512vl\n",
            "clflush size\t: 64\n",
            "address sizes\t: 48 bits physical, 48 bits virtual\n",
            "\n"
        )
        .as_bytes()
        .to_vec(),
        LinuxAbi::Aarch64 => concat!(
            "processor\t: 0\n",
            "BogoMIPS\t: 125.00\n",
            "Features\t: fp asimd aes sha1 sha2 crc32 atomics cpuid\n",
            "CPU implementer\t: 0x41\n",
            "CPU architecture: 8\n",
            "CPU variant\t: 0x0\n",
            "CPU part\t: 0xd08\n",
            "CPU revision\t: 3\n",
            "\n"
        )
        .as_bytes()
        .to_vec(),
        LinuxAbi::Riscv64 => concat!(
            "processor\t: 0\n",
            "hart\t\t: 0\n",
            "isa\t\t: rv64imafdcv\n",
            "mmu\t\t: sv48\n",
            "uarch\t\t: rax,user\n",
            "\n"
        )
        .as_bytes()
        .to_vec(),
    }
}

/// Looks up a synthesized path for thread `cur` of a process whose threads
/// are `threads` (in list order, `cur` among them). `guest` is absolute and
/// lexically joined. Returns `None` for paths the personality does not
/// synthesize.
pub fn lookup(p: &ProcState, cur: &Thread, threads: &[&Thread], guest: &str) -> Option<ProcEntry> {
    let path = guest.trim_end_matches('/');
    let find = |tid: i32| threads.iter().copied().find(|t| t.tid == tid);
    // The process directory shows the leader (the caller once the leader
    // has exited).
    let leader = find(p.pid).unwrap_or(cur);
    let under = |prefix: &str| -> Option<&str> {
        let rest = path.strip_prefix(prefix)?;
        (rest.is_empty() || rest.starts_with('/')).then(|| rest.trim_start_matches('/'))
    };
    if let Some(rest) = under("/proc/self") {
        return process_entry(p, leader, threads, rest);
    }
    if let Some(rest) = under("/proc/thread-self") {
        return thread_entry(p, cur, threads, rest, false);
    }
    if let Some(num) = path.strip_prefix("/proc/") {
        let (id, rest) = num.split_once('/').unwrap_or((num, ""));
        if let Ok(id) = id.parse::<i32>() {
            if id == p.pid {
                return process_entry(p, leader, threads, rest);
            }
            // /proc/<tid> of another thread: not listed, but present.
            return find(id).and_then(|t| thread_entry(p, t, threads, rest, true));
        }
    }
    match path {
        "/proc" => Some(dir(&[
            "self",
            "thread-self",
            "cpuinfo",
            "meminfo",
            "uptime",
            "version",
        ])),
        "/proc/cpuinfo" => Some(ProcEntry::File(cpuinfo(p.abi))),
        "/proc/version" => Some(ProcEntry::File(
            format!(
                "Linux version {} (rax-user) #1 SMP PREEMPT_DYNAMIC\n",
                p.config.kernel_release
            )
            .into_bytes(),
        )),
        "/proc/sys/kernel/osrelease" => Some(ProcEntry::File(
            format!("{}\n", p.config.kernel_release).into_bytes(),
        )),
        "/proc/sys/kernel/ostype" => Some(ProcEntry::File(b"Linux\n".to_vec())),
        "/proc/sys/kernel/pid_max" => Some(ProcEntry::File(b"4194304\n".to_vec())),
        "/proc/sys/vm/overcommit_memory" => Some(ProcEntry::File(b"0\n".to_vec())),
        "/proc/sys/vm/mmap_min_addr" => Some(ProcEntry::File(b"65536\n".to_vec())),
        "/proc/uptime" => {
            let (s, ns) = super::host::clock_gettime(super::host::HostClock::Monotonic);
            Some(ProcEntry::File(
                format!("{}.{:02} 0.00\n", s, ns / 10_000_000).into_bytes(),
            ))
        }
        "/proc/meminfo" => {
            let total = p.config.arena_bytes / 1024;
            let used = p.space.resident_pages() * 4;
            Some(ProcEntry::File(
                format!(
                    "MemTotal:       {total:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\n",
                    total - used,
                    total - used
                )
                .into_bytes(),
            ))
        }
        "/sys/devices/system/cpu/online"
        | "/sys/devices/system/cpu/possible"
        | "/sys/devices/system/cpu/present" => Some(ProcEntry::File(b"0\n".to_vec())),
        _ => None,
    }
}

/// Whether `guest` lies where this process's `/proc` entries come and go
/// with its descriptors and threads (under `fd/`, `fdinfo/`, or `task/`
/// of `/proc/self`, `/proc/thread-self`, or `/proc/<id>` for its own IDs).
/// [`lookup`] finding nothing there means the entry does not exist: the
/// host's `/proc` would describe the emulator's own descriptors and
/// threads.
pub fn owned(p: &ProcState, threads: &[&Thread], guest: &str) -> bool {
    let path = guest.trim_end_matches('/');
    let rest = if let Some(r) = path.strip_prefix("/proc/self/") {
        r
    } else if let Some(r) = path.strip_prefix("/proc/thread-self/") {
        r
    } else if let Some((id, r)) = path.strip_prefix("/proc/").and_then(|n| n.split_once('/')) {
        match id.parse::<i32>() {
            Ok(id) if id == p.pid || threads.iter().any(|t| t.tid == id) => r,
            _ => return false,
        }
    } else {
        return false;
    };
    ["fd/", "fdinfo/", "task/"]
        .iter()
        .any(|d| rest.starts_with(d))
}

/// An entry of the process directory: its `task` directory, or what
/// thread `t` (the leader) shows.
fn process_entry(p: &ProcState, t: &Thread, threads: &[&Thread], rest: &str) -> Option<ProcEntry> {
    if rest == "task" {
        let mut v = dot_entries();
        for th in threads {
            v.push(DirEntry {
                ino: PROC_INO + 0x10_0000 + th.tid as u64,
                dtype: super::fs::fd::dt::DT_DIR,
                name: th.tid.to_string().into_bytes(),
            });
        }
        return Some(ProcEntry::Dir(v));
    }
    if let Some(task) = rest.strip_prefix("task/") {
        let (id, rest) = task.split_once('/').unwrap_or((task, ""));
        let id = id.parse::<i32>().ok()?;
        let th = threads.iter().copied().find(|t| t.tid == id)?;
        return thread_entry(p, th, threads, rest, false);
    }
    // The process's comm is the leader's, kept after it exits.
    if rest == "comm" && t.tid != p.pid {
        let mut text = p.comm.clone();
        text.push(b'\n');
        return Some(ProcEntry::Comm { tid: p.pid, text });
    }
    thread_entry(p, t, threads, rest, true)
}

/// `.` and `..`.
fn dot_entries() -> Vec<DirEntry> {
    vec![
        DirEntry {
            ino: PROC_INO,
            dtype: super::fs::fd::dt::DT_DIR,
            name: b".".to_vec(),
        },
        DirEntry {
            ino: PROC_INO,
            dtype: super::fs::fd::dt::DT_DIR,
            name: b"..".to_vec(),
        },
    ]
}

/// An entry of thread `t`'s directory (`/proc/<pid>` when `process`, which
/// also lists `task`; `/proc/<pid>/task/<tid>` otherwise).
fn thread_entry(
    p: &ProcState,
    t: &Thread,
    all: &[&Thread],
    rest: &str,
    process: bool,
) -> Option<ProcEntry> {
    let threads = all.len();
    let file = |v: Vec<u8>| Some(ProcEntry::File(v));
    match rest {
        "" => {
            let mut names = vec![
                "auxv", "cmdline", "comm", "cwd", "environ", "exe", "fd", "fdinfo", "maps", "root",
                "stat", "status",
            ];
            if process {
                names.push("task");
            }
            Some(dir(&names))
        }
        "exe" => Some(ProcEntry::Link(p.exe_path.clone())),
        "cwd" => Some(ProcEntry::Link(p.vfs.cwd().to_string())),
        "root" => Some(ProcEntry::Link("/".into())),
        "maps" => file(maps(p)),
        "auxv" => file(auxv(p)),
        "cmdline" => file(p.cmdline.clone()),
        "environ" => file(p.environ.clone()),
        "comm" => {
            let mut text = t.comm.clone();
            text.push(b'\n');
            Some(ProcEntry::Comm { tid: t.tid, text })
        }
        "stat" => file(stat(p, t, threads)),
        "status" => file(status(p, t, threads)),
        "fd" => {
            let mut v = dot_entries();
            for fd in p.fds.open_fds() {
                v.push(DirEntry {
                    ino: PROC_INO + 0x1000 + fd as u64,
                    dtype: super::fs::fd::dt::DT_LNK,
                    name: fd.to_string().into_bytes(),
                });
            }
            Some(ProcEntry::Dir(v))
        }
        "fdinfo" => {
            let mut v = dot_entries();
            for fd in p.fds.open_fds() {
                v.push(DirEntry {
                    ino: PROC_INO + 0x2000 + fd as u64,
                    dtype: super::fs::fd::dt::DT_REG,
                    name: fd.to_string().into_bytes(),
                });
            }
            Some(ProcEntry::Dir(v))
        }
        _ if rest.starts_with("fdinfo/") => {
            let n = rest.strip_prefix("fdinfo/")?.parse::<i32>().ok()?;
            let own = |tid: i32| all.iter().any(|t| t.tid == tid);
            super::fdinfo::fdinfo(p, &own, n).map(ProcEntry::File)
        }
        _ => {
            let n = rest.strip_prefix("fd/")?.parse::<i32>().ok()?;
            let f = p.fds.get(n).ok()?;
            let target = match &f.file.host_path {
                Some(h) => p.vfs.guest_path_of(h),
                None => f.file.path.clone(),
            };
            Some(ProcEntry::Link(target))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn maps_prefix_width_matches_seq_setwidth() {
        // 25 + sizeof(void *) * 6 - 1 = 72 columns before the name's space.
        let prefix = format!(
            "{:08x}-{:08x} {} {:08x} {:02x}:{:02x} {} ",
            0x5555_5555_4000u64, 0x5555_5555_5000u64, "r-xp", 0, 8, 1, 1234
        );
        let mut line = prefix.clone();
        while line.len() < 72 {
            line.push(' ');
        }
        line.push(' ');
        line.push_str("/bin/true");
        assert_eq!(line.find("/bin/true"), Some(73));
    }
}
