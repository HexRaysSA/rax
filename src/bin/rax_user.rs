//! `rax-user`: run a Linux user-space program on RAX's software CPUs.
//!
//! ```text
//! rax-user [OPTIONS] <PROGRAM> [ARGS]...
//! ```
//!
//! The guest ABI (x86-64, AArch64, or RV64) is taken from the ELF header.
//! The exit status is the guest's: its `exit` code; when a signal killed it,
//! death by the same signal, or `128 + N` for a signal whose default action
//! dumps core (so the host records no crash of the emulator) or that the
//! host lacks; 125 for an emulator failure; 126 when the program cannot be
//! executed; and 127 when it cannot be found. Asynchronous host signals
//! (terminal interrupts, `kill` from other processes, window changes, ...)
//! are forwarded to the guest.

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;

    use clap::Parser;
    use rax::user::linux::loader::ImageFile;
    use rax::user::linux::{ExitStatus, LinuxConfig, LinuxProcess};

    /// Parses a byte size with an optional `K`, `M`, `G`, or `T` suffix
    /// (binary multiples).
    fn parse_size(s: &str) -> Result<u64, String> {
        let s = s.trim();
        let (digits, shift) = match s.char_indices().last() {
            Some((i, c)) if c.is_ascii_alphabetic() => {
                let shift = match c.to_ascii_uppercase() {
                    'K' => 10,
                    'M' => 20,
                    'G' => 30,
                    'T' => 40,
                    _ => return Err(format!("unknown size suffix in {s:?}")),
                };
                (&s[..i], shift)
            }
            _ => (s, 0),
        };
        let n: u64 = digits.parse().map_err(|_| format!("invalid size {s:?}"))?;
        n.checked_shl(shift)
            .filter(|v| v >> shift == n)
            .ok_or_else(|| format!("size {s:?} overflows"))
    }

    #[derive(Parser, Debug)]
    #[command(
        name = "rax-user",
        version,
        about = "Run a Linux user-space program (x86-64, AArch64, RV64) on RAX's software CPUs",
        long_about = "rax-user loads a Linux ELF executable as the kernel's binfmt_elf would \
(with address-space randomization disabled), executes it on RAX's x86-64, AArch64, or RISC-V \
CPU in user mode, and services its system calls on the host. Dynamically linked programs find \
their interpreter and libraries through --sysroot, as with QEMU's -L.",
        trailing_var_arg = true
    )]
    struct Cli {
        /// Guest root overlay: absolute guest paths that exist under DIR
        /// resolve there (QEMU -L semantics).
        #[arg(short = 'L', long, value_name = "DIR")]
        sysroot: Option<PathBuf>,
        /// Set an environment variable (repeatable).
        #[arg(short = 'E', long = "env", value_name = "VAR=VALUE")]
        set_env: Vec<String>,
        /// Remove an environment variable (repeatable).
        #[arg(short = 'U', long = "unset-env", value_name = "VAR")]
        unset_env: Vec<String>,
        /// Start from an empty environment instead of rax-user's own.
        #[arg(long)]
        clear_env: bool,
        /// Use NAME as argv[0] instead of PROGRAM.
        #[arg(short = '0', long, value_name = "NAME")]
        argv0: Option<String>,
        /// Guest working directory (default: the current directory).
        #[arg(short = 'C', long, value_name = "DIR")]
        cwd: Option<String>,
        /// Log every system call to standard error.
        #[arg(long)]
        strace: bool,
        /// Deterministic seed for AT_RANDOM and getrandom (default: host entropy).
        #[arg(long, value_name = "N")]
        seed: Option<u64>,
        /// RLIMIT_STACK soft limit and [stack] mapping size (default 8M).
        #[arg(short = 's', long, value_name = "SIZE", value_parser = parse_size)]
        stack_size: Option<u64>,
        /// Guest memory arena size; committed on demand (default 16G).
        #[arg(long, value_name = "SIZE", value_parser = parse_size)]
        memory: Option<u64>,
        /// Execute RISC-V guests through the SMIR JIT where available.
        #[arg(long)]
        riscv_jit: bool,
        /// Kernel release reported by uname (default 6.19.0).
        #[arg(long, value_name = "RELEASE")]
        kernel_release: Option<String>,
        /// Instructions per scheduling slice for AArch64 and RV64 guests.
        #[arg(long, value_name = "N")]
        slice: Option<u64>,
        /// Leave host signals at their host dispositions instead of
        /// forwarding them to the guest, and report every guest killed by a
        /// signal with exit status 128 + N.
        #[arg(long)]
        no_signal_forwarding: bool,
        /// The Linux executable.
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,
        /// Arguments passed to the program.
        #[arg(value_name = "ARGS", allow_hyphen_values = true)]
        args: Vec<String>,
    }

    fn environment(cli: &Cli) -> Vec<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let mut env: Vec<(Vec<u8>, Vec<u8>)> = if cli.clear_env {
            Vec::new()
        } else {
            std::env::vars_os()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect()
        };
        for name in &cli.unset_env {
            env.retain(|(k, _)| k.as_slice() != name.as_bytes());
        }
        for pair in &cli.set_env {
            let (k, v) = pair.split_once('=').unwrap_or((pair.as_str(), ""));
            env.retain(|(ek, _)| ek.as_slice() != k.as_bytes());
            env.push((k.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        env.into_iter()
            .map(|(mut k, v)| {
                k.push(b'=');
                k.extend_from_slice(&v);
                k
            })
            .collect()
    }

    pub fn main() -> i32 {
        let cli = Cli::parse();
        let program = cli.program.to_string_lossy().into_owned();
        let bytes = match std::fs::read(&cli.program) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("rax-user: {program}: {e}");
                return if e.kind() == std::io::ErrorKind::NotFound {
                    127
                } else {
                    126
                };
            }
        };
        let argv0 = cli.argv0.clone().unwrap_or_else(|| program.clone());
        let argv: Vec<Vec<u8>> = std::iter::once(argv0)
            .chain(cli.args.iter().cloned())
            .map(String::into_bytes)
            .collect();
        let mut config = LinuxConfig::new(program.clone(), argv, environment(&cli));
        config.sysroot = cli.sysroot.clone();
        if let Some(cwd) = &cli.cwd {
            config.cwd = cwd.clone();
        }
        config.strace = cli.strace;
        config.seed = cli.seed;
        if let Some(s) = cli.stack_size {
            config.stack_limit = s;
        }
        if let Some(m) = cli.memory {
            config.arena_bytes = m;
        }
        config.cpu.riscv_jit = cli.riscv_jit;
        if let Some(r) = &cli.kernel_release {
            config.kernel_release = r.clone();
        }
        if let Some(n) = cli.slice {
            config.slice_insns = n.max(1);
        }
        if !cli.no_signal_forwarding
            && let Err(e) = rax::user::linux::host::forward_host_signals()
        {
            eprintln!("rax-user: cannot forward host signals: {e:?}");
            return 125;
        }
        let mut process = match LinuxProcess::spawn(config, ImageFile::new(bytes, program.clone()))
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("rax-user: {program}: {e}");
                return 126;
            }
        };
        let status = process.run();
        if !matches!(status, ExitStatus::Exited(_)) {
            eprintln!("rax-user: {program}: {status}");
        }
        if let ExitStatus::Signaled { info, core, .. } = &status
            && !cli.no_signal_forwarding
            && !core
        {
            // Die by the guest's signal so the parent sees a signal death.
            // Core-dumping signals are reported as 128 + N instead, so the
            // host records no crash of the emulator.
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            rax::user::linux::host::die_by_signal(info.signo);
        }
        status.shell_code()
    }
}

#[cfg(unix)]
fn main() {
    let code = unix::main();
    // Flush Rust's buffered standard streams before leaving.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}

#[cfg(not(unix))]
fn main() {
    eprintln!("rax-user: the Linux personality requires a Unix host (Linux or macOS)");
    std::process::exit(125);
}
