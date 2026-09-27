//! `rax-user`: run a Linux or macOS user-space program on RAX's software
//! CPUs.
//!
//! ```text
//! rax-user [OPTIONS] <PROGRAM> [ARGS]...
//! ```
//!
//! The personality follows the executable's format: an ELF file runs under
//! the Linux personality (x86-64, AArch64, RV64, or the partial i386 and ARM
//! EABI compatibility ones, from the ELF header), a Mach-O or fat file under
//! the Darwin personality (x86-64 or arm64; `--arch` picks a fat file's
//! slice).
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
        about = "Run a Linux (x86-64, AArch64, RV64; partial i386 and ARM EABI) or macOS (x86-64, arm64) user-space program on RAX's software CPUs",
        long_about = "rax-user loads a Linux ELF executable as the kernel's binfmt_elf would \
(with address-space randomization disabled), executes it on RAX's x86-64, AArch64, AArch32, or \
RISC-V CPU in user mode, and services its system calls on the host. ELF32 i386 programs, and \
ARM EABI programs as an arm64 kernel runs them, use a partial compatibility syscall table and \
interpreter-only execution. Dynamically linked programs find their interpreter and libraries \
through --sysroot, as with QEMU's -L. A Mach-O program runs under the Darwin personality: \
rax-user maps it and /usr/lib/dyld as XNU's exec does, and dyld maps the dyld shared cache \
through the emulated shared-region calls; --sysroot supplies dyld and the cache on a host that \
is not a Mac.",
        trailing_var_arg = true
    )]
    pub struct Cli {
        /// Guest root overlay: absolute guest paths that exist under DIR
        /// resolve there (QEMU -L semantics).
        #[arg(short = 'L', long, value_name = "DIR")]
        pub sysroot: Option<PathBuf>,
        /// Set an environment variable (repeatable).
        #[arg(short = 'E', long = "env", value_name = "VAR=VALUE")]
        pub set_env: Vec<String>,
        /// Remove an environment variable (repeatable).
        #[arg(short = 'U', long = "unset-env", value_name = "VAR")]
        pub unset_env: Vec<String>,
        /// Start from an empty environment instead of rax-user's own.
        #[arg(long)]
        pub clear_env: bool,
        /// Use NAME as argv[0] instead of PROGRAM.
        #[arg(short = '0', long, value_name = "NAME")]
        argv0: Option<String>,
        /// Guest working directory (default: the current directory).
        #[arg(short = 'C', long, value_name = "DIR")]
        pub cwd: Option<String>,
        /// Log every system call to standard error.
        #[arg(long)]
        pub strace: bool,
        /// Deterministic seed for AT_RANDOM and getrandom (default: host entropy).
        #[arg(long, value_name = "N")]
        pub seed: Option<u64>,
        /// RLIMIT_STACK soft limit and [stack] mapping size (default 8M).
        #[arg(short = 's', long, value_name = "SIZE", value_parser = parse_size)]
        pub stack_size: Option<u64>,
        /// Guest memory arena size; committed on demand (default 16G).
        #[arg(long, value_name = "SIZE", value_parser = parse_size)]
        pub memory: Option<u64>,
        /// Execute RISC-V guests through the SMIR JIT where available.
        #[arg(long)]
        pub riscv_jit: bool,
        /// Kernel release reported by uname (default 6.19.0).
        #[arg(long, value_name = "RELEASE")]
        pub kernel_release: Option<String>,
        /// Instructions per scheduling slice for AArch64 and RV64 guests.
        #[arg(long, value_name = "N")]
        pub slice: Option<u64>,
        /// Architecture to run a universal (fat) Mach-O file as:
        /// `x86_64` or `arm64` (default: the host's).
        #[arg(long, value_name = "ARCH")]
        pub arch: Option<String>,
        /// Leave host signals at their host dispositions instead of
        /// forwarding them to the guest, and report every guest killed by a
        /// signal with exit status 128 + N.
        #[arg(long)]
        pub no_signal_forwarding: bool,
        /// The Linux executable.
        #[arg(value_name = "PROGRAM")]
        pub program: PathBuf,
        /// Arguments passed to the program.
        #[arg(value_name = "ARGS", allow_hyphen_values = true)]
        pub args: Vec<String>,
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
        if rax::user::image::macho::is_macho(&bytes) {
            return crate::darwin::run(&cli, &program, argv, environment(&cli));
        }
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
        // Guest processes are host processes: fork forks rax-user.
        config.processes = true;
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

/// The Darwin personality's front end.
#[cfg(unix)]
mod darwin {
    use rax::user::darwin::abi::DarwinAbi;
    use rax::user::darwin::loader::ImageFile;
    use rax::user::darwin::{DarwinConfig, DarwinProcess, ExitStatus};

    pub fn run(
        cli: &super::unix::Cli,
        program: &str,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
    ) -> i32 {
        let abi = match cli.arch.as_deref() {
            None => None,
            Some("x86_64") => Some(DarwinAbi::X86_64),
            Some("arm64") | Some("arm64e") | Some("aarch64") => Some(DarwinAbi::Arm64),
            Some(other) => {
                eprintln!("rax-user: unknown --arch {other:?} (x86_64 or arm64)");
                return 125;
            }
        };
        let host = match &cli.sysroot {
            Some(root) if program.starts_with('/') => {
                let under = root.join(program.trim_start_matches('/'));
                if under.exists() {
                    under
                } else {
                    program.into()
                }
            }
            _ => std::path::PathBuf::from(program),
        };
        let image = match ImageFile::read(program, &host) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("rax-user: {program}: {e}");
                return 126;
            }
        };
        let mut config = DarwinConfig::new(program, argv, envp);
        config.root = cli.sysroot.clone();
        config.abi = abi;
        if let Some(cwd) = &cli.cwd {
            config.cwd = cwd.clone();
        }
        config.strace = cli.strace;
        config.seed = cli.seed;
        config.stack_limit = cli.stack_size;
        if let Some(m) = cli.memory {
            config.arena_bytes = m;
        }
        if let Some(n) = cli.slice {
            config.slice_insns = n.max(1);
        }
        // What the guest inherits across exec is what this process
        // inherited (before its own handlers go in).
        config.inherited = Some(rax::user::darwin::signal::host::inherited());
        if !cli.no_signal_forwarding {
            // The guest is this process: host signals are its signals, and
            // its stops stop this process.
            if let Err(e) = rax::user::darwin::signal::host::forward() {
                eprintln!("rax-user: cannot forward host signals: {e:?}");
                return 125;
            }
            config.host_job_control = true;
        }
        let mut process = match DarwinProcess::spawn(config, image) {
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
        if let ExitStatus::Signaled {
            signo, core: false, ..
        } = status
            && !cli.no_signal_forwarding
        {
            // Die by the guest's signal so the parent sees a signal death;
            // core-dumping signals are reported as 128 + N instead, so the
            // host records no crash of the emulator.
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            rax::user::darwin::signal::die_by_signal(signo);
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
