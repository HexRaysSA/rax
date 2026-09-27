//! `rax-user`: run Linux ELF or Windows PE programs on RAX's software CPUs.
//!
//! ```text
//! rax-user [OPTIONS] <PROGRAM> [ARGS]...
//! ```
//!
//! The guest ABI (x86-64, AArch64, RV64, or partial i386 compatibility)
//! is taken from the ELF header.
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
    use rax::user::windows::{WindowsConfig, WindowsProcess};

    #[derive(clap::ValueEnum, Clone, Copy, Debug)]
    enum Personality {
        Auto,
        Linux,
        Windows,
    }

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
        about = "Run a Linux ELF or Windows PE program on RAX's software CPUs",
        long_about = "rax-user selects Linux for ELF and Windows for PE images. Windows guests \
use x86, x64, or ARM64 instructions with emulated DLL services. Linux guests load as binfmt_elf would \
(with address-space randomization disabled), executes it on RAX's x86-64, AArch64, or RISC-V \
CPU in user mode, and services its system calls on the host. ELF32 i386 programs use a partial \
compatibility syscall table and interpreter-only execution. Dynamically linked programs find \
their interpreter and libraries through --sysroot, as with QEMU's -L.",
        trailing_var_arg = true
    )]
    struct Cli {
        /// OS personality; auto selects from the executable file signature.
        #[arg(long, value_enum, default_value_t = Personality::Auto)]
        os: Personality,
        /// Map a Windows drive letter to a host directory (repeatable C=/dir).
        #[arg(long, value_name = "LETTER=DIR")]
        drive: Vec<String>,
        /// Additional Windows DLL search directory (repeatable).
        #[arg(long, value_name = "DIR")]
        dll_path: Vec<PathBuf>,
        /// Exact Windows command line, overriding the generated argument string.
        #[arg(long, value_name = "TEXT")]
        command_line: Option<String>,
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
        /// The ELF or PE executable.
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
        if matches!(cli.os, Personality::Windows)
            || matches!(cli.os, Personality::Auto) && bytes.starts_with(b"MZ")
        {
            let mut config = WindowsConfig::new(cli.program.clone(), cli.args.clone());
            config.argv0 = cli.argv0.clone();
            config.command_line = cli.command_line.clone();
            config.cwd = cli.cwd.clone();
            config.dll_paths = cli.dll_path.clone();
            config.trace = cli.strace;
            config.seed = cli.seed;
            if let Some(size) = cli.memory {
                config.arena_bytes = size;
            }
            if let Some(slice) = cli.slice {
                config.slice_insns = slice.max(1);
            }
            if cli.clear_env {
                config.env = Some(Vec::new());
            }
            if !cli.unset_env.is_empty() {
                let arch = rax::user::image::pe::PeImage::parse(bytes.clone())
                    .ok()
                    .and_then(|p| rax::user::windows::WinArch::from_machine(p.headers().machine));
                if let Some(arch) = arch {
                    let mut env = config
                        .env
                        .clone()
                        .unwrap_or_else(|| config.default_environment(arch));
                    env.retain(|(key, _)| {
                        !cli.unset_env
                            .iter()
                            .any(|unset| key.eq_ignore_ascii_case(unset))
                    });
                    config.env = Some(env);
                }
            }
            for pair in &cli.set_env {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                config
                    .env_overrides
                    .push((name.to_owned(), value.to_owned()));
            }
            for drive in &cli.drive {
                let Some((letter, root)) = drive.split_once('=') else {
                    eprintln!("rax-user: invalid drive mapping {drive:?}: expected LETTER=DIR");
                    return 126;
                };
                let letter = letter.strip_suffix(':').unwrap_or(letter);
                if letter.len() != 1
                    || !letter.as_bytes()[0].is_ascii_alphabetic()
                    || root.is_empty()
                {
                    eprintln!("rax-user: invalid drive mapping {drive:?}");
                    return 126;
                }
                config.drives.set(
                    letter.chars().next().expect("one ASCII letter"),
                    PathBuf::from(root),
                );
            }
            let mut process = match WindowsProcess::spawn_image(config, bytes) {
                Ok(process) => process,
                Err(e) => {
                    eprintln!("rax-user: {program}: {e}");
                    return (e.exit_code() & 0xFF) as i32;
                }
            };
            let status = process.run();
            if !matches!(status, rax::user::windows::ExitStatus::Exited(0)) {
                eprintln!("rax-user: {program}: {status}");
            }
            return status.shell_code();
        }
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
