use std::path::PathBuf;

use clap::Parser;

use rax::config::{
    Address, ArchKind, BackendKind, CliConfig, Endianness, FileConfig, HexagonIsa, MemorySize,
    VmConfig,
};
use rax::Result;
use rax::snapshot::Snapshot;
use rax::vmm::Vmm;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rax", about = "Minimal KVM-based hypervisor for x86_64")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum)]
    arch: Option<ArchKind>,
    #[arg(long, value_enum)]
    backend: Option<BackendKind>,
    #[arg(long, value_parser = clap::value_parser!(MemorySize))]
    memory: Option<MemorySize>,
    #[arg(long)]
    vcpus: Option<u8>,
    #[arg(long)]
    kernel: Option<PathBuf>,
    #[arg(long)]
    initrd: Option<PathBuf>,
    #[arg(long)]
    cmdline: Option<String>,
    #[arg(long, value_enum)]
    hexagon_isa: Option<HexagonIsa>,
    #[arg(long, value_enum)]
    hexagon_endian: Option<Endianness>,
    #[arg(long, value_parser = clap::value_parser!(Address))]
    hexagon_entry: Option<Address>,
    #[arg(long, value_parser = clap::value_parser!(Address))]
    hexagon_load_addr: Option<Address>,
    /// Output instruction trace file (SDE-compatible format)
    #[arg(long)]
    trace: Option<PathBuf>,
    /// Enable GDB server on specified port (requires --features debug)
    #[arg(long)]
    gdb: Option<u16>,
    /// Wait for GDB connection before starting execution
    #[arg(long)]
    wait_gdb: bool,
    /// Enable GDB protocol tracing (shows all RX/TX packets)
    #[arg(long)]
    gdb_trace: bool,
    /// Take snapshot every N instructions (0 = disabled)
    #[arg(long, default_value = "0")]
    snapshot_interval: u64,
    /// Take snapshot at specific instruction counts (comma-separated)
    #[arg(long, value_delimiter = ',')]
    snapshot_at: Vec<u64>,
    /// Directory to save snapshots
    #[arg(long)]
    snapshot_dir: Option<PathBuf>,
    /// Resume from snapshot file
    #[arg(long)]
    resume: Option<PathBuf>,
    /// Resume the whole machine from a checkpoint (.rxc). The checkpoint's
    /// embedded config is used, so no other flags are required; any flag you do
    /// pass overrides the embedded value (even nonsensical ones).
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// Output path for checkpoints triggered by the Ctrl-A s console hotkey or
    /// SIGUSR1 (default: ./checkpoint.rxc relative to the working directory).
    #[arg(long)]
    snapshot_out: Option<PathBuf>,
    /// Enable instruction profiling (requires --features profiling)
    #[arg(long)]
    profile: bool,
    /// JSON output path for profiling results
    #[arg(long)]
    profile_output: Option<PathBuf>,
    /// Live profiling stats interval (instructions, default: 10M, 0 = disabled)
    #[arg(long)]
    profile_interval: Option<u64>,
}

fn main() -> Result<()> {
    // Parse CLI first so we can check --gdb-trace
    let cli = Cli::parse();

    // Build log filter, adding gdb trace if requested
    let base_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let filter = if cli.gdb_trace {
        base_filter.add_directive("rax::gdb=trace".parse().unwrap())
    } else {
        base_filter
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let file_config = match cli.config.as_deref() {
        Some(path) => Some(FileConfig::load(path)?),
        None => None,
    };
    let cli_config = CliConfig {
        arch: cli.arch,
        backend: cli.backend,
        memory: cli.memory,
        vcpus: cli.vcpus,
        kernel: cli.kernel,
        initrd: cli.initrd,
        cmdline: cli.cmdline,
        hexagon_isa: cli.hexagon_isa,
        hexagon_endian: cli.hexagon_endian,
        hexagon_entry: cli.hexagon_entry,
        hexagon_load_addr: cli.hexagon_load_addr,
        // ARM options (not implemented yet via CLI)
        aarch64_isa: None,
        aarch32_isa: None,
        cortexm_isa: None,
        cortexr_isa: None,
        arm_entry: None,
        arm_load_addr: None,
        arm_dtb: None,
        trace: cli.trace,
        gdb_port: cli.gdb,
        wait_gdb: cli.wait_gdb,
        snapshot_interval: cli.snapshot_interval,
        snapshot_at: cli.snapshot_at,
        snapshot_dir: cli.snapshot_dir,
        resume: cli.resume,
        checkpoint: cli.checkpoint.clone(),
        snapshot_out: cli.snapshot_out,
        profile: cli.profile,
        profile_output: cli.profile_output,
        profile_interval: cli.profile_interval,
    };

    // Resolve the final config and any checkpoint to restore. With --checkpoint
    // the machine is rebuilt from the checkpoint's embedded config (no --kernel
    // required) and CLI flags override the embedded values; otherwise we build
    // from CLI + file config and optionally restore a legacy --resume file.
    let (config, restore, resume_bare): (VmConfig, Option<Snapshot>, bool) =
        if let Some(ckpt_path) = cli.checkpoint.clone() {
            let snapshot = Snapshot::load(&ckpt_path)?;
            tracing::info!("resuming from checkpoint {:?}", ckpt_path);
            tracing::info!("{}", snapshot.summary());
            let config = VmConfig::from_checkpoint(snapshot.config.clone(), cli_config)?;
            (config, Some(snapshot), true)
        } else {
            let config = VmConfig::from_sources(cli_config, file_config)?;
            let restore = match config.resume.clone() {
                Some(path) => {
                    tracing::info!("Loading snapshot from {:?}", path);
                    let snapshot = Snapshot::load(&path)?;
                    tracing::info!("{}", snapshot.summary());
                    Some(snapshot)
                }
                None => None,
            };
            (config, restore, false)
        };

    // Initialize profiling if requested
    #[cfg(feature = "profiling")]
    if config.profile {
        let profiling_config = rax::profiling::ProfilingConfig {
            track_memory: true,
            live_interval: config.profile_interval.unwrap_or(10_000_000),
            json_path: config.profile_output.clone(),
        };
        rax::profiling::init(profiling_config);
    }

    #[cfg(not(feature = "profiling"))]
    if config.profile {
        return Err(rax::error::Error::InvalidConfig(
            "--profile requires building with --features profiling".to_string(),
        ));
    }

    // Set up Ctrl+C handler for graceful shutdown
    #[cfg(feature = "profiling")]
    {
        ctrlc::set_handler(move || {
            eprintln!("\n[profiling] Caught SIGINT, shutting down...");
            rax::profiling::shutdown();
            std::process::exit(0);
        })
        .expect("Error setting Ctrl+C handler");
    }

    let mut vmm = if resume_bare {
        Vmm::new_resume(config)?
    } else {
        Vmm::new(config)?
    };

    // Restore the checkpoint (full machine image) if we loaded one.
    if let Some(snapshot) = restore {
        vmm.restore_snapshot(&snapshot)?;
    }

    vmm.run()?;

    // Shutdown profiling (exports JSON and prints summary)
    #[cfg(feature = "profiling")]
    rax::profiling::shutdown();

    Ok(())
}
