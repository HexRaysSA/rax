//! `rax-trace-map`: read a `rax-user --mem-trace` capture and show how the
//! guest used its address space.
//!
//! The report ranks contiguous regions by role (code, self-modifying code,
//! pointer tables, multi-writer contexts, stack, heap, plain data), lists the
//! code pages that wrote each region, and can emit JSON or a compact terminal
//! profile.

use std::path::PathBuf;

use clap::Parser;
use rax::observability::memtrace::analysis::{self, Options};

#[derive(Parser, Debug)]
#[command(
    name = "rax-trace-map",
    version,
    about = "Visualise memory access patterns in a rax-user instruction trace",
    long_about = "Reads the binary trace written by `rax-user --mem-trace FILE`. Regions are \
grouped by contiguous access pattern and classified as code, self-modifying or unpacked code, \
pointer/dispatch tables, multi-writer contexts, stack, heap, or data. For every region the \
report shows fetch/read/write counts, store widths, write coverage, ordering evidence, and the \
code pages that wrote it. Use --region or --page for a detailed view, or --json for \
machine-readable output."
)]
struct Cli {
    /// Trace file written by `rax-user --mem-trace`.
    #[arg(value_name = "TRACE")]
    trace: PathBuf,
    /// Number of regions in the table.
    #[arg(long, default_value_t = 40)]
    top: usize,
    /// Show every region.
    #[arg(long)]
    all: bool,
    /// Hide regions with fewer writes than this.
    #[arg(long, default_value_t = 0, value_name = "N")]
    min_writes: u64,
    /// Show details for the region containing this address (hex or decimal).
    #[arg(long, value_parser = parse_address, value_name = "ADDR")]
    region: Option<u64>,
    /// Show details for the page containing this address (hex or decimal).
    #[arg(long, value_parser = parse_address, value_name = "ADDR")]
    page: Option<u64>,
    /// Suppress the address-space character map.
    #[arg(long)]
    no_map: bool,
    /// Write a machine-readable JSON report.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// Print parse progress on stderr (default: only on a terminal).
    #[arg(long, conflicts_with = "no_progress")]
    progress: bool,
    /// Never print parse progress.
    #[arg(long)]
    no_progress: bool,
}

fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid address {text:?}"))
}

fn main() {
    let cli = Cli::parse();
    let opts = Options {
        top: cli.top,
        all: cli.all,
        min_writes: cli.min_writes,
        region: cli.region,
        page: cli.page,
        show_map: !cli.no_map,
        json: cli.json.clone(),
        progress: if cli.progress {
            true
        } else if cli.no_progress {
            false
        } else {
            std::io::IsTerminal::is_terminal(&std::io::stderr())
        },
    };
    match analysis::run(&cli.trace, &opts) {
        Ok(report) => {
            print!("{report}");
            if let Some(path) = &cli.json {
                eprintln!("wrote JSON report to {}", path.display());
            }
        }
        Err(error) => {
            eprintln!("rax-trace-map: {}: {error}", cli.trace.display());
            std::process::exit(1);
        }
    }
}
