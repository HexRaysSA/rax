//! Instruction and memory-access tracing for user-mode execution.
//!
//! The emulator already exposes a per-access stream to embedders through
//! [`crate::vm::vcpu::MemRecord`]. This module turns that stream into a compact
//! binary file, and [`analysis`] turns the file into a region-by-region view of
//! how a program touched its address space.
//!
//! The intended use is reverse engineering: run an obfuscated or virtualised
//! userland program under `rax-user --mem-trace`, then inspect where code lives,
//! which pages were written, which pages are read as pointer tables, and which
//! code pages write the same small data region (the signature of a VM context
//! written by a handler set).
//!
//! # File layout
//!
//! All integers are little-endian. The file starts with an eight-byte magic,
//! a `u32` version, and a `u32` architecture tag. It is followed by records of
//! exactly [`RECORD_LEN`] bytes:
//!
//! | offset | width | meaning |
//! |--------|-------|---------|
//! | 0      | 1     | tag ([`TAG_READ`], [`TAG_WRITE`], [`TAG_EXEC`], [`TAG_MAP`]) |
//! | 1      | 1     | access size, or permission bits for [`TAG_MAP`] |
//! | 2      | 2     | map-name length in bytes, zero otherwise |
//! | 4      | 8     | address, or map start for [`TAG_MAP`] |
//! | 12     | 8     | value, or map end for [`TAG_MAP`] |
//! | 20     | 8     | instruction address that performed the access |
//! | 28     | 4     | reserved, zero |
//!
//! A [`TAG_MAP`] record is followed by its name bytes (no terminator). Map
//! records are snapshots: a reader applies them in order to the address space
//! it is modelling. The file deliberately carries no host pointers or Rust
//! layouts, so it can be read by any language.

pub mod analysis;

use crate::host::time::{Duration, Instant};
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::vm::vcpu::{MemAccess, MemRecord};

/// File magic.
pub const MAGIC: &[u8; 8] = b"RAXTRC1\n";
/// Current file version.
pub const VERSION: u32 = 1;
/// Architecture tag for x86-64 user mode.
pub const ARCH_X86_64: u32 = 1;

/// Data read record.
pub const TAG_READ: u8 = 1;
/// Data write record.
pub const TAG_WRITE: u8 = 2;
/// Address-space map snapshot record.
pub const TAG_MAP: u8 = 3;
/// Instruction fetch record.
pub const TAG_EXEC: u8 = 4;
/// Marks the beginning of a new address-space snapshot. Map records that
/// follow belong to it.
pub const TAG_SNAPSHOT: u8 = 5;

/// Size of one fixed record.
pub const RECORD_LEN: usize = 32;

/// Bytes in the file header.
pub const HEADER_LEN: usize = 16;

static ACTIVE: AtomicBool = AtomicBool::new(false);

struct Sink {
    writer: BufWriter<File>,
    path: PathBuf,
    /// Set once a write fails, so a broken trace is reported once.
    failed: bool,
    started: Instant,
    accesses: u64,
    bytes: u64,
    /// When to print the next live line; `None` keeps capture silent.
    next_report: Option<Instant>,
}

/// Interval between live capture lines.
const LIVE_INTERVAL: Duration = Duration::from_secs(5);

static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();

fn sink() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// Whether live capture lines are wanted.
///
/// A capture can run for hours and write many gigabytes, so progress is
/// printed on an interactive terminal. `RAX_MEMTRACE_PROGRESS` overrides the
/// decision: `0`/`off` silences capture, any other value forces the lines.
fn live_progress() -> bool {
    match std::env::var("RAX_MEMTRACE_PROGRESS") {
        Ok(value) => !matches!(value.as_str(), "0" | "off" | "false" | "no"),
        Err(_) => io::stderr().is_terminal(),
    }
}

/// Starts capturing to `path`, replacing any previous capture.
///
/// The file is created immediately. Capture is process-global: every CPU that
/// consults [`is_active`] while it is being constructed records its accesses.
pub fn start(path: &Path) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&ARCH_X86_64.to_le_bytes())?;
    let started = Instant::now();
    let next_report = live_progress().then(|| started + LIVE_INTERVAL);
    {
        let mut guard = sink().lock().unwrap();
        *guard = Some(Sink {
            writer,
            path: path.to_path_buf(),
            failed: false,
            started,
            accesses: 0,
            bytes: HEADER_LEN as u64,
            next_report,
        });
    }
    ACTIVE.store(true, Ordering::Release);
    Ok(())
}

/// Whether capture is currently on.
#[inline]
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Stops capture and flushes the file.
///
/// The final line reports what was captured, so a long unattended run leaves
/// its own record even when the live lines were off.
pub fn stop() {
    ACTIVE.store(false, Ordering::Release);
    let mut guard = sink().lock().unwrap();
    if let Some(mut sink) = guard.take() {
        let _ = sink.writer.flush();
        if sink.accesses > 0 {
            let elapsed = sink.started.elapsed();
            eprintln!(
                "[memtrace] stopped: {} accesses, {} in {:.1}s -> {}",
                count_short(sink.accesses),
                compact(sink.bytes),
                elapsed.as_secs_f64(),
                sink.path.display()
            );
        }
    }
}

/// Returns the path capture is writing to, if any.
pub fn path() -> Option<PathBuf> {
    sink()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.path.clone()))
}

fn write_all(bytes: &[u8], accesses: u64) {
    if let Ok(mut guard) = sink().lock() {
        if let Some(sink) = guard.as_mut() {
            if sink.failed {
                return;
            }
            if let Err(error) = sink.writer.write_all(bytes) {
                sink.failed = true;
                eprintln!(
                    "[memtrace] write to {} failed: {error}",
                    sink.path.display()
                );
                return;
            }
            sink.accesses += accesses;
            sink.bytes += bytes.len() as u64;
            if let Some(next) = sink.next_report {
                let now = Instant::now();
                if now >= next {
                    let elapsed = now.duration_since(sink.started);
                    eprintln!(
                        "[memtrace] {} accesses, {} -> {} ({}/s, {}/s)",
                        count_short(sink.accesses),
                        compact(sink.bytes),
                        sink.path.display(),
                        count_short(
                            (sink.accesses as f64 / elapsed.as_secs_f64().max(1e-3)) as u64
                        ),
                        bytes_per_second(sink.bytes, elapsed),
                    );
                    sink.next_report = Some(now + LIVE_INTERVAL);
                }
            }
        }
    }
}

/// Formats a count with a decimal magnitude suffix.
fn count_short(value: u64) -> String {
    if value >= 1_000_000_000 {
        format!("{:.2}B", value as f64 / 1e9)
    } else if value >= 1_000_000 {
        format!("{:.2}M", value as f64 / 1e6)
    } else if value >= 1_000 {
        format!("{:.1}K", value as f64 / 1e3)
    } else {
        value.to_string()
    }
}

/// Formats a byte count with a binary magnitude suffix.
fn compact(value: u64) -> String {
    if value >= 1 << 40 {
        format!("{:.2} TiB", value as f64 / (1u64 << 40) as f64)
    } else if value >= 1 << 30 {
        format!("{:.2} GiB", value as f64 / (1u64 << 30) as f64)
    } else if value >= 1 << 20 {
        format!("{:.2} MiB", value as f64 / (1u64 << 20) as f64)
    } else if value >= 1 << 10 {
        format!("{:.1} KiB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64().max(1e-3);
    compact((bytes as f64 / seconds) as u64)
}

/// Records a batch of vCPU accesses.
pub fn record(records: &[MemRecord]) {
    if !is_active() || records.is_empty() {
        return;
    }
    let mut buf = Vec::with_capacity(records.len() * RECORD_LEN);
    for record in records {
        let tag = match record.access {
            MemAccess::Read => TAG_READ,
            MemAccess::Write => TAG_WRITE,
            MemAccess::Exec => TAG_EXEC,
        };
        push_record(
            &mut buf,
            tag,
            record.size,
            record.addr,
            record.value,
            record.rip,
            0,
        );
    }
    write_all(&buf, records.len() as u64);
}

/// Records one address-space map. `perms` uses [`TAG_MAP`]'s permission bits:
/// 1 read, 2 write, 4 execute.
pub fn record_map(start: u64, end: u64, perms: u8, name: &str) {
    record_maps(std::iter::once((start, end, perms, Some(name.to_string()))));
}

/// Records a complete address-space snapshot. Each entry is
/// `(start, end, permission bits, name)`.
pub fn record_maps<I>(maps: I)
where
    I: IntoIterator<Item = (u64, u64, u8, Option<String>)>,
{
    if !is_active() {
        return;
    }
    let mut buf = Vec::new();
    push_record(&mut buf, TAG_SNAPSHOT, 0, 0, 0, 0, 0);
    for (start, end, perms, name) in maps {
        let name = name.unwrap_or_default();
        let len = name.len().min(u16::MAX as usize);
        push_record(&mut buf, TAG_MAP, perms, start, end, 0, len as u16);
        buf.extend_from_slice(&name.as_bytes()[..len]);
    }
    write_all(&buf, 0);
}

fn push_record(buf: &mut Vec<u8>, tag: u8, aux: u8, a: u64, b: u64, c: u64, name_len: u16) {
    buf.push(tag);
    buf.push(aux);
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&a.to_le_bytes());
    buf.extend_from_slice(&b.to_le_bytes());
    buf.extend_from_slice(&c.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_layout_is_stable() {
        let mut buf = Vec::new();
        push_record(&mut buf, TAG_WRITE, 8, 0x1122, 0x3344, 0x5566, 0);
        assert_eq!(buf.len(), RECORD_LEN);
        assert_eq!(buf[0], TAG_WRITE);
        assert_eq!(buf[1], 8);
        assert_eq!(u64::from_le_bytes(buf[4..12].try_into().unwrap()), 0x1122);
        assert_eq!(u64::from_le_bytes(buf[12..20].try_into().unwrap()), 0x3344);
        assert_eq!(u64::from_le_bytes(buf[20..28].try_into().unwrap()), 0x5566);
    }
}
