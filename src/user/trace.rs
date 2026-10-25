//! Instruction tracing for process-level (user-mode) execution.
//!
//! A trace records one line per instruction the guest CPU is about to execute,
//! with the instruction address, the executing ISA, and the instruction bytes
//! fetched through the guest address space. It covers every user-mode CPU
//! adapter (x86-64/i386, AArch64, RV64, and AArch32), so a single switch works
//! across the Linux, Darwin, and Windows personalities.
//!
//! This is distinct from the machine-level trace in
//! [`crate::observability::trace`], which is x86-specific, gated by the
//! `trace` Cargo feature, and follows the interpreter/JIT execution policy of
//! the machine run loop. User-mode tracing is always available and executes
//! the guest one precise instruction at a time so the record does not depend
//! on native-region promotion.
//!
//! Tracing is process-global. [`init`] installs a sink; after a guest `fork`
//! the child shares the inherited file description, so both processes append
//! to the same trace. The sink is unbuffered: a forked child that ends with
//! `_exit` still has every line it wrote in the file.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether a sink is installed. Checked on every instruction, so it is a
/// relaxed atomic rather than a mutex acquisition.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// The trace sink. Only touched while [`ENABLED`] is true.
static WRITER: Mutex<Option<File>> = Mutex::new(None);

/// Creates or truncates `path` and starts tracing guest instructions to it.
///
/// Replaces any previously installed sink. The file is shared with guest
/// children created by `fork`; it is not reopened or truncated by them.
pub fn init(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    *WRITER.lock().expect("instruction trace sink poisoned") = Some(file);
    ENABLED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Whether instruction tracing is active.
#[inline(always)]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Records the instruction at `pc` before it executes.
///
/// `isa` is the guest instruction set (`x86_64`, `i386`, `aarch64`, `riscv64`,
/// or `arm`) and `bytes` are the instruction bytes fetched from the guest
/// address space, or an empty slice when the fetch itself faults.
pub fn write_insn(isa: &str, pc: u64, bytes: &[u8]) {
    if !is_enabled() {
        return;
    }
    let mut writer = match WRITER.lock() {
        Ok(writer) => writer,
        // A poisoned sink must not abort guest execution.
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(file) = writer.as_mut() else {
        return;
    };
    // One write per record keeps forked processes (which share the file
    // description and its offset) from interleaving parts of two lines.
    let mut line = format!("INS 0x{pc:016x}  {isa:<8} ");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            line.push(' ');
        }
        let _ = write!(line, "{byte:02x}");
    }
    line.push('\n');
    let _ = file.write_all(line.as_bytes());
}

/// Flushes the sink (the file is unbuffered, so this only reports errors).
pub fn flush() {
    let mut writer = match WRITER.lock() {
        Ok(writer) => writer,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(file) = writer.as_mut() {
        let _ = file.flush();
    }
}

/// Stops tracing and closes the sink.
pub fn close() {
    ENABLED.store(false, Ordering::Relaxed);
    let mut writer = match WRITER.lock() {
        Ok(writer) => writer,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(mut file) = writer.take() {
        let _ = file.flush();
    }
}
