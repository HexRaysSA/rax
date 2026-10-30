//! `strace` dumps of Mach messages (`strace_messages`).
//!
//! A message is shown twice: as its sender laid it out, before copy-in
//! (the header the trap gave, the sender's names, and the sender's
//! out-of-line memory, read before a deallocating send unmaps it), and as
//! its receiver gets it, after copy-out (the receiver's names, the
//! addresses the out-of-line memory was given, then the trailer). Each
//! shows the header, the decoded descriptors, and a hex dump of at most
//! `limit` bytes of the inline message, of each out-of-line region or port
//! array, and of the auxiliary data. Decoding reports what the bytes hold
//! without validating them: a send copy-in refuses is dumped too.
//!
//! Layouts: `mach/message.h` 64-bit user descriptors
//! (`mach_msg_port_descriptor_t`, `mach_msg_ool_descriptor64_t`,
//! `mach_msg_ool_ports_descriptor64_t`,
//! `mach_msg_guarded_port_descriptor64_t`).

use std::fmt::Write as _;

use super::kmsg;
use crate::user::darwin::mach::ipc::{KObject, PortName, disp};
use crate::user::darwin::mach::msg::{HEADER_SIZE, Sender, bits, desc};
use crate::user::darwin::mig::ids;
use crate::user::darwin::syscall::Ctx;

/// `sizeof(mach_msg_base_t)`: the header and the descriptor count.
const BASE_SIZE: usize = HEADER_SIZE + 4;
/// Bytes per hex dump line.
const DUMP_LINE: usize = 16;

/// Reports a message about to be copied in: `raw` is the message as the
/// sender laid it out with the trap's header, `dsc_count` the trap's
/// descriptor count, and `aux` the auxiliary data.
pub fn send(ctx: &Ctx<'_>, raw: &[u8], dsc_count: u32, aux: &[u8]) {
    let Some(limit) = limit(ctx) else {
        return;
    };
    let tid = ctx.thread.tid;
    let mut text = format!("[{tid:#x}]   send {}", header(raw));
    if let Some(to) = destination(ctx, raw) {
        let _ = write!(text, " to {to}");
    }
    text.push('\n');
    body(ctx, &mut text, raw, raw, dsc_count, aux, limit, false);
    eprint!("{text}");
}

/// Reports a received message: `out` is what the receiver's buffer gets
/// (the message, then the trailer), `aux` the auxiliary data, and
/// `sender` who sent it.
pub fn received(ctx: &Ctx<'_>, out: &[u8], aux: &[u8], sender: &Sender) {
    if !ctx.proc.config.strace {
        return;
    }
    let tid = ctx.thread.tid;
    let mut text = format!(
        "[{tid:#x}]   received {} ({} bytes with trailer)",
        header(out),
        out.len()
    );
    let Some(limit) = limit(ctx) else {
        eprintln!("{text}");
        return;
    };
    if *sender == Sender::KERNEL {
        text.push_str(" from the kernel");
        if let Some(what) = word(out, 20).and_then(|id| kernel_message(id as i32)) {
            let _ = write!(text, " ({what})");
        }
    }
    text.push('\n');
    // The descriptors are in the message (`msgh_size` bytes, the header
    // alone when the message was too large), not the trailer after it.
    let size = word(out, 4).map_or(0, |s| s as usize);
    let message = &out[..size.min(out.len())];
    let count = word(message, HEADER_SIZE).unwrap_or(0);
    body(ctx, &mut text, out, message, count, aux, limit, true);
    eprint!("{text}");
}

/// The dump limit, when the trace dumps messages.
fn limit(ctx: &Ctx<'_>) -> Option<usize> {
    ctx.proc
        .config
        .strace
        .then_some(ctx.proc.config.strace_messages)
        .flatten()
}

/// The header fields `strace` shows.
fn header(m: &[u8]) -> String {
    let w = |o: usize| word(m, o).unwrap_or(0);
    format!(
        "bits={:#x} size={} remote={:#x} local={:#x} voucher={:#x} id={}",
        w(0),
        w(4),
        w(8),
        w(12),
        w(16),
        w(20) as i32
    )
}

/// What the sender's destination name stands for, and the MIG routine a
/// kernel object's message calls.
fn destination(ctx: &Ctx<'_>, raw: &[u8]) -> Option<String> {
    let name: PortName = word(raw, 8)?;
    let entry = ctx.proc.ipc.lookup(name).ok()?;
    let port = entry.port()?;
    let host = port.state.lock().unwrap().host.is_some();
    let mut what = if host {
        "a host service".to_string()
    } else {
        object(&port.kobject)?
    };
    if port.is_kernel()
        && let Some(routine) = word(raw, 20).and_then(|id| ids::name(id as i32))
    {
        let _ = write!(what, " ({routine})");
    }
    Some(what)
}

/// A kernel object's kind; `None` for an ordinary port.
fn object(kobject: &KObject) -> Option<String> {
    Some(match kobject {
        KObject::None => return None,
        KObject::Task => "task".into(),
        KObject::TaskName => "task name".into(),
        KObject::TaskRead => "task read".into(),
        KObject::TaskInspect => "task inspect".into(),
        KObject::Thread(tid) => format!("thread {tid:#x}"),
        KObject::Host => "host".into(),
        KObject::HostPriv => "host_priv".into(),
        KObject::Semaphore(_) => "semaphore".into(),
        KObject::Timer(_) => "timer".into(),
        KObject::Clock(_) => "clock".into(),
        KObject::Voucher(_) => "voucher".into(),
        KObject::TaskIdToken(_) => "task identity token".into(),
        KObject::TaskResume(_) => "task resume".into(),
        KObject::Proxy(_) => "a host service".into(),
    })
}

/// What a message from the kernel is: a notification, or a MIG reply
/// (the request's ID + 100).
fn kernel_message(id: i32) -> Option<String> {
    let notification = match id {
        kmsg::MACH_NOTIFY_PORT_DELETED => Some("port-deleted notification"),
        kmsg::MACH_NOTIFY_SEND_POSSIBLE => Some("send-possible notification"),
        kmsg::MACH_NOTIFY_PORT_DESTROYED => Some("port-destroyed notification"),
        kmsg::MACH_NOTIFY_NO_SENDERS => Some("no-senders notification"),
        kmsg::MACH_NOTIFY_SEND_ONCE => Some("send-once notification"),
        kmsg::MACH_NOTIFY_DEAD_NAME => Some("dead-name notification"),
        _ => None,
    };
    if let Some(n) = notification {
        return Some(n.into());
    }
    ids::name(id.wrapping_sub(100)).map(|routine| format!("{routine} reply"))
}

/// Appends the dump of `shown` (the message, and the trailer of a
/// received one), the descriptors of `message` with their memory, and
/// the auxiliary data.
#[allow(clippy::too_many_arguments)]
fn body(
    ctx: &Ctx<'_>,
    out: &mut String,
    shown: &[u8],
    message: &[u8],
    count: u32,
    aux: &[u8],
    limit: usize,
    received: bool,
) {
    let tid = ctx.thread.tid;
    let detail = format!("[{tid:#x}]     ");
    let data = format!("[{tid:#x}]       ");
    // A limit of 0 keeps the headers and descriptors alone.
    let contents = limit != 0;
    if contents {
        hexdump(out, &detail, &shown[..shown.len().min(limit)], shown.len());
    }
    let complex = word(message, 0).is_some_and(|b| b & bits::COMPLEX != 0);
    if complex {
        for (i, d) in descriptors(message, count).into_iter().enumerate() {
            let _ = writeln!(out, "{detail}descriptor {i}: {}", d.describe(received));
            match d {
                Desc::Ool { addr, size, .. } if contents => {
                    region(ctx, out, &data, addr, size as usize, limit);
                }
                Desc::OolPorts { addr, count, .. } if contents => {
                    port_array(ctx, out, &data, addr, count as usize, limit);
                }
                _ => {}
            }
        }
    }
    if !aux.is_empty() {
        let _ = writeln!(out, "{detail}auxiliary data: {} bytes", aux.len());
        if contents {
            hexdump(out, &data, &aux[..aux.len().min(limit)], aux.len());
        }
    }
}

/// Dumps at most `limit` bytes of the `size`-byte region at `addr`.
fn region(ctx: &Ctx<'_>, out: &mut String, prefix: &str, addr: u64, size: usize, limit: usize) {
    match ctx.read(addr, size.min(limit)) {
        Ok(bytes) => hexdump(out, prefix, &bytes, size),
        Err(_) => {
            let _ = writeln!(out, "{prefix}(unreadable)");
        }
    }
}

/// Lists the names of an out-of-line port array (`mach_port_name_t`
/// each), at most `limit` bytes of them.
fn port_array(
    ctx: &Ctx<'_>,
    out: &mut String,
    prefix: &str,
    addr: u64,
    count: usize,
    limit: usize,
) {
    let shown = count.min(limit / 4);
    let names = match ctx.read(addr, shown * 4) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = writeln!(out, "{prefix}(unreadable)");
            return;
        }
    };
    let mut line = prefix.to_string();
    line.push_str("names:");
    for name in names.chunks_exact(4) {
        let name = u32::from_le_bytes(name.try_into().expect("4 bytes"));
        let _ = write!(line, " {name:#x}");
    }
    if shown < count {
        let _ = write!(line, " ... {} more", count - shown);
    }
    out.push_str(&line);
    out.push('\n');
}

/// Appends a hex dump of `shown`, the first bytes of `total`: 16 bytes a
/// line with their offset and ASCII, then how many bytes were left out.
fn hexdump(out: &mut String, prefix: &str, shown: &[u8], total: usize) {
    for (row, chunk) in shown.chunks(DUMP_LINE).enumerate() {
        let _ = write!(out, "{prefix}{:04x} ", row * DUMP_LINE);
        for i in 0..DUMP_LINE {
            if i == DUMP_LINE / 2 {
                out.push(' ');
            }
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(out, " {b:02x}");
                }
                None => out.push_str("   "),
            }
        }
        out.push_str("  |");
        for &b in chunk {
            let printable = b.is_ascii_graphic() || b == b' ';
            out.push(if printable { char::from(b) } else { '.' });
        }
        out.push_str("|\n");
    }
    if shown.len() < total {
        let _ = writeln!(out, "{prefix}... {} more bytes", total - shown.len());
    }
}

/// A descriptor as its bytes say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Desc {
    /// `MACH_MSG_PORT_DESCRIPTOR`.
    Port { name: PortName, disposition: u8 },
    /// `MACH_MSG_OOL_DESCRIPTOR` or `MACH_MSG_OOL_VOLATILE_DESCRIPTOR`.
    Ool {
        addr: u64,
        size: u32,
        deallocate: u8,
        copy: u8,
        volatile: bool,
    },
    /// `MACH_MSG_OOL_PORTS_DESCRIPTOR`.
    OolPorts {
        addr: u64,
        count: u32,
        deallocate: u8,
        copy: u8,
        disposition: u8,
    },
    /// `MACH_MSG_GUARDED_PORT_DESCRIPTOR`.
    Guarded {
        name: PortName,
        disposition: u8,
        flags: u16,
        context: u64,
    },
    /// A type no message carries; decoding stops here.
    Unknown { kind: u8 },
}

impl Desc {
    fn describe(&self, received: bool) -> String {
        match *self {
            Desc::Port { name, disposition } => format!(
                "port name={name:#x} disposition={}",
                disposition_name(disposition, received)
            ),
            Desc::Ool {
                addr,
                size,
                deallocate,
                copy,
                volatile,
            } => format!(
                "{} address={addr:#x} size={size} copy={} deallocate={deallocate}",
                if volatile { "ool-volatile" } else { "ool" },
                copy_name(copy)
            ),
            Desc::OolPorts {
                addr,
                count,
                deallocate,
                copy,
                disposition,
            } => format!(
                "ool-ports address={addr:#x} count={count} disposition={} copy={} deallocate={deallocate}",
                disposition_name(disposition, received),
                copy_name(copy)
            ),
            Desc::Guarded {
                name,
                disposition,
                flags,
                context,
            } => format!(
                "guarded-port name={name:#x} disposition={} flags={flags:#x} context={context:#x}",
                disposition_name(disposition, received)
            ),
            Desc::Unknown { kind } => format!("type {kind} (not a descriptor type)"),
        }
    }
}

/// Decodes the first `count` descriptors of message `m`, as many as its
/// bytes hold.
fn descriptors(m: &[u8], count: u32) -> Vec<Desc> {
    let mut out = Vec::new();
    let mut pos = BASE_SIZE;
    for _ in 0..count {
        let Some(&kind) = m.get(pos + 11) else {
            break;
        };
        let Some(d) = m.get(pos..pos + desc::size(kind)) else {
            break;
        };
        let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().expect("4 bytes"));
        let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().expect("8 bytes"));
        let decoded = match kind {
            desc::PORT => Desc::Port {
                name: u32_at(0),
                disposition: d[10],
            },
            desc::OOL | desc::OOL_VOLATILE => Desc::Ool {
                addr: u64_at(0),
                size: u32_at(12),
                deallocate: d[8],
                copy: d[9],
                volatile: kind == desc::OOL_VOLATILE,
            },
            desc::OOL_PORTS => Desc::OolPorts {
                addr: u64_at(0),
                count: u32_at(12),
                deallocate: d[8],
                copy: d[9],
                disposition: d[10],
            },
            desc::GUARDED_PORT => Desc::Guarded {
                name: u32_at(12),
                disposition: d[10],
                flags: u16::from_le_bytes([d[8], d[9]]),
                context: u64_at(0),
            },
            _ => Desc::Unknown { kind },
        };
        out.push(decoded);
        if matches!(decoded, Desc::Unknown { .. }) {
            break;
        }
        pos += d.len();
    }
    out
}

/// `MACH_MSG_TYPE_*` as a sender writes it, or the right type
/// (`MACH_MSG_TYPE_PORT_*`) a receiver is given.
fn disposition_name(d: u8, received: bool) -> String {
    let name = match (u32::from(d), received) {
        (disp::MOVE_RECEIVE, true) => "PORT_RECEIVE",
        (disp::MOVE_SEND, true) => "PORT_SEND",
        (disp::MOVE_SEND_ONCE, true) => "PORT_SEND_ONCE",
        (disp::MOVE_RECEIVE, false) => "MOVE_RECEIVE",
        (disp::MOVE_SEND, false) => "MOVE_SEND",
        (disp::MOVE_SEND_ONCE, false) => "MOVE_SEND_ONCE",
        (disp::COPY_SEND, _) => "COPY_SEND",
        (disp::MAKE_SEND, _) => "MAKE_SEND",
        (disp::MAKE_SEND_ONCE, _) => "MAKE_SEND_ONCE",
        _ => return d.to_string(),
    };
    name.into()
}

/// `mach_msg_copy_options_t`.
fn copy_name(copy: u8) -> String {
    match copy {
        desc::PHYSICAL_COPY => "physical".into(),
        desc::VIRTUAL_COPY => "virtual".into(),
        2 => "allocate".into(),
        3 => "overwrite".into(),
        other => other.to_string(),
    }
}

/// The little-endian word at `offset` of `m`, if `m` holds it.
fn word(m: &[u8], offset: usize) -> Option<u32> {
    m.get(offset..offset + 4)
        .map(|w| u32::from_le_bytes(w.try_into().expect("4 bytes")))
}

#[cfg(test)]
mod tests;
