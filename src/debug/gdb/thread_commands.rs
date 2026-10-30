//! RSP thread/control packets use owner-side state and completed stop events.
use super::*;
use protocol::{decode_hex, send_error, send_ok, send_packet};
use std::io::Write;
use std::time::Duration;

pub(super) fn request(channels: &GdbChannels, command: GdbCommand) -> std::io::Result<GdbResponse> {
    channels
        .cmd_tx
        .send(command)
        .map_err(std::io::Error::other)?;
    channels
        .resp_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(std::io::Error::other)
}
pub(super) fn send_response<W: Write>(
    stream: &mut W,
    response: GdbResponse,
) -> std::io::Result<()> {
    match response {
        GdbResponse::Ok | GdbResponse::Detached => send_ok(stream),
        GdbResponse::Error(code) => send_error(stream, code),
        GdbResponse::Text(data) | GdbResponse::Registers(data) | GdbResponse::Memory(data) => {
            send_packet(stream, &data)
        }
        GdbResponse::ThreadStop { signal, index } => send_packet(
            stream,
            &format!("T{signal:02x}thread:{:x};core:{index:x};", index + 1),
        ),
        GdbResponse::Exited(code) => send_packet(stream, &format!("W{code:02x}")),
        GdbResponse::StopReply(signal) => send_stop_reply(stream, signal),
        _ => send_error(stream, 1),
    }
}
pub(super) fn handle(
    packet: &str,
    stream: &mut TcpStream,
    channels: &GdbChannels,
) -> std::io::Result<Option<bool>> {
    let command = if packet == "?" {
        Some(GdbCommand::QueryHaltReason)
    } else if let Some(raw) = packet.strip_prefix('H') {
        let (operation, thread) = raw.split_at_checked(1).unwrap_or(("", ""));
        match (operation, ThreadId::parse(thread)) {
            ("c" | "g", Some(thread)) => Some(GdbCommand::SelectThread {
                execution: operation == "c",
                thread,
            }),
            _ => {
                send_error(stream, 1)?;
                return Ok(Some(true));
            }
        }
    } else if packet == "qfThreadInfo" {
        Some(GdbCommand::Threads)
    } else if packet == "qsThreadInfo" {
        send_packet(stream, "l")?;
        return Ok(Some(true));
    } else if packet == "qC" {
        Some(GdbCommand::CurrentThread)
    } else if let Some(raw) = packet.strip_prefix("qThreadExtraInfo,") {
        match ThreadId::parse(raw) {
            Some(thread) => Some(GdbCommand::ThreadInfo {
                thread,
                describe: true,
            }),
            None => {
                send_error(stream, 1)?;
                return Ok(Some(true));
            }
        }
    } else if let Some(raw) = packet.strip_prefix('T') {
        match ThreadId::parse(raw) {
            Some(thread) => Some(GdbCommand::ThreadInfo {
                thread,
                describe: false,
            }),
            None => {
                send_error(stream, 1)?;
                return Ok(Some(true));
            }
        }
    } else if let Some(raw) = packet.strip_prefix('P') {
        let parsed = raw
            .split_once('=')
            .and_then(|(i, d)| Some((usize::from_str_radix(i, 16).ok()?, decode_hex(d)?)));
        match parsed {
            Some((index, data)) => Some(GdbCommand::WriteRegister { index, data }),
            None => {
                send_error(stream, 1)?;
                return Ok(Some(true));
            }
        }
    } else if packet == "vCont?" {
        send_packet(stream, "vCont;c;C;s;S;t")?;
        return Ok(Some(true));
    } else if packet == "c" || packet == "s" || packet.starts_with("vCont;") {
        let command = if packet == "c" {
            Some(GdbCommand::Continue)
        } else if packet == "s" {
            Some(GdbCommand::Step)
        } else {
            threads::parse_resume(&packet[6..]).map(GdbCommand::Resume)
        };
        if let Some(command) = command {
            channels
                .cmd_tx
                .send(command)
                .map_err(std::io::Error::other)?;
            let reply = commands::wait_for_stop_or_interrupt(stream, channels)?;
            send_response(stream, reply)?;
        } else {
            send_error(stream, 1)?;
        }
        return Ok(Some(true));
    } else if packet == "D" {
        let reply = request(channels, GdbCommand::Detach)?;
        let detached = matches!(reply, GdbResponse::Detached);
        send_response(stream, reply)?;
        return Ok(Some(!detached));
    } else {
        None
    };
    if let Some(command) = command {
        send_response(stream, request(channels, command)?)?;
        Ok(Some(true))
    } else {
        Ok(None)
    }
}
