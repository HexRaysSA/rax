//! GDB RSP command handlers.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tracing::debug;

/// x86_64 target description XML for GDB/IDA Pro.
use super::protocol::{
    decode_hex, parse_addr, parse_len, send_empty, send_error, send_ok, send_packet,
    send_stop_reply,
};
use super::{GdbChannels, GdbCommand, GdbResponse};

/// Wait for a stop response from VMM while also checking for interrupt (0x03) from debugger.
/// This allows Ctrl+C / pause to work during execution.
pub(super) fn wait_for_stop_or_interrupt(
    stream: &mut TcpStream,
    channels: &GdbChannels,
) -> std::io::Result<GdbResponse> {
    // Set stream to non-blocking so we can poll for interrupts
    stream.set_nonblocking(true)?;

    let mut buf = [0u8; 64];
    loop {
        // Check for response from VMM (non-blocking)
        match channels.resp_rx.try_recv() {
            Ok(resp) => {
                // Got a response, restore blocking mode and return
                stream.set_nonblocking(false)?;
                return Ok(resp);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // No response yet, check for interrupt from debugger
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                stream.set_nonblocking(false)?;
                return Ok(GdbResponse::Error(1));
            }
        }

        // Check for incoming data from debugger (0x03 interrupt)
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed
                stream.set_nonblocking(false)?;
                return Ok(GdbResponse::Error(1));
            }
            Ok(n) => {
                // Check if any byte is 0x03 (interrupt)
                if buf[..n].contains(&0x03) {
                    debug!("Received interrupt (0x03) during execution");
                    // Send interrupt command to VMM
                    channels.cmd_tx.send(GdbCommand::Interrupt).ok();
                    // Now wait for the stop response (blocking is fine now)
                    stream.set_nonblocking(false)?;
                    match channels.resp_rx.recv() {
                        Ok(resp) => return Ok(resp),
                        Err(_) => return Ok(GdbResponse::Error(1)),
                    }
                }
                // Otherwise ignore (could be ACKs or other data we don't care about)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, sleep briefly to avoid busy-spinning
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                stream.set_nonblocking(false)?;
                return Err(e);
            }
        }
    }
}

/// Handle a GDB RSP command.
/// Returns Ok(true) to continue, Ok(false) to disconnect.
pub fn handle_command(
    packet: &str,
    stream: &mut TcpStream,
    channels: &GdbChannels,
) -> std::io::Result<bool> {
    if let Some(keep) = super::thread_commands::handle(packet, stream, channels)? {
        return Ok(keep);
    }
    // Get first character (command type)
    let cmd = packet.chars().next().unwrap_or(' ');
    let args = if packet.len() > 1 { &packet[1..] } else { "" };

    match cmd {
        // Read registers
        'g' => {
            channels.cmd_tx.send(GdbCommand::ReadRegisters).ok();
            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Registers(hex)) => {
                    send_packet(stream, &hex)?;
                }
                Ok(GdbResponse::Error(code)) => {
                    send_error(stream, code)?;
                }
                _ => {
                    send_error(stream, 1)?;
                }
            }
        }

        // Write registers
        'G' => {
            let data = match decode_hex(args) {
                Some(d) => d,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };
            channels.cmd_tx.send(GdbCommand::WriteRegisters(data)).ok();
            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Ok) => send_ok(stream)?,
                _ => send_error(stream, 1)?,
            }
        }

        // Read single register (p<reg_num>)
        'p' => {
            let reg_num = match usize::from_str_radix(args, 16) {
                Ok(n) => n,
                Err(_) => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };
            // We need to get all registers and extract the one requested
            channels.cmd_tx.send(GdbCommand::ReadRegisters).ok();
            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Registers(hex)) => {
                    // Extract the specific register from the full register set
                    if let Some(reg_data) = extract_register(&hex, reg_num) {
                        send_packet(stream, &reg_data)?;
                    } else {
                        send_error(stream, 1)?;
                    }
                }
                _ => {
                    send_error(stream, 1)?;
                }
            }
        }

        // Read memory
        'm' => {
            let parts: Vec<&str> = args.split(',').collect();
            if parts.len() != 2 {
                send_error(stream, 1)?;
                return Ok(true);
            }
            let addr = match parse_addr(parts[0]) {
                Some(a) => a,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };
            let len = match parse_len(parts[1]) {
                Some(l) => l,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };

            channels
                .cmd_tx
                .send(GdbCommand::ReadMemory { addr, len })
                .ok();
            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Memory(hex)) => {
                    send_packet(stream, &hex)?;
                }
                Ok(GdbResponse::Error(code)) => {
                    send_error(stream, code)?;
                }
                _ => {
                    send_error(stream, 1)?;
                }
            }
        }

        // Write memory
        'M' => {
            let colon_pos = match args.find(':') {
                Some(p) => p,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };
            let header = &args[..colon_pos];
            let hex_data = &args[colon_pos + 1..];

            let parts: Vec<&str> = header.split(',').collect();
            if parts.len() != 2 {
                send_error(stream, 1)?;
                return Ok(true);
            }

            let addr = match parse_addr(parts[0]) {
                Some(a) => a,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };

            let data = match decode_hex(hex_data) {
                Some(d) => d,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };

            channels
                .cmd_tx
                .send(GdbCommand::WriteMemory { addr, data })
                .ok();
            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Ok) => send_ok(stream)?,
                _ => send_error(stream, 1)?,
            }
        }

        // Set/remove breakpoint
        'Z' | 'z' => {
            let parts: Vec<&str> = args.split(',').collect();
            if parts.len() < 2 {
                send_error(stream, 1)?;
                return Ok(true);
            }

            let bp_type = parts[0];
            let addr = match parse_addr(parts[1]) {
                Some(a) => a,
                None => {
                    send_error(stream, 1)?;
                    return Ok(true);
                }
            };

            // Only support software breakpoints (type 0)
            if bp_type != "0" {
                send_empty(stream)?; // Unsupported
                return Ok(true);
            }

            if cmd == 'Z' {
                channels
                    .cmd_tx
                    .send(GdbCommand::SetBreakpoint { addr })
                    .ok();
            } else {
                channels
                    .cmd_tx
                    .send(GdbCommand::RemoveBreakpoint { addr })
                    .ok();
            }

            match channels.resp_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(GdbResponse::Ok) => send_ok(stream)?,
                _ => send_error(stream, 1)?,
            }
        }

        // Kill
        'k' => {
            channels.cmd_tx.send(GdbCommand::Kill).ok();
            return Ok(false);
        }

        // Query commands
        'q' => {
            super::queries::handle_query(args, stream)?;
        }

        // Unknown command
        _ => {
            debug!(cmd = %cmd, "Unknown GDB command");
            send_empty(stream)?;
        }
    }

    Ok(true)
}

/// Extract a single register from the full register hex string.
/// Returns "xxxxxxxx..." for 64-bit regs (0-16), "xxxx" for 32-bit (17-23)
fn extract_register(hex: &str, reg_num: usize) -> Option<String> {
    let (offset, width) = super::x86_registers::location(reg_num)?;
    hex.get(offset * 2..(offset + width) * 2)
        .map(str::to_string)
}
