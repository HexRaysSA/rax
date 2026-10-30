//! Target description and stateless RSP queries.
use super::protocol::{send_empty, send_error, send_ok, send_packet};
use std::io::Write;
use tracing::debug;
const TARGET_XML: &str = include_str!("target.xml");
/// Handle query commands (q...).
pub(super) fn handle_query<W: Write>(args: &str, stream: &mut W) -> std::io::Result<()> {
    if args.starts_with("Supported") {
        // Report supported features including target description
        send_packet(
            stream,
            "PacketSize=4096;swbreak+;vContSupported+;qXfer:features:read+",
        )?;
    } else if args.starts_with("Xfer:features:read:target.xml:") {
        // Target description XML for x86_64
        // Parse offset and length from "target.xml:offset,length"
        let params = &args["Xfer:features:read:target.xml:".len()..];
        let Some((offset, length)) = params.split_once(',').and_then(|(o, l)| {
            Some((
                usize::from_str_radix(o, 16).ok()?,
                usize::from_str_radix(l, 16).ok()?,
            ))
        }) else {
            send_error(stream, 1)?;
            return Ok(());
        };
        if length == 0 {
            send_error(stream, 1)?;
            return Ok(());
        }
        if offset >= TARGET_XML.len() {
            send_packet(stream, "l")?;
        } else {
            let remaining = &TARGET_XML[offset..];
            let chunk = remaining.len().min(length);
            let prefix = if chunk == remaining.len() { 'l' } else { 'm' };
            send_packet(stream, &format!("{prefix}{}", &remaining[..chunk]))?;
        }
    } else if args.starts_with("Attached") {
        // We attached to an existing process
        send_packet(stream, "1")?;
    } else if args.starts_with("TStatus") {
        // Tracepoint status - not supported
        send_empty(stream)?;
    } else if args.starts_with("Offsets") {
        // Section offsets - not applicable
        send_empty(stream)?;
    } else if args.starts_with("Symbol") {
        // Symbol lookup - not supported
        send_ok(stream)?;
    } else if args.starts_with("Rcmd") {
        // Remote command - not supported
        send_ok(stream)?;
    } else {
        debug!(query = %args, "Unknown query");
        send_empty(stream)?;
    }

    Ok(())
}
