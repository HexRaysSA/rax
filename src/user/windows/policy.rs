//! Virtual software-policy queries over immutable selected host metadata.
//! Packet decoding and reply encoding never invoke a host operation.

mod catalog;
mod codec;

pub(crate) use catalog::{Catalog, capture};
use codec::Direction;

use super::nt::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};

pub(crate) const MAX_PACKET_BYTES: usize = 2 << 20;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;

#[derive(Debug)]
pub(crate) enum Error {
    Status(u32),
    Unsupported(&'static str),
}

impl From<u32> for Error {
    fn from(status: u32) -> Self {
        Self::Status(status)
    }
}

fn word(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?,
    ))
}

fn blocks(mut bytes: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(STATUS_DATA_ERROR.into());
        }
        let size = word(&bytes[..4])? as usize;
        let rest = &bytes[4..];
        let value = rest.get(..size).ok_or(STATUS_DATA_ERROR)?;
        result.push(value);
        bytes = &rest[size..];
    }
    Ok(result)
}

fn push_block(bytes: &mut Vec<u8>, block: &[u8]) {
    bytes.extend_from_slice(&(block.len() as u32).to_le_bytes());
    bytes.extend_from_slice(block);
}

fn checksum(bytes: &[u8]) -> u64 {
    u64::from(bytes.iter().fold(0, |sum, byte| sum ^ byte))
}

#[cfg(any(windows, test))]
fn qualification_request() -> Vec<u8> {
    let request_context = [255; 160];
    let request_key = 0x0F1E_2D3C_4B5A_6978u64;
    let mut reply_context = [0u8; 160];
    for (index, byte) in reply_context[..128].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    for (index, byte) in reply_context[128..].iter_mut().enumerate() {
        *byte = if index < 31 { index as u8 } else { 255 };
    }
    let name: Vec<_> = "Kernel-BrandingInfo\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut payload = Vec::new();
    push_block(&mut payload, &0u32.to_le_bytes());
    push_block(&mut payload, &reply_context);
    push_block(&mut payload, &0x0123_4567_89AB_CDEFu64.to_le_bytes());
    push_block(&mut payload, &0x5241_5850_514C_434Bu64.to_le_bytes());
    push_block(&mut payload, &name);
    push_block(&mut payload, &0u32.to_le_bytes());
    push_block(&mut payload, &0u32.to_le_bytes());
    let mut plain = Vec::new();
    plain.extend_from_slice(&7u32.to_le_bytes());
    plain.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plain.extend_from_slice(&payload);
    plain.resize(plain.len().next_multiple_of(8), 0);
    let mut body = codec::transform(
        &plain,
        &request_context,
        request_key,
        Direction::Request,
        false,
    )
    .expect("fixed aligned software-policy qualification packet");
    body.extend_from_slice(&checksum(&plain).to_le_bytes());
    let mut packet = Vec::new();
    push_block(&mut packet, &body);
    push_block(&mut packet, &request_context);
    push_block(&mut packet, &request_key.to_le_bytes());
    packet
}

/// Class0 QueryPolicy. Other policy commands remain explicit unsupported
/// operations; no opaque request is forwarded to the host licensing service.
pub(crate) fn query(catalog: &Catalog, packet: &[u8]) -> Result<Vec<u8>, Error> {
    if packet.len() > MAX_PACKET_BYTES {
        return Err(Error::Unsupported("software policy input exceeds 2 MiB"));
    }
    let outer = blocks(packet)?;
    if outer.len() != 3 {
        return Err(STATUS_DATA_ERROR.into());
    }
    let context: &[u8; 160] = outer[1].try_into().map_err(|_| STATUS_UNSUCCESSFUL)?;
    let key = u64::from_le_bytes(outer[2].try_into().map_err(|_| STATUS_UNSUCCESSFUL)?);
    let body = outer[0];
    if body.len() <= 8 {
        return Err(STATUS_UNSUCCESSFUL.into());
    }
    let encrypted = &body[..body.len() - 8];
    let plain = codec::transform(encrypted, context, key, Direction::Request, true)
        .ok_or(STATUS_UNSUCCESSFUL)?;
    let recorded = u64::from_le_bytes(body[body.len() - 8..].try_into().unwrap());
    if recorded != checksum(&plain) || plain.len() < 8 {
        return Err(STATUS_UNSUCCESSFUL.into());
    }
    let count = word(&plain[..4])? as usize;
    let length = word(&plain[4..8])? as usize;
    let payload = plain
        .get(8..)
        .and_then(|bytes| bytes.get(..length))
        .ok_or(STATUS_DATA_ERROR)?;
    let fields = blocks(payload)?;
    if fields.len() != count || count < 3 {
        return Err(STATUS_DATA_ERROR.into());
    }
    let operation = word(fields[0])?;
    if operation != 0 {
        return Err(Error::Unsupported(
            "software policy command is not QueryPolicy0",
        ));
    }
    if fields.len() < 7 {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let reply_context: &[u8; 160] = fields[1].try_into().map_err(|_| STATUS_UNSUCCESSFUL)?;
    let reply_key = u64::from_le_bytes(fields[2].try_into().map_err(|_| STATUS_UNSUCCESSFUL)?);
    if fields[3].len() != 8 {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let raw_name = fields[4];
    if raw_name.len() < 2 || raw_name.len() % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let mut name: Vec<_> = raw_name
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    if name.pop() != Some(0) || name.is_empty() || name.contains(&0) {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let _query_flags = word(fields[5])?;
    let capacity = word(fields[6])? as usize;
    let value = catalog.value(&name)?;
    let (status, data) = if capacity == 0 {
        (0, Vec::new())
    } else if capacity < value.data.len() {
        (STATUS_BUFFER_TOO_SMALL, vec![0; capacity])
    } else {
        (0, value.data.to_vec())
    };
    let mut payload = Vec::new();
    push_block(&mut payload, &(status | 0x1000_0000).to_le_bytes());
    push_block(&mut payload, fields[3]);
    push_block(&mut payload, &value.kind.to_le_bytes());
    push_block(&mut payload, &data);
    push_block(&mut payload, &(value.data.len() as u32).to_le_bytes());
    // This immutable virtual catalog has no external policy-cache updater.
    push_block(&mut payload, &0u32.to_le_bytes());
    let mut reply = Vec::with_capacity(payload.len() + 15);
    reply.extend_from_slice(&6u32.to_le_bytes());
    reply.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    reply.extend_from_slice(&payload);
    // ParameterBytes excludes block-alignment padding. Do not reproduce the
    // native allocator's undefined trailing bytes or expose host memory.
    reply.resize(reply.len().next_multiple_of(8), 0);
    let sum = checksum(&reply);
    let mut encoded = codec::transform(&reply, reply_context, reply_key, Direction::Reply, false)
        .ok_or(STATUS_UNSUCCESSFUL)?;
    encoded.extend_from_slice(&sum.to_le_bytes());
    let mut output = Vec::with_capacity(encoded.len() + 180);
    push_block(&mut output, &encoded);
    push_block(&mut output, reply_context);
    push_block(&mut output, &reply_key.to_le_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests;
