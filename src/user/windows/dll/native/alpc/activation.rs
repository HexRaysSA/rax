//! The installed isolation-aware DLL manifest exchange for an owned CSR peer.
use super::super::query::probe_write;
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, Mem, MemFault, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const SELECTOR: u32 = 0x0001_001e;
const WIRE_BYTES: usize = 0x238;
const HEADER_BYTES: usize = 0x40;
const SLOTS: [usize; 4] = [0x68, 0xa0, 0xd0, 0x50];
const MANIFEST_FILE: usize = 0x78;
const MANIFEST_ADDRESS: usize = 0x80;
const MANIFEST_SIZE: usize = 0x88;

fn half(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().unwrap(),
    ))
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(super) fn is_request(message: &[u8]) -> bool {
    message.len() == WIRE_BYTES
        && message[..8] == [0x10, 2, 0x38, 2, 0, 0, 0, 0]
        && dword(message, 0x30) == SELECTOR
}

fn capture_fields(message: &[u8], base: u64, data: &[u8]) -> Option<[String; 4]> {
    if data.len() < HEADER_BYTES || dword(data, 0x10) != 4 || word(data, 0x18) != 0 {
        return None;
    }
    let mut fields = Vec::with_capacity(4);
    let mut previous_end = HEADER_BYTES;
    for (index, slot) in SLOTS.into_iter().enumerate() {
        if word(data, 0x20 + index * 8) != slot as u64 {
            return None;
        }
        let start = usize::try_from(word(message, slot).checked_sub(base)?).ok()?;
        let used = half(message, slot - 8);
        let capacity = half(message, slot - 6);
        let end = start.checked_add(capacity)?;
        if start < previous_end
            || end > data.len()
            || used > capacity
            || (start | used | capacity) % 2 != 0
        {
            return None;
        }
        let units: Vec<_> = data[start..start + used]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        fields.push(String::from_utf16(&units).ok()?);
        previous_end = end;
    }
    fields.try_into().ok()
}

fn overlap(first: u64, first_size: u64, second: u64, second_size: u64) -> bool {
    first < second.saturating_add(second_size) && second < first.saturating_add(first_size)
}

pub(super) fn reply(
    c: &mut Ctx,
    port: u64,
    [
        receive,
        received,
        send_attributes,
        receive_attributes,
        timeout,
    ]: [u64; 5],
    capacity: u64,
    message: &[u8],
) -> ApiResult {
    if c.arch() != WinArch::Arm64
        || (send_attributes | receive_attributes | timeout) != 0
        || received == 0
        || dword(message, 0x40) != 0x4041
        || dword(message, 0x44) != 12
        || word(message, MANIFEST_FILE) != u64::MAX
        || word(message, 0xf0) != 2
    {
        return Err(c.unsupported("unmeasured CSR activation-context request fields"));
    }
    let Some(snapshot) = c.p.object_namespace.activation_context.clone() else {
        return Err(c.unsupported("installed activation context is unavailable"));
    };
    let manifest = word(message, MANIFEST_ADDRESS);
    let manifest_len = snapshot.manifest.len() as u64;
    let image_rva = if let Some(view) = c.p.vm.section_view(manifest) {
        manifest.checked_sub(view.image_base).and_then(|within| {
            if view.section.file_identity() != Some(&snapshot.file_identity)
                || within.checked_add(manifest_len)? > view.size
            {
                return None;
            }
            view.offset.checked_add(within)
        })
    } else {
        c.p.modules.by_address(manifest).and_then(|(_, module)| {
            let within = manifest.checked_sub(module.base)?;
            (module.host_path.as_ref() == Some(&snapshot.image)
                && within.checked_add(manifest_len)? <= module.size)
                .then_some(within)
        })
    };
    if image_rva != Some(u64::from(snapshot.manifest_rva))
        || word(message, MANIFEST_SIZE) != manifest_len
        || c.mem().bytes(manifest, snapshot.manifest.len())? != snapshot.manifest
    {
        return Err(c.unsupported("CSR activation manifest differs from the installed selection"));
    }
    let capture = word(message, 0x28);
    let mut capture_data = {
        let Some(Object::LpcPort(port)) = c.p.objects.get(port) else {
            unreachable!("verified ALPC port");
        };
        let Some((peer, view)) = port.peer().zip(port.view()) else {
            return Err(c.unsupported("CSR activation requires a selected peer"));
        };
        let owns = |bytes| {
            capture >= peer.base
                && capture % 8 == 0
                && capture
                    .checked_add(bytes)
                    .zip(peer.base.checked_add(view.size))
                    .is_some_and(|(end, limit)| end <= limit)
        };
        if !peer.arm64_29708_session_one
            || !c.p.vm.owns_shared_view(view)
            || !owns(HEADER_BYTES as u64)
        {
            return Err(c.unsupported("CSR activation capture is outside the selected peer view"));
        }
        let memory = peer.vm.space();
        let size = memory.u32(capture)? as usize;
        if !(HEADER_BYTES..=4096).contains(&size) || !owns(size as u64) {
            return Err(c.unsupported("CSR activation capture size is outside the peer view"));
        }
        memory
            .probe(capture, size, MemoryAccessKind::Write)
            .map_err(|error| MemFault {
                addr: error.address,
                write: true,
            })?;
        memory.bytes(capture, size)?
    };
    let Some([image, config, directory, languages]) =
        capture_fields(message, capture, &capture_data)
    else {
        return Err(c.unsupported("unmeasured CSR activation capture fields"));
    };
    let Some((root, _)) = snapshot.guest_path.rsplit_once('\\') else {
        return Err(c.unsupported("CSR activation manifest has no selected DOS directory"));
    };
    if !image.eq_ignore_ascii_case(&snapshot.guest_path)
        || !config.eq_ignore_ascii_case(&format!("{}.2.Config", snapshot.guest_path))
        || !directory.eq_ignore_ascii_case(&format!("{root}\\"))
        || !languages.eq_ignore_ascii_case("en-US\0en\0\0")
    {
        return Err(
            c.unsupported("CSR activation paths or languages differ from the installed selection")
        );
    }
    let out = word(message, 0xf8);
    if out % 8 != 0
        || out < c.entry_sp.max(c.t.stack_limit)
        || out.checked_add(8).is_none_or(|end| end > c.t.stack_base)
        || overlap(out, 8, receive, WIRE_BYTES as u64)
        || overlap(out, 8, received, 8)
        || overlap(received, 8, receive, WIRE_BYTES as u64)
        || c.mem().u64(out)? != 0
    {
        return Err(c.unsupported(
            "CSR activation output is outside the calling stack or aliases its reply",
        ));
    }
    probe_write(c, received, 8)?;
    if capacity < WIRE_BYTES as u64 {
        c.write_ptr(received, WIRE_BYTES as u64)?;
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    probe_write(c, receive, WIRE_BYTES)?;
    probe_write(c, out, 8)?;
    let size = snapshot.view.size;
    let Some(base) = c.p.vm.find_free(
        size,
        ALLOCATION_GRANULARITY,
        c.p.vm.low(),
        c.p.vm.high(),
        false,
    ) else {
        return Flow::ret(STATUS_NO_MEMORY.into());
    };
    if let Err(error) =
        c.p.vm
            .map_data_section(snapshot.view.clone(), base, 0, size, prot::READONLY)
    {
        return Flow::ret(error.status().into());
    }
    let Some(Object::LpcPort(port)) = c.p.objects.get_mut(port) else {
        unreachable!("verified ALPC port");
    };
    let peer = port.peer_mut().expect("verified CSR peer");
    let (reply_capture, message_id) = match peer.prepare_capture_buffer(&mut capture_data) {
        Ok(reply) => reply,
        Err(error) => {
            c.p.vm.release(base).map_err(|rollback| {
                ApiErr::Internal(format!(
                    "CSR activation mapping rollback failed: {rollback:?}"
                ))
            })?;
            return Flow::ret(error.status().into());
        }
    };
    peer.vm.space().wr(capture, &capture_data)?;
    let mut reply = message.to_vec();
    reply[4..40].fill(0);
    reply[4..6].copy_from_slice(&2u16.to_le_bytes());
    reply[8..16].copy_from_slice(&u64::from(peer.server_pid).to_le_bytes());
    reply[16..24].copy_from_slice(&u64::from(peer.server_thread).to_le_bytes());
    reply[24..28].copy_from_slice(&message_id.to_le_bytes());
    reply[32..36].copy_from_slice(&message_id.to_le_bytes());
    reply[0x28..0x30].copy_from_slice(&reply_capture.to_le_bytes());
    reply[0x34..0x38].fill(0);
    reply[0xe8..0xf0].copy_from_slice(&snapshot.manifest_time.to_le_bytes());
    c.mem().wr(receive, &reply)?;
    c.write_ptr(out, base)?;
    c.write_ptr(received, WIRE_BYTES as u64)?;
    Flow::ret(STATUS_SUCCESS.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_capture_checks_slot_order_and_complete_non_overlapping_ranges() {
        let base = 0x10000u64;
        let mut data = [0u8; 0x80];
        data[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
        let mut message = [0u8; WIRE_BYTES];
        message[..8].copy_from_slice(&[0x10, 2, 0x38, 2, 0, 0, 0, 0]);
        message[0x30..0x34].copy_from_slice(&SELECTOR.to_le_bytes());
        for (index, slot) in SLOTS.into_iter().enumerate() {
            let member = 0x20 + 8 * index;
            data[member..member + 8].copy_from_slice(&(slot as u64).to_le_bytes());
            let start = HEADER_BYTES + 4 * index;
            data[start] = b'A' + index as u8;
            message[slot - 8..slot - 4].copy_from_slice(&[2, 0, 4, 0]);
            message[slot..slot + 8].copy_from_slice(&(base + start as u64).to_le_bytes());
        }
        assert!(is_request(&message));
        let fields = capture_fields(&message, base, &data).unwrap();
        assert_eq!(fields.each_ref().map(String::as_str), ["A", "B", "C", "D"]);
        let slot = SLOTS[3];
        for address in [base - 1, base + 64, base + 77, base + 126, u64::MAX] {
            message[slot..slot + 8].copy_from_slice(&address.to_le_bytes());
            assert!(capture_fields(&message, base, &data).is_none());
        }
    }
}
