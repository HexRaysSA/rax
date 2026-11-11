//! Validate the guest exchange and publish the peer reply transactionally.
use crate::user::windows::dll::native::query::probe_write;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::cache::{
    CachePeer, LOOKUP_ACCESS, lookup_file, lookup_request,
};
use crate::user::windows::objects::Object;

const ATTRIBUTES: u32 = 0x3000_0000;
const HANDLE: u32 = 0x1000_0000;
const CONTEXT: u32 = 0x2000_0000;
const SECTION_ACCESS: u32 = 0xc;

pub(in super::super) fn lookup(
    c: &mut Ctx,
    port: u64,
    [
        send_attributes,
        receive,
        length,
        receive_attributes,
        timeout,
    ]: [u64; 5],
    capacity: u64,
    message: &[u8],
) -> ApiResult {
    if !c.arch().is64()
        || c.p.native.is_none()
        || timeout != 0
        || capacity != 80
        || message != lookup_request()
    {
        return Err(c.unsupported("translation-cache lookup profile is not measured"));
    }
    let sent = c.mem().bytes(send_attributes, 64)?;
    let mut expected = [0; 64];
    expected[..4].copy_from_slice(&ATTRIBUTES.to_le_bytes());
    expected[4..8].copy_from_slice(&HANDLE.to_le_bytes());
    expected[48..56].copy_from_slice(&sent[48..56]);
    expected[60..64].copy_from_slice(&LOOKUP_ACCESS.to_le_bytes());
    if sent != expected {
        return Err(c.unsupported("translation-cache file transfer attributes are not measured"));
    }
    let source = u64::from_le_bytes(sent[48..56].try_into().expect("captured file handle"));
    let Some(Object::File(file)) = c.p.objects.get(source) else {
        return Flow::ret(
            if c.p.objects.get(source).is_some() {
                STATUS_OBJECT_TYPE_MISMATCH
            } else {
                STATUS_INVALID_HANDLE
            }
            .into(),
        );
    };
    if c.p.objects.access(source).unwrap_or(0) & LOOKUP_ACCESS != LOOKUP_ACCESS {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    let Some(host) = file.host.as_ref().filter(|_| !file.directory && !file.null) else {
        return Err(c.unsupported("translation-cache source has no retained regular file"));
    };

    let mut reply_attributes: [u8; 64] = c
        .mem()
        .bytes(receive_attributes, 64)?
        .try_into()
        .expect("captured receive attributes");
    if reply_attributes[..4] != ATTRIBUTES.to_le_bytes() || reply_attributes[4..8] != [0; 4] {
        return Err(c.unsupported("translation-cache receive attributes are not measured"));
    }
    let outputs = [(receive, 80usize), (length, 8), (receive_attributes, 64)];
    let mut originals = Vec::with_capacity(outputs.len());
    // O(1) capture and rollback. Check every output before acquiring a
    // transferred Section or committing a sequence number to the guest peer.
    for (index, (address, size)) in outputs.into_iter().enumerate() {
        let end = address
            .checked_add(size as u64)
            .ok_or_else(|| c.unsupported("translation-cache output wraps"))?;
        if outputs[..index].iter().any(|(other, size)| {
            other
                .checked_add(*size as u64)
                .is_none_or(|other_end| address < other_end && *other < end)
        }) {
            return Err(c.unsupported("translation-cache overlapping outputs are not measured"));
        }
        probe_write(c, address, size)?;
        let mut bytes = vec![0; size];
        c.p.space.read_raw(address, &mut bytes).map_err(|fault| {
            ApiErr::Internal(format!("translation-cache output capture: {fault:?}"))
        })?;
        originals.push((address, bytes));
    }

    let Some(Object::LpcPort(endpoint)) = c.p.objects.get(port) else {
        unreachable!("captured cache endpoint")
    };
    let peer = endpoint.cache_peer().expect("captured cache peer");
    if peer.pending_reply.is_some() {
        return Err(c.unsupported("translation-cache reply is still owned by this endpoint"));
    }
    let Some(sequence) = peer.lookup_slot.checked_add(2) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let section = lookup_file(host)
        .map_err(|error| c.unsupported(format!("translation-cache lookup: {error}")))?;
    let Some(callback) = peer.next_callback() else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let reply = reply_packet(peer, callback, section.is_some());
    let message_id = peer.connection_message;
    let handle = if let Some(section) = section {
        // Repeated service lookups can return the same native Section object.
        // Keep a single guest object while assigning independent handle slots.
        let existing = c.p.objects.iter().find_map(|(id, object)| match object {
            Object::FileSection(other) if section.same_imported_section(other) => Some(id),
            _ => None,
        });
        let Some(id) = existing.or_else(|| c.p.objects.try_create(Object::FileSection(section)))
        else {
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        let Some(handle) = c.p.objects.open_access(id, false, SECTION_ACCESS) else {
            if existing.is_none() {
                c.p.objects.release(id);
            }
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        Some(handle)
    } else {
        None
    };
    publish_attributes(
        &mut reply_attributes,
        port,
        sequence,
        message_id,
        callback,
        handle,
    );
    let result = (|| -> Result<(), ApiErr> {
        c.mem().wr(receive, &reply)?;
        c.mem().wr(receive_attributes, &reply_attributes)?;
        c.write_ptr(length, reply.len() as u64)?;
        Ok(())
    })();
    if let Err(error) = result {
        if let Some(handle) = handle {
            c.p.objects.close(handle.into());
        }
        for (address, original) in originals {
            c.p.space.write_raw(address, &original).map_err(|fault| {
                ApiErr::Internal(format!("translation-cache output rollback: {fault:?}"))
            })?;
        }
        return Err(error);
    }
    let Some(Object::LpcPort(endpoint)) = c.p.objects.get_mut(port) else {
        unreachable!("captured cache endpoint")
    };
    let peer = endpoint.cache_peer_mut().expect("captured cache peer");
    peer.lookup_slot += 1;
    if handle.is_some() {
        peer.pending_reply = Some(reply);
    }
    Flow::ret(STATUS_SUCCESS.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::object_namespace::cache::{CacheMetadata, CacheServer};

    #[test]
    fn native_cache_lookup_reply_copies_measured_hit_and_miss_fields() {
        let server = CacheServer::selected(CacheMetadata {
            kernel: (10, 0, 29704),
            native_machine: 0xaa64,
            server_pid: 0x90c,
        })
        .unwrap();
        let mut peer = server.peer().unwrap();
        peer.lookup_slot = 3;
        let callback = peer.next_callback().unwrap();
        for handle in [None, Some(0x118)] {
            let packet = reply_packet(&peer, callback, handle.is_some());
            let mut expected = [0; 80];
            expected[..8].copy_from_slice(&[
                0x28,
                0,
                0x50,
                0,
                2,
                if handle.is_some() { 0x20 } else { 0 },
                0,
                0,
            ]);
            expected[8..12].copy_from_slice(&[0x0c, 9, 0, 0]);
            expected[16] = 4;
            expected[24] = 1;
            expected[32] = 2;
            expected[40] = 3;
            expected[48] = 3;
            assert_eq!(packet, expected);

            let mut attributes = [0xa5; 64];
            attributes[..4].copy_from_slice(&ATTRIBUTES.to_le_bytes());
            publish_attributes(&mut attributes, 0x7c, 5, 1, callback, handle);
            let mut expected = [0; 64];
            expected[3] = 0x30;
            expected[7] = if handle.is_some() { 0x30 } else { 0x20 };
            expected[8] = 0x7c;
            expected[24] = 5;
            expected[28] = 1;
            expected[32] = 2;
            if handle.is_some() {
                expected[48..50].copy_from_slice(&[0x18, 1]);
                expected[56] = 0x80;
                expected[60] = 0x0c;
            } else {
                expected[40..].fill(0xa5);
            }
            assert_eq!(attributes, expected);
        }
        assert_ne!(peer.next_callback(), Some(callback));
    }
}

fn reply_packet(peer: &CachePeer, callback: u32, hit: bool) -> Vec<u8> {
    let mut reply = vec![0; 80];
    reply[..4].copy_from_slice(&[40, 0, 80, 0]);
    reply[4..6].copy_from_slice(&(if hit { 0x2002u16 } else { 2 }).to_le_bytes());
    reply[8..16].copy_from_slice(&u64::from(peer.server_pid).to_le_bytes());
    reply[16..24].copy_from_slice(&u64::from(peer.server_thread).to_le_bytes());
    reply[24..28].copy_from_slice(&peer.connection_message.to_le_bytes());
    reply[32..36].copy_from_slice(&callback.to_le_bytes());
    reply[40] = 3;
    reply[48..52].copy_from_slice(&peer.lookup_slot.to_le_bytes());
    reply
}

fn publish_attributes(
    attributes: &mut [u8; 64],
    port: u64,
    sequence: u32,
    message_id: u32,
    callback: u32,
    handle: Option<u32>,
) {
    let valid = if handle.is_some() {
        ATTRIBUTES
    } else {
        CONTEXT
    };
    attributes[4..8].copy_from_slice(&valid.to_le_bytes());
    attributes[8..40].fill(0);
    attributes[8..16].copy_from_slice(&port.to_le_bytes());
    attributes[24..28].copy_from_slice(&sequence.to_le_bytes());
    attributes[28..32].copy_from_slice(&message_id.to_le_bytes());
    attributes[32..36].copy_from_slice(&callback.to_le_bytes());
    if let Some(handle) = handle {
        attributes[40..64].fill(0);
        attributes[48..56].copy_from_slice(&u64::from(handle).to_le_bytes());
        attributes[56..60].copy_from_slice(&0x80u32.to_le_bytes());
        attributes[60..64].copy_from_slice(&SECTION_ACCESS.to_le_bytes());
    }
}
