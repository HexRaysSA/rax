//! Measured CSR USER and BASE replies in owned client/server address spaces.
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::csr::BaseNlsReply;
use crate::user::windows::objects::Object;

fn word(message: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .expect("validated CSR message span"),
    )
}

pub(super) fn client_connect(
    c: &mut Ctx,
    port: u64,
    send_attributes: u64,
    receive: u64,
    length: u64,
    receive_attributes: u64,
    timeout: u64,
    capacity: u64,
    message: &[u8],
) -> ApiResult {
    let base_nls = message.len() == 80
        && message[..8] == [40, 0, 80, 0, 0, 0, 0, 0]
        && message[48..64] == [0x1B, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        && word(message, 72) == 1660
        && c.p.cfg.version.build == 29698;
    let user = message.len() == 88
        && message[..8] == [48, 0, 88, 0, 0, 0, 0, 0]
        && message[48..64] == [0; 16]
        && word(message, 64) == 3
        && word(message, 80) == 584;
    if c.arch() != WinArch::Arm64
        || !crate::user::windows::object_namespace::csr::supports_kernel(
            c.p.cfg.version.major,
            c.p.cfg.version.minor,
            c.p.cfg.version.build,
        )
        || send_attributes != 0
        || receive_attributes != 0
        || timeout != 0
        || !(base_nls || user)
    {
        return Err(c.unsupported("NtAlpcSendWaitReceivePort unmeasured CSR message/profile"));
    }
    let (view, remote, user_data, nls_data, server_pid, server_thread) = match c.p.objects.get(port)
    {
        Some(Object::LpcPort(port)) => {
            let Some(peer) = port.peer() else {
                return Err(
                    c.unsupported("NtAlpcSendWaitReceivePort endpoint has no selected peer")
                );
            };
            let Some(view) = port.view() else {
                return Err(
                    c.unsupported("NtAlpcSendWaitReceivePort selected client view is absent")
                );
            };
            (
                view.clone(),
                peer.base,
                peer.client_data.clone(),
                peer.base_nls.clone(),
                peer.server_pid,
                peer.server_thread,
            )
        }
        _ => return Err(c.unsupported("NtAlpcSendWaitReceivePort selected peer disappeared")),
    };
    if base_nls && nls_data.is_none() || user && user_data.is_none() {
        return Err(c.unsupported("NtAlpcSendWaitReceivePort selected reply data is absent"));
    }
    if !c.p.vm.owns_shared_view(&view) {
        return Err(c.unsupported("NtAlpcSendWaitReceivePort client view was unmapped or replaced"));
    }
    let capture = word(message, 40);
    let pointer_offset = if base_nls { 64 } else { 72 };
    let information = word(message, pointer_offset);
    let information_len = if base_nls { 1660 } else { 584 };
    let capture_bytes = 40 + information_len as u64 + 4;
    if capture < remote
        || capture.checked_add(capture_bytes).is_none_or(|end| {
            remote
                .checked_add(view.size)
                .is_none_or(|limit| end > limit)
        })
        || capture % 8 != 0
        || capture.checked_add(40) != Some(information)
    {
        return Err(c.unsupported("NtAlpcSendWaitReceivePort capture leaves owned peer view"));
    }
    let mut header = [0; 40];
    {
        let Some(Object::LpcPort(port)) = c.p.objects.get(port) else {
            unreachable!("serialized peer")
        };
        let peer = port.peer().expect("selected peer");
        peer.vm
            .space()
            .rd(capture, &mut header)
            .map_err(|e| ApiErr::Internal(format!("CSR peer capture: {e:?}")))?;
        if u64::from(u32::from_le_bytes(
            header[..4].try_into().expect("capture length"),
        )) != capture_bytes
            || u32::from_le_bytes(header[16..20].try_into().expect("capture pointer count")) != 1
            || word(&header, 24) != 0
            || word(&header, 32) != pointer_offset as u64
            || !base_nls
                && peer
                    .vm
                    .space()
                    .bytes(information, 584)
                    .map_err(|e| ApiErr::Internal(format!("CSR peer information: {e:?}")))?
                    != [0; 584]
        {
            return Err(
                c.unsupported("NtAlpcSendWaitReceivePort unmeasured CSR capture schema/input")
            );
        }
    }
    let unchanged;
    let (information_bytes, reply_status): (&[u8], u32) = if base_nls {
        match nls_data.as_ref().expect("selected BASE reply") {
            BaseNlsReply::Information(bytes) => (bytes.as_slice(), 0),
            BaseNlsReply::Unsuccessful => {
                let Some(Object::LpcPort(port)) = c.p.objects.get(port) else {
                    unreachable!("serialized peer")
                };
                unchanged = port
                    .peer()
                    .expect("selected peer")
                    .vm
                    .space()
                    .bytes(information, information_len)
                    .map_err(|e| ApiErr::Internal(format!("CSR unchanged BASE input: {e:?}")))?;
                (&unchanged, STATUS_UNSUCCESSFUL)
            }
        }
    } else {
        (
            &user_data.as_ref().expect("selected USER data").information,
            0,
        )
    };
    // BASE NLS is an opaque copied payload with no client mappings. USER owns
    // its two independently selected readonly mappings as before.
    let allocated = if base_nls {
        Vec::new()
    } else {
        user_data
            .as_ref()
            .expect("selected USER data")
            .map(&mut c.p.vm)
            .map_err(|error| c.unsupported(format!("CSR USER mapping admission: {error:?}")))?
    };
    let prepared = {
        let Some(Object::LpcPort(port)) = c.p.objects.get_mut(port) else {
            unreachable!("serialized peer")
        };
        port.peer_mut()
            .expect("selected peer")
            .prepare_capture(&header, information_bytes)
    };
    let (server_capture, message_id) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            for base in allocated.into_iter().rev() {
                c.p.vm
                    .release(base)
                    .map_err(|e| ApiErr::Internal(format!("CSR client mapping rollback: {e:?}")))?;
            }
            return Err(c.unsupported(format!("CSR private capture admission: {error:?}")));
        }
    };
    {
        let Some(Object::LpcPort(port)) = c.p.objects.get(port) else {
            unreachable!("serialized peer")
        };
        let peer = port.peer().expect("selected peer");
        // Writes use the server's shared view. Client page protections and
        // dangling/replaced client addresses cannot redirect these writes.
        if reply_status == STATUS_SUCCESS {
            peer.vm
                .space()
                .wr(information, information_bytes)
                .map_err(|e| ApiErr::Internal(format!("CSR information reply: {e:?}")))?;
        }
        peer.vm
            .space()
            .w64(capture + 8, 0)
            .map_err(|e| ApiErr::Internal(format!("CSR related-buffer reply: {e:?}")))?;
    }
    if length != 0 {
        c.write_ptr(length, message.len() as u64)?;
    }
    if capacity < message.len() as u64 {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    let mut reply = message.to_vec();
    reply[4..40].fill(0);
    reply[4..6].copy_from_slice(&2u16.to_le_bytes());
    reply[8..16].copy_from_slice(&u64::from(server_pid).to_le_bytes());
    reply[16..24].copy_from_slice(&u64::from(server_thread).to_le_bytes());
    reply[24..28].copy_from_slice(&message_id.to_le_bytes());
    // This cookie is an owned virtual-message identifier, not a captured host
    // kernel cookie or an address. Native cookies are opaque to the CSR client.
    reply[32..36].copy_from_slice(&message_id.to_le_bytes());
    reply[40..48].copy_from_slice(&server_capture.to_le_bytes());
    reply[52..56].copy_from_slice(&reply_status.to_le_bytes());
    c.mem().wr(receive, &reply)?;
    Flow::ret(STATUS_SUCCESS.into())
}
