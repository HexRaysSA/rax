//! One measured CSR startup connection, with real client/server backing.
use super::*;
use crate::user::windows::memory::prot;
use crate::user::windows::object_namespace::csr::CsrServer;
use crate::user::windows::objects::{LpcPort, Object};
use std::sync::Arc;

const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const QOS: [u8; 12] = [0, 0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0];

pub(super) fn connect(c: &mut Ctx, request: &Capture, server: Arc<CsrServer>) -> ApiResult {
    let metadata = &server.metadata;
    if c.arch() != WinArch::Arm64
        || metadata.arch != c.arch()
        || !crate::user::windows::object_namespace::csr::supports_kernel(
            c.p.cfg.version.major,
            c.p.cfg.version.minor,
            c.p.cfg.version.build,
        )
        || metadata.session != 0
        || metadata.server_pid == c.p.pid
        || request.client_length != Some(48)
        || request.server_length != Some(24)
        || request.qos == 0
        || request.sid == 0
        || request.length == 0
        || request.information == 0
        || request.maximum == 0
    {
        return Err(c.unsupported("NtSecureConnectPort selected CSR startup profile differs"));
    }
    // SessionId is initialized to zero in the current guest PEB. A modified
    // or future nonzero-session PEB cannot borrow this session0 section/profile.
    if c.mem().u32(c.p.peb + 0x2C0)? != metadata.session
        || c.mem().bytes(request.qos, 12)? != QOS
        || c.mem().bytes(request.sid, 12)? != SYSTEM_SID
        || c.mem().u32(request.length)? != 48
    {
        return Err(c.unsupported(
            "NtSecureConnectPort unmeasured CSR session, QoS, SID or information size",
        ));
    }
    let mut view = [0; 48];
    c.mem().rd(request.client, &mut view)?;
    let section_handle = u64::from_le_bytes(view[8..16].try_into().expect("fixed section span"));
    let offset = u32::from_le_bytes(view[16..20].try_into().expect("fixed section offset"));
    let size = u64::from_le_bytes(view[24..32].try_into().expect("fixed view size"));
    if offset != 0 || size != 65536 || view[32..48] != [0; 16] {
        return Err(c.unsupported("NtSecureConnectPort unmeasured CSR client-view geometry"));
    }
    let mut information = [0; 48];
    c.mem().rd(request.information, &mut information)?;
    if information[..32] != [0; 32] || information[32..40] != 1u64.to_le_bytes() {
        return Err(c.unsupported("NtSecureConnectPort unmeasured CSR startup information packet"));
    }
    let backing = match c.p.objects.get(section_handle) {
        Some(Object::Mapping {
            file: None,
            size: section_size,
            protect,
            attributes,
            shared: Some(backing),
        }) if *section_size == size
            && *protect == prot::READWRITE
            && *attributes == 0x0800_0000
            && c.p
                .objects
                .access(section_handle)
                .is_some_and(|grant| grant & 2 != 0) =>
        {
            backing.clone()
        }
        _ => {
            return Err(c.unsupported(
                "NtSecureConnectPort requires the selected writable committed pagefile section",
            ));
        }
    };
    // Reject unmeasured overlapping outputs before allocating or publishing.
    // Six fixed spans: O(1) comparisons and 136 bytes of undo data.
    let spans = [
        (request.out, 8),
        (request.client, 48),
        (request.server, 24),
        (request.maximum, 4),
        (request.information, 48),
        (request.length, 4),
    ];
    for (index, &(base, bytes)) in spans.iter().enumerate() {
        let Some(end) = base.checked_add(bytes) else {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        };
        for &(other, length) in &spans[..index] {
            if other
                .checked_add(length)
                .is_none_or(|other_end| base < other_end && other < end)
            {
                return Err(c.unsupported("NtSecureConnectPort overlapping CSR output spans"));
            }
        }
        if base == request.length && probe_write(c, base, bytes as usize).is_err() {
            return Err(c.unsupported(
                "NtSecureConnectPort readonly CSR information-length success path is unmeasured",
            ));
        }
        probe_write(c, base, bytes as usize)?;
    }
    let mut originals = Vec::with_capacity(spans.len());
    for &(base, bytes) in &spans {
        let mut data = vec![0; bytes as usize];
        c.p.space
            .read_raw(base, &mut data)
            .map_err(|e| ApiErr::Internal(format!("CSR prepared-output snapshot: {e:?}")))?;
        originals.push((base, data));
    }
    let peer = match server.peer(backing.clone(), size) {
        Ok(peer) => peer,
        Err(error) => return Flow::ret(error.status().into()),
    };
    let remote = peer.base;
    let owner = match c.p.vm.map_shared_view(backing, None, 0, size) {
        Ok(owner) => owner,
        Err(error) => return Flow::ret(error.status().into()),
    };
    let local = owner.base;
    let Some(id) =
        c.p.objects
            .try_create(Object::LpcPort(LpcPort::csr(owner.clone(), peer)))
    else {
        c.p.vm
            .retire_shared_view(&owner)
            .map_err(|e| ApiErr::Internal(format!("CSR publication rollback: {e:?}")))?;
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, false, 0x001F_0001) else {
        c.p.objects.release(id);
        c.p.reclaim_scheduler_views()
            .map_err(|e| ApiErr::Internal(format!("CSR handle rollback: {e:?}")))?;
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    view[32..40].copy_from_slice(&local.to_le_bytes());
    view[40..48].copy_from_slice(&remote.to_le_bytes());
    information[..8].copy_from_slice(&metadata.server_base.to_le_bytes());
    information[8..16]
        .copy_from_slice(&(metadata.server_base + metadata.statics_offset).to_le_bytes());
    information[16..24].copy_from_slice(&u64::from(metadata.server_pid).to_le_bytes());
    // Preserve the final16 caller bytes exactly; no address-looking-word rewrite.
    // Every output was checked before publication and the process is serialized.
    let result = (|| -> Result<(), ApiErr> {
        c.mem().wr(request.client, &view)?;
        c.mem().wr(request.server, &[0; 24])?;
        c.mem().w32(request.maximum, 952)?;
        c.mem().wr(request.information, &information)?;
        c.mem().w64(request.out, u64::from(handle))?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = c.p.objects.close(handle.into());
        c.p.reclaim_scheduler_views()
            .map_err(|e| ApiErr::Internal(format!("CSR copyback rollback: {e:?}")))?;
        for (base, data) in originals {
            c.p.space
                .write_raw(base, &data)
                .map_err(|e| ApiErr::Internal(format!("CSR output rollback: {e:?}")))?;
        }
        return Err(error);
    }
    Flow::ret(STATUS_SUCCESS.into())
}
