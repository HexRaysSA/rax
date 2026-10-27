//! Pure-x86 BASE bridge measured on ARM64 Windows 10.0.29695/session0.
//! Five stdcall arguments, including a scalar ULONG byte count. No request
//! invokes host CSR: selected immutable bytes and two owned VMs supply it.
use super::query::write_guard_result;
use crate::user::mm::SharedObject;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, VmError, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::LookupError;
use crate::user::windows::object_namespace::csr::CsrServer;
use crate::user::windows::objects::{LpcPort, Object};
use crate::user::windows::process::{Proc, wow64::CsrConnection};
use std::sync::Arc;

const KERNEL: (u32, u32, u32) = (10, 0, 29695);
const VIEW_BYTES: u64 = 65536;
const MAX_CAPTURE: u32 = 80;

pub(super) fn connect(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    let result = write_guard_result(c, result);
    // This WoW64 service catches caller-memory faults and returns NTSTATUS.
    if matches!(result, Err(ApiErr::Fault(_))) {
        Flow::ret(STATUS_ACCESS_VIOLATION.into())
    } else {
        result
    }
}

fn selected(c: &Ctx) -> Result<Arc<CsrServer>, ApiErr> {
    let unsupported = || c.unsupported("unmeasured WoW64 CSR kernel, architecture or session");
    let state = c.p.wow64.as_ref().ok_or_else(unsupported)?;
    let server = c
        .p
        .object_namespace
        .csr_server(&"\\Windows\\ApiPort".encode_utf16().collect::<Vec<_>>())
        .map_err(|_| c.unsupported("WoW64 CSR requires the selected server and shared section"))?;
    let metadata = &server.metadata;
    if c.arch() != WinArch::X86
        || state.machine != 0xaa64
        || state.kernel != KERNEL
        || metadata.arch != WinArch::Arm64
        || metadata.kernel != KERNEL
        || metadata.session != 0
        || metadata.server_pid == c.p.pid
        || c.mem().u32(c.p.peb + offsets(c.arch()).peb_session_id)? != 0
    {
        return Err(unsupported());
    }
    if let Some(connection) = &state.csr {
        let valid_port = c.p.objects.id(connection.port.into()) == Some(connection.object)
            && matches!(c.p.objects.get(connection.port.into()), Some(Object::LpcPort(port))
                if port.peer().is_some_and(|peer| peer.server_pid == metadata.server_pid)
                && port.view().is_some_and(|view| c.p.vm.owns_shared_view(view)));
        if !Arc::ptr_eq(&connection.section, &server.section())
            || !valid_port
            || !c
                .p
                .vm
                .owns_readonly_data_view(connection.base, &connection.section)
        {
            return Err(c.unsupported("WoW64 CSR connection or shared-view identity was retired"));
        }
    }
    native_publication(c, &server)?;
    Ok(server)
}

/// A native64 RTL instance is not executing in the guest. Its three modeled
/// CSR fields must describe exactly the owned connection (or initial zeros).
/// Never convert caller-mutated private native pointers into a success reply.
fn native_publication(c: &Ctx, server: &CsrServer) -> Result<(), ApiErr> {
    let state = c.p.wow64.as_ref().expect("selected WoW64 identity");
    let expected = state.csr.as_ref().map_or([0; 3], |connection| {
        [
            connection.base,
            connection.base + server.metadata.statics_offset,
            server.metadata.server_base,
        ]
    });
    for (offset, value) in [0x88, 0x98, 0x380].into_iter().zip(expected) {
        if c.mem().u64(state.native_peb + offset)? != value {
            return Err(
                c.unsupported("WoW64 CSR native PEB fields differ from the owned connection")
            );
        }
    }
    Ok(())
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (root, server_id, buffer, bytes, inside) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    let server = selected(c)?;
    if server_id != 1 {
        return Err(c.unsupported("WoW64 CSR server other than measured BASE server1"));
    }
    // No capture, root lookup, allocation or Boolean store on this failure.
    if buffer != 0 && bytes == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if buffer != 0 && bytes > MAX_CAPTURE {
        return Err(c.unsupported("WoW64 CSR caller capture exceeds the measured 80-byte bound"));
    }
    if buffer == 0 {
        if inside != 0 {
            c.mem().w8(inside, 0)?;
        }
        if c.p.wow64.as_ref().is_some_and(|state| state.csr.is_some()) {
            publish_wow(c, &server)?;
        }
        return Flow::ret(STATUS_SUCCESS.into());
    }
    let connected = c.p.wow64.as_ref().is_some_and(|state| state.csr.is_some());
    let mut provisional = None;
    if !connected {
        if root == 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        // The native first connection opens the directory before either
        // section or caller-buffer capture. Later calls never visit it.
        let directory = c.mem().wstr(root, 4096)?;
        if directory.len() == 4096 {
            return Err(c.unsupported("WoW64 CSR directory exceeds the capture bound"));
        }
        // CSR appends a separator and object name. A trailing separator
        // introduces an empty component; directory lookup is case-sensitive.
        if directory.last() == Some(&92) {
            return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
        }
        if !directory.iter().copied().eq("\\Windows".encode_utf16()) {
            if matches!(
                c.p.object_namespace.lookup(None, &directory, 0),
                Err(LookupError::Status(
                    STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
                ))
            ) {
                return Flow::ret(STATUS_OBJECT_PATH_NOT_FOUND.into());
            }
            return Err(c.unsupported("WoW64 CSR directory outside the measured selected root"));
        }
        let shared = match SharedObject::anonymous(VIEW_BYTES) {
            Ok(backing) => Arc::new(backing),
            Err(_) => return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into()),
        };
        let Some(readonly) = c.p.objects.open_data_section(server.section(), false, 4) else {
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        let Some(id) = c.p.objects.try_create(Object::Mapping {
            file: None,
            size: VIEW_BYTES,
            protect: prot::READWRITE,
            attributes: 0x0800_0000,
            shared: Some(shared.clone()),
        }) else {
            let _ = c.p.objects.close(readonly.into());
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        let Some(private) = c.p.objects.open_access(id, false, 0x000F_001F) else {
            c.p.objects.release(id);
            let _ = c.p.objects.close(readonly.into());
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        provisional = Some((readonly, private, shared));
    }
    // A capture fault intentionally retains both new Section handles, with
    // no mapped views or PEB publication. Each failed retry retains a new pair.
    let captured = c.mem().bytes(buffer, bytes as usize)?;
    if let Some((readonly, private, backing)) = provisional {
        let result = establish(c.p, &server, backing);
        let _ = c.p.objects.close(readonly.into());
        let _ = c.p.objects.close(private.into());
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => return Flow::ret(error.status().into()),
        };
        let base = connection.base;
        let native_peb =
            c.p.wow64
                .as_ref()
                .expect("selected WoW64 identity")
                .native_peb;
        c.p.wow64.as_mut().expect("selected WoW64 identity").csr = Some(connection);
        c.mem().w64(native_peb + 0x88, base)?;
        c.mem()
            .w64(native_peb + 0x98, base + server.metadata.statics_offset)?;
        c.mem()
            .w64(native_peb + 0x380, server.metadata.server_base)?;
    } else if bytes == 8 {
        // An initialized native CSR client copies a successful BASE reply
        // back even when its bytes are identical. The first connection does
        // not perform this write; a readonly initial buffer therefore works.
        c.mem().wr(buffer, &captured)?;
    }
    // Native64 publication and the real connection survive a Boolean fault.
    // PEB32 publication follows the Boolean, also for a server-size rejection.
    if inside != 0 {
        c.mem().w8(inside, 0)?;
    }
    publish_wow(c, &server)?;
    Flow::ret(
        if bytes == 8 {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_PARAMETER
        }
        .into(),
    )
}

fn publish_wow(c: &mut Ctx, server: &CsrServer) -> Result<(), ApiErr> {
    // A Boolean alias into native64 private fields can change the source
    // after initial validation. Reject that unmeasured state before PEB32 copy.
    native_publication(c, server)?;
    let base =
        c.p.wow64
            .as_ref()
            .and_then(|s| s.csr.as_ref())
            .expect("established WoW64 CSR connection")
            .base;
    c.mem().w32(c.p.peb + 0x4c, base as u32)?;
    c.mem().w32(
        c.p.peb + 0x54,
        (base + server.metadata.statics_offset) as u32,
    )?;
    c.mem().w64(c.p.peb + 0x248, server.metadata.server_base)?;
    Ok(())
}

/// Own both sides of the private port, the 64KiB shared view and selected
/// readonly bytes. O(B + V log V) time for committed bytes B and VM spans V;
/// O(B + V) storage. Resource failures publish no partial connection.
fn establish(
    p: &mut Proc,
    server: &Arc<CsrServer>,
    backing: Arc<SharedObject>,
) -> Result<CsrConnection, VmError> {
    let peer = server.peer(backing.clone(), VIEW_BYTES)?;
    let owner = p.vm.map_shared_view(backing, None, 0, VIEW_BYTES)?;
    let section = server.section();
    let Some(base) =
        p.vm.find_free(section.size, 65536, p.vm.low(), p.vm.high(), true)
    else {
        p.vm.retire_shared_view(&owner)?;
        return Err(VmError::NoMemory);
    };
    if let Err(error) =
        p.vm.map_data_section(section.clone(), base, 0, section.size, prot::READONLY)
    {
        p.vm.retire_shared_view(&owner)?;
        return Err(error);
    }
    let Some(object) = p
        .objects
        .try_create(Object::LpcPort(LpcPort::csr(owner.clone(), peer)))
    else {
        p.vm.release(base)?;
        p.vm.retire_shared_view(&owner)?;
        return Err(VmError::NoMemory);
    };
    let Some(port) = p.objects.open_access(object, false, 0x001F_0001) else {
        p.objects.release(object);
        p.objects.reclaim_lpc_views(&mut p.vm)?;
        p.vm.release(base)?;
        return Err(VmError::NoMemory);
    };
    Ok(CsrConnection {
        section,
        base,
        port,
        object,
    })
}
