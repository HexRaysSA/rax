//! Process-local connection for the installed account-lookup RPC client.
use super::{Connection, Ctx, Flow, Mem, Object, SYNCHRONOUS, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::ApiResult;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{LpcPort, LsarpcInterface};

pub(super) const PORT_NAME: &str = "\\RPC Control\\LSARPC_ENDPOINT";

pub(in crate::user::windows::dll::native) const LOCAL_SYSTEM: [u8; 12] =
    [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const PORT_ACCESS: u32 = 0x001f_0001;
mod bind;
mod exchange;
mod policy;
mod policy_lookup;
mod translate;

pub(super) use exchange::exchange;
pub(super) const MAX_MESSAGE: usize = 4096;
pub(super) const PORT_FLAGS: u32 = 0x0209_0000;
pub(super) const WOW64_SYNCHRONOUS: u32 = SYNCHRONOUS | 0x4000_0000;

pub(super) fn connect(c: &mut Ctx, connection: Connection) -> ApiResult {
    // The installed x86 RPC client supplies this flag at the WoW64 entry.
    let wow64_synchronous = c.arch() == WinArch::X86 && connection.flags == WOW64_SYNCHRONOUS;
    if (connection.flags != SYNCHRONOUS && !wow64_synchronous)
        || connection.message != 0
        || connection.length != 0
        || connection.send != 0
        || connection.wait != 0
    {
        return Err(c.unsupported("LSARPC connection options are outside the selected profile"));
    }

    let width = c.psize() as usize;
    if connection.attributes != 0 {
        let mut object = c.mem().bytes(connection.attributes, 6 * width)?;
        let size = u32::from_le_bytes(object[..4].try_into().expect("object length"));
        if size as usize != object.len() {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        if width == 8 {
            object[4..8].fill(0);
            object[28..32].fill(0);
        }
        if object[4..].iter().any(|byte| *byte != 0) {
            return Err(c.unsupported(
                "LSARPC connection object attributes are outside the selected profile",
            ));
        }
    }

    check_port_attributes(c, connection.port_attributes)?;

    // Authenticate only the fixed identity of this virtual server. The supplied
    // SID is a constraint on the endpoint and grants no rights to the caller.
    if connection.sid != 0 && c.mem().bytes(connection.sid, LOCAL_SYSTEM.len())? != LOCAL_SYSTEM {
        return Flow::ret(STATUS_SERVER_SID_MISMATCH.into());
    }
    // Under this flag the kernel checks the optional attribute header after
    // validating the server SID and before publishing either output.
    if wow64_synchronous && !connection.receive.is_multiple_of(8) {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    open(
        c,
        LsarpcInterface::Policy,
        connection.out,
        connection.receive,
    )
}

pub(in crate::user::windows::dll::native) fn check_port_attributes(
    c: &Ctx,
    port_attributes: u64,
) -> Result<(), crate::user::windows::hle::ApiErr> {
    let width = c.psize() as usize;
    let mut port = c
        .mem()
        .bytes(port_attributes, if width == 8 { 72 } else { 44 })?;
    port[14..16].fill(0); // Padding in SECURITY_QUALITY_OF_SERVICE.
    let mut expected_port = [0; 72];
    for (field, value) in [PORT_FLAGS, 12, 2, 1].into_iter().enumerate() {
        expected_port[field * 4..field * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (field, value) in [
        MAX_MESSAGE as u32,
        0,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 16 + field * width;
        expected_port[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let offset = 16 + 6 * width;
    expected_port[offset..offset + 4].copy_from_slice(&4093u32.to_le_bytes());
    if port != expected_port[..port.len()] {
        return Err(
            c.unsupported("LSARPC connection port attributes are outside the selected profile")
        );
    }

    Ok(())
}

pub(in crate::user::windows::dll::native) fn open(
    c: &mut Ctx,
    interface: LsarpcInterface,
    out: u64,
    receive: u64,
) -> ApiResult {
    let width = c.psize() as usize;
    probe_write(c, out, width)?;
    if receive != 0 {
        if c.mem().u32(receive)? != 0 {
            return Err(c.unsupported(
                "LSARPC connection message attributes are outside the selected profile",
            ));
        }
        probe_write(c, receive, 8)?;
    }

    let Some(id) =
        c.p.objects
            .try_create(Object::LpcPort(LpcPort::lsarpc(interface)))
    else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, false, PORT_ACCESS) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(Object::LpcPort(endpoint)) = c.p.objects.obj_mut(id) else {
        unreachable!("new LSARPC handle owns the port created above");
    };
    endpoint.set_lsarpc_context(handle);

    let publish = || -> Result<(), crate::user::windows::memory::MemFault> {
        if receive != 0 {
            c.mem().w32(receive + 4, 0)?;
        }
        c.write_ptr(out, handle.into())
    };
    if let Err(error) = publish() {
        c.p.objects.close(handle.into());
        return Err(error.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
