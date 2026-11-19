//! Process-local connection for the installed account-lookup RPC client.
use super::{Connection, Ctx, Flow, Mem, Object, SYNCHRONOUS, probe_write};
use crate::user::windows::hle::ApiResult;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LpcPort;

pub(super) const PORT_NAME: &str = "\\RPC Control\\LSARPC_ENDPOINT";

const LOCAL_SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const PORT_ACCESS: u32 = 0x001f_0001;
pub(super) const PORT_FLAGS: u32 = 0x0209_0000;

pub(super) fn connect(c: &mut Ctx, connection: Connection) -> ApiResult {
    if connection.flags != SYNCHRONOUS
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

    let mut port = c
        .mem()
        .bytes(connection.port_attributes, if width == 8 { 72 } else { 44 })?;
    port[14..16].fill(0); // Padding in SECURITY_QUALITY_OF_SERVICE.
    let mut expected_port = [0; 72];
    for (field, value) in [PORT_FLAGS, 12, 2, 1].into_iter().enumerate() {
        expected_port[field * 4..field * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (field, value) in [4096, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]
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

    // Authenticate only the fixed identity of this virtual server. The supplied
    // SID is a constraint on the endpoint and grants no rights to the caller.
    if connection.sid != 0 && c.mem().bytes(connection.sid, LOCAL_SYSTEM.len())? != LOCAL_SYSTEM {
        return Flow::ret(STATUS_SERVER_SID_MISMATCH.into());
    }
    probe_write(c, connection.out, width)?;
    if connection.receive != 0 {
        if c.mem().u32(connection.receive)? != 0 {
            return Err(c.unsupported(
                "LSARPC connection message attributes are outside the selected profile",
            ));
        }
        probe_write(c, connection.receive, 8)?;
    }

    let Some(id) = c.p.objects.try_create(Object::LpcPort(LpcPort::lsarpc())) else {
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
        if connection.receive != 0 {
            c.mem().w32(connection.receive + 4, 0)?;
        }
        c.write_ptr(connection.out, handle.into())
    };
    if let Err(error) = publish() {
        c.p.objects.close(handle.into());
        return Err(error.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
