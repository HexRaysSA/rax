//! Extended connection to the process-local LSA Policy Lookup RPC endpoint.

use super::{Connection, pointer};
use crate::user::windows::dll::native::alpc::lsarpc;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::user::windows::objects::LsarpcInterface;

const PORT_NAME: &str = r"\RPC Control\lsapolicylookup";
const PROFILE_BUILD: u32 = 29708;
mod security;

pub(super) fn connect(c: &mut Ctx, args: Connection) -> ApiResult {
    if c.p.native.as_ref().map(|runtime| runtime.version.build) != Some(PROFILE_BUILD)
        || args.message != 0
        || args.length != 0
        || args.input == 0
    {
        return Err(c.unsupported("NtAlpcConnectPortEx connection options are not selected"));
    }

    let width = c.psize() as usize;
    let server = c.mem().bytes(args.server, 6 * width)?;
    let client = c.mem().bytes(args.client, 6 * width)?;
    let size = (6 * width as u32).to_le_bytes();
    if server[..4] != size || client[..4] != size {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !empty_attributes(&server, width) || !empty_attributes(&client, width) {
        return Err(
            c.unsupported("lsapolicylookup object attributes are outside the selected profile")
        );
    }

    let name = pointer(&server, 2 * width, width);
    if name == 0 || pointer(&client, 2 * width, width) != 0 {
        return Err(c.unsupported(
            "lsapolicylookup server name attributes are outside the selected profile",
        ));
    }
    let header = c.mem().bytes(name, 2 * width)?;
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if length % 2 != 0 || maximum < length {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if length != PORT_NAME.len() * 2
        || !c
            .mem()
            .wunits(pointer(&header, width, width), length / 2)?
            .into_iter()
            .eq(PORT_NAME.encode_utf16())
    {
        return Err(c.unsupported("NtAlpcConnectPortEx port name is not selected"));
    }

    lsarpc::check_port_attributes(c, args.port)?;
    let status = security::check(c, args.security)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    lsarpc::open(c, LsarpcInterface::PolicyLookup, args.out, args.input)
}

fn empty_attributes(attributes: &[u8], width: usize) -> bool {
    pointer(attributes, width, width) == 0
        && attributes[3 * width..3 * width + 4] == [0; 4]
        && pointer(attributes, 4 * width, width) == 0
        && pointer(attributes, 5 * width, width) == 0
}
