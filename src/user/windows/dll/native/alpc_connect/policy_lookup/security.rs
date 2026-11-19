//! Apply the caller's server requirements to the virtual endpoint's identity.

use crate::user::windows::dll::native::alpc::lsarpc::LOCAL_SYSTEM;
use crate::user::windows::hle::{ApiErr, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_SERVER_SID_MISMATCH, STATUS_SUCCESS};
use crate::user::windows::security::{self, Descriptor, Group, Mapping, Subject};
use std::sync::LazyLock;

const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const GROUP_ENABLED: u32 = 0x4;
const PORT_CONNECT: u32 = 0x1;
const HEADER_BYTES: usize = 20;
const DACL_PRESENT: u16 = 0x0004;
const SELF_RELATIVE: u16 = 0x8000;
const DACL_INHERITANCE_FLAGS: u16 = 0x1500;

// This subject exists only for the server-identity check. It is never
// published as a token or used to authorize an operation on the host.
static SERVER: LazyLock<Subject> = LazyLock::new(|| Subject {
    statistics: None,
    user_attributes: 0,
    token_pointer_records: Default::default(),
    empty_claims: Default::default(),
    user: LOCAL_SYSTEM.to_vec(),
    groups: [EVERYONE.as_slice(), ADMINISTRATORS.as_slice()]
        .into_iter()
        .map(|sid| Group {
            sid: sid.to_vec(),
            attributes: GROUP_ENABLED,
        })
        .collect(),
    restricted: Vec::new(),
    app_container: false,
    privileges: Vec::new(),
    attributes: None,
});

pub(super) fn check(c: &Ctx, address: u64) -> Result<u32, ApiErr> {
    if address == 0 {
        return Ok(STATUS_SUCCESS);
    }
    let mut header = [0; HEADER_BYTES];
    c.mem().rd(address, &mut header)?;
    let control = u16::from_le_bytes([header[2], header[3]]);
    let [owner, group, sacl, dacl] = [4, 8, 12, 16].map(|offset| {
        u32::from_le_bytes(
            header[offset..offset + 4]
                .try_into()
                .expect("descriptor offset"),
        )
    });
    if header[..2] != [1, 0]
        || control & SELF_RELATIVE == 0
        || control & !(SELF_RELATIVE | DACL_PRESENT | DACL_INHERITANCE_FLAGS) != 0
        || sacl != 0
    {
        return Err(c.unsupported(
            "lsapolicylookup server security descriptor is outside the selected profile",
        ));
    }

    let owner = read_sid(c, component(c, address, owner)?)?;
    read_sid(c, component(c, address, group)?)?;
    let dacl = if control & DACL_PRESENT != 0 && dacl != 0 {
        let acl = component(c, address, dacl)?;
        let header = c.mem().bytes(acl, 8)?;
        let bytes = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if bytes < 8 {
            return Err(c.unsupported("lsapolicylookup server security ACL has an invalid extent"));
        }
        Some(c.mem().bytes(acl, bytes)?)
    } else {
        None
    };
    let result = security::evaluate(
        &SERVER,
        Descriptor {
            owner: &owner,
            dacl: dacl.as_deref(),
        },
        // Only the PORT_CONNECT projection is relevant. The native object
        // grants that bit through generic read, write, or all.
        Mapping([PORT_CONNECT, PORT_CONNECT, 0, PORT_CONNECT]),
        PORT_CONNECT,
    )
    .map_err(|message| c.unsupported(format!("lsapolicylookup server security: {message}")))?;
    Ok(if result.status == STATUS_SUCCESS {
        STATUS_SUCCESS
    } else {
        STATUS_SERVER_SID_MISMATCH
    })
}

fn component(c: &Ctx, base: u64, offset: u32) -> Result<u64, ApiErr> {
    if offset < HEADER_BYTES as u32 || offset % 4 != 0 {
        return Err(
            c.unsupported("lsapolicylookup server security descriptor has an invalid offset")
        );
    }
    base.checked_add(u64::from(offset))
        .ok_or_else(|| c.unsupported("lsapolicylookup server security descriptor offset wraps"))
}

fn read_sid(c: &Ctx, address: u64) -> Result<Vec<u8>, ApiErr> {
    let prefix = c.mem().bytes(address, 8)?;
    if prefix[0] != 1 || prefix[1] > 15 {
        return Err(c.unsupported("lsapolicylookup server security descriptor has an invalid SID"));
    }
    let bytes = 8 + 4 * usize::from(prefix[1]);
    Ok(c.mem().bytes(address, bytes)?)
}
