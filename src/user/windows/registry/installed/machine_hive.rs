//! Selection-time acquisition of the one fixed MACHINE header and grant ceiling.
use super::super::{MACHINE_HIVE_KEY, MachineAccess, MachineHeader};
use super::*;

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: Hkey,
    name: *mut Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    48
} else {
    24
}] = [(); std::mem::size_of::<Attributes>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKeyEx(out: *mut Hkey, access: u32, attributes: *mut Attributes, options: u32) -> i32;
    fn NtQueryObject(
        handle: Hkey,
        class: u32,
        buffer: *mut u32,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn open(access: u32) -> Result<OwnedKey, u32> {
    if !matches!(access, 0x0200_0000 | 0x0100_0000) {
        return Err(super::super::super::nt::status::STATUS_INVALID_PARAMETER);
    }
    let mut path: Vec<_> = MACHINE_HIVE_KEY.encode_utf16().collect();
    let mut name = Unicode {
        length: (path.len() * 2) as u16,
        maximum: (path.len() * 2) as u16,
        buffer: path.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &mut name,
        flags: 0x40,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut handle = null_mut();
    // SAFETY: only the fixed MACHINE path and compile-time access probes reach
    // this API. The counted UTF-16 buffer and attributes live for the call.
    // A successful real HKEY is owned and closes through RegCloseKey.
    let status = unsafe { NtOpenKeyEx(&mut handle, access, &mut attributes, 0) };
    if status == 0 && !handle.is_null() {
        Ok(OwnedKey(handle))
    } else {
        if !handle.is_null() {
            drop(OwnedKey(handle));
        }
        Err(status as u32)
    }
}

fn basic(key: &OwnedKey) -> io::Result<u32> {
    let mut words = [0u32; 14];
    let mut returned = 0;
    // SAFETY: live owned key, initialized 56-byte OBJECT_BASIC_INFORMATION
    // storage and exclusive ULONG result; only GrantedAccess is retained.
    let status = unsafe { NtQueryObject(key.0, 0, words.as_mut_ptr(), 56, &mut returned) };
    if status != 0 || returned != 56 {
        return Err(invalid(&format!(
            "MACHINE key grant query failed: 0x{:08X}, length {returned}",
            status as u32
        )));
    }
    Ok(words[1])
}

pub(super) fn capture(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, open)
}
fn capture_with(
    registry: Registry,
    mut opener: impl FnMut(u32) -> Result<OwnedKey, u32>,
) -> io::Result<Registry> {
    if registry.upcase.len() != 65_536 || registry.machine_hive.is_some() {
        return Err(invalid("invalid or duplicate MACHINE hive acquisition"));
    }
    let key = opener(0x0200_0000).map_err(|status| {
        invalid(&format!(
            "MACHINE key maximum-access open failed: 0x{status:08X}"
        ))
    })?;
    let maximum_access = basic(&key)?;
    let system_security_status = match opener(0x0100_0000) {
        Ok(security) => {
            if basic(&security)? & 0x0100_0000 == 0 {
                return Err(invalid("MACHINE security grant lacks requested access"));
            }
            0
        }
        Err(0) => return Err(invalid("MACHINE security open returned no handle")),
        Err(status) => status,
    };
    let budget = registry.value_budget()?;
    let (children, values) = capture_stable_values(
        &key,
        MAX_VALUES - budget.count,
        super::super::MAX_TOTAL_BYTES - budget.bytes,
    )?;
    let canonical = canonical_hive_name(&key, "MACHINE")?;
    if basic(&key)? != maximum_access {
        return Err(invalid("MACHINE key grant changed during capture"));
    }
    registry.with_machine_hive(MachineHeader {
        canonical,
        children,
        values,
        access: MachineAccess {
            maximum_access,
            system_security_status,
        },
    })
}

#[cfg(test)]
#[path = "machine_hive_tests.rs"]
mod tests;
