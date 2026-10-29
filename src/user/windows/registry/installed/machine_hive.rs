//! Selection-time acquisition of the one fixed MACHINE header and grant ceiling.
use super::super::{KeyAccess, MACHINE_HIVE_KEY, MachineHeader};
use super::*;

fn open(access: u32) -> Result<OwnedKey, u32> {
    super::native_key::open(&MACHINE_HIVE_KEY.encode_utf16().collect::<Vec<_>>(), access)
}
fn basic(key: &OwnedKey) -> io::Result<u32> {
    super::native_key::basic(key, "MACHINE")
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
        access: KeyAccess {
            maximum_access,
            system_security_status,
        },
    })
}

#[cfg(test)]
#[path = "machine_hive_tests.rs"]
mod tests;
