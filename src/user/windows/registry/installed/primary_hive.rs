//! Acquire only the captured primary SID's hive header, then its fixed policy.
//! The owned query-only HKEY closes before immutable selection returns.
use super::super::primary_hive::HiveHeader;
use super::super::user_policy::user_hive_path;
use super::*;

pub(crate) fn capture(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    let registry = capture_header(registry, sid)?;
    super::command_processor::capture_user(super::user_policy::capture(registry, sid)?, sid)
}

pub(super) fn capture_header(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_with(registry, sid, |path| open(sid, path))
}

fn capture_with(
    registry: Registry,
    sid: &[u8],
    opener: impl FnOnce(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    if registry.upcase.len() != 65_536 || registry.primary_hive.is_some() {
        return Err(invalid("invalid or duplicate primary hive acquisition"));
    }
    let fixed = user_hive_path(sid)?;
    registry.check_primary_hive_sid(sid)?;
    let key = match opener(&fixed) {
        Ok(key) => key,
        Err(error) if error.raw_os_error() == Some(2) => {
            return registry.with_primary_hive(sid, None);
        }
        Err(error) => return Err(error),
    };
    let budget = registry.value_budget()?;
    let (children, values) = capture_stable_values(
        &key,
        MAX_VALUES - budget.count,
        super::super::MAX_TOTAL_BYTES - budget.bytes,
    )?;
    let canonical = canonical_name(&key)?;
    registry.with_primary_hive(
        sid,
        Some(HiveHeader {
            canonical,
            children,
            values,
        }),
    )
}

fn open(sid: &[u8], path: &[u16]) -> io::Result<OwnedKey> {
    let fixed = user_hive_path(sid)?;
    if path != fixed {
        return Err(invalid(
            "native hive path differs from captured primary SID",
        ));
    }
    let prefix: Vec<_> = "\\Registry\\User\\".encode_utf16().collect();
    let relative = path
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| invalid("primary hive path lacks native HKU root"))?;
    let name: Vec<_> = relative.iter().copied().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: one validated creator SID forms the terminated name; only
    // KEY_QUERY_VALUE is requested. Output is exclusive and closes via OwnedKey.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_645isize) as Hkey,
            name.as_ptr(),
            0,
            1,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(OwnedKey(handle))
}

fn canonical_name(key: &OwnedKey) -> io::Result<Vec<u16>> {
    canonical_hive_name(key, "primary")
}

#[cfg(test)]
#[path = "primary_hive_tests.rs"]
mod tests;
