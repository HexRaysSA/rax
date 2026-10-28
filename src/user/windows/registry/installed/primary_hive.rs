//! Acquire only the captured primary SID's hive header, then its fixed policy.
//! The owned query-only HKEY closes before immutable selection returns.
use super::super::primary_hive::HiveHeader;
use super::super::user_policy::user_hive_path;
use super::*;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryKey(
        key: Hkey,
        class: u32,
        information: *mut u32,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

pub(crate) fn capture(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    let registry = capture_with(registry, sid, |path| open(sid, path))?;
    super::user_policy::capture(registry, sid)
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
    // A ULONG header followed by at most MAX_NAME_UNITS WCHARs. The backing
    // words guarantee the native ULONG alignment and initialize the entire buffer.
    let mut words = vec![0u32; (4 + MAX_NAME_UNITS * 2).div_ceil(4)];
    let mut returned = 0xCCCC_CCCC;
    let capacity = (words.len() * 4) as u32;
    // SAFETY: live query-only key, KeyNameInformation=3, exclusive aligned
    // initialized buffer of exactly capacity bytes and one ULONG result length.
    let status = unsafe { NtQueryKey(key.0, 3, words.as_mut_ptr(), capacity, &mut returned) };
    if status != 0 {
        return Err(invalid(&format!(
            "primary hive name query failed: 0x{:08X}",
            status as u32
        )));
    }
    let bytes = words[0] as usize;
    if returned > capacity
        || returned < 4
        || bytes % 2 != 0
        || bytes > MAX_NAME_UNITS * 2
        || bytes + 4 > returned as usize
    {
        return Err(invalid(
            "native primary hive name exceeded its returned buffer",
        ));
    }
    Ok(words[1..]
        .iter()
        .flat_map(|&word| [word as u16, (word >> 16) as u16])
        .take(bytes / 2)
        .collect())
}

#[cfg(test)]
#[path = "primary_hive_tests.rs"]
mod tests;
