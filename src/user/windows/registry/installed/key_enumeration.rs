//! Selection-time values and ordered child names/FILETIMEs from a fixed key.
//! Children are metadata only here: no arbitrary descendant is opened.
use super::*;
use crate::user::windows::registry::tree::{MAX_COMPONENT_UNITS, MAX_TREE_KEYS, child_path};
use crate::user::windows::registry::{BasicChild, ValueBudget};

fn entries(key: &OwnedKey, before: &Info) -> io::Result<Vec<BasicChild>> {
    let mut scratch = vec![0; before.max_child as usize + 1];
    let mut result = Vec::new();
    for index in 0..before.children {
        let mut units = scratch.len() as u32;
        let mut time = [0u32; 2];
        // SAFETY: owned key, initialized bounded WCHAR/FILETIME outputs and
        // exclusive DWORD length; optional outputs are NULL. Validate length
        // and component grammar before retaining the native returned name.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                scratch.as_mut_ptr(),
                &mut units,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut time,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if units as usize >= scratch.len() {
            return Err(invalid("native enumeration exceeded child-name capacity"));
        }
        let name = scratch[..units as usize].to_vec();
        child_path(&[], &name)?;
        result.push(BasicChild {
            name,
            last_write: u64::from(time[0]) | u64::from(time[1]) << 32,
        });
    }
    // Preserve native index order. The lookup tree folds names separately.
    Ok(result)
}

pub(super) fn stable(
    key: &OwnedKey,
    budget: &ValueBudget,
    reserved: usize,
) -> io::Result<(Vec<Value>, Vec<BasicChild>)> {
    for _ in 0..3 {
        let before = info(key)?;
        if before.children as usize > MAX_TREE_KEYS.saturating_sub(reserved)
            || before.max_child as usize > MAX_COMPONENT_UNITS
            || before.values as usize > MAX_VALUES.saturating_sub(budget.count)
        {
            return Err(invalid(
                "native child/value metadata exceeds aggregate bounds",
            ));
        }
        let sample = || -> io::Result<_> {
            let values = values(key, &before, super::super::MAX_TOTAL_BYTES - budget.bytes)?;
            let children = entries(key, &before)?;
            // Check aggregate metadata before retaining a recursive frame.
            let mut count = budget.enumeration_count;
            let mut bytes = budget.enumeration_bytes;
            count += children.len();
            for child in &children {
                bytes += child.name.len() * 2 + 8;
            }
            if count > 2 * MAX_TREE_KEYS || bytes > 1 << 20 {
                return Err(invalid("native enumeration aggregate exceeds bounds"));
            }
            Ok((values, children))
        };
        let first = match sample() {
            Ok(value) => value,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        let second = match sample() {
            Ok(value) => value,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        if before == info(key)? && first == second {
            return Ok(first);
        }
    }
    Err(invalid(
        "native child metadata changed during bounded snapshot",
    ))
}
