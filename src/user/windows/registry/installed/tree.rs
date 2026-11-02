//! Selection-only capture of explicitly fixed, complete runtime subtrees.
//! Native parents close before descendant opens; guest names never reach here.
use super::super::tree::{MAX_COMPONENT_UNITS, MAX_TREE_KEYS, TreeBudget, child_path};
use super::super::{
    KeyTree, MAX_TOTAL_BYTES, MAX_VALUES, Registry, TreeRoot, Value, ValueBudget, invalid,
};
use super::{Hkey, Info, OwnedKey, RegEnumKeyExW, RegOpenKeyExW, info, null_mut, values};
use std::io;

pub(super) fn capture(registry: &Registry) -> io::Result<Option<KeyTree>> {
    capture_root(registry, TreeRoot::Ifeo)
}
pub(super) fn capture_root(registry: &Registry, root: TreeRoot) -> io::Result<Option<KeyTree>> {
    capture_root_with(registry, root, |path| open(root, path))
}
pub(super) fn capture_with(
    registry: &Registry,
    opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Option<KeyTree>> {
    capture_root_with(registry, TreeRoot::Ifeo, opener)
}
pub(super) fn capture_root_with(
    registry: &Registry,
    root: TreeRoot,
    opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Option<KeyTree>> {
    capture_path_with(registry, root.path().encode_utf16().collect(), opener)
}
pub(super) fn capture_path_with(
    registry: &Registry,
    path: Vec<u16>,
    opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Option<KeyTree>> {
    capture_path_budgeted(registry, path, TreeBudget::default(), opener)
}
pub(super) fn capture_path_budgeted(
    registry: &Registry,
    path: Vec<u16>,
    mut metadata: TreeBudget,
    mut opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Option<KeyTree>> {
    let key = match opener(&path) {
        Ok(key) => key,
        Err(error) if error.raw_os_error() == Some(2) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut value_budget = registry.value_budget()?;
    let mut reserved = metadata
        .key_count()
        .checked_add(1)
        .filter(|count| *count <= MAX_TREE_KEYS)
        .ok_or_else(|| invalid("installed subtree key budget exhausted"))?;
    node(
        path,
        0,
        &mut value_budget,
        &mut metadata,
        &mut reserved,
        Some(key),
        &mut opener,
    )
    .map(Some)
}
fn open(root: TreeRoot, path: &[u16]) -> io::Result<OwnedKey> {
    let fixed: Vec<_> = root.path().encode_utf16().collect();
    if path != fixed && (!path.starts_with(&fixed) || path.get(fixed.len()) != Some(&92)) {
        return Err(invalid(
            "native registry subtree path outside fixed selection",
        ));
    }
    if path.contains(&0) {
        return Err(invalid("native registry subtree path contains NUL"));
    }
    let prefix: Vec<_> = "\\Registry\\Machine\\".encode_utf16().collect();
    let suffix = path
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| invalid("fixed runtime path lacks native HKLM root"))?;
    let name: Vec<_> = suffix.iter().copied().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: only an enumerated fixed root and validated native-enumerated child
    // components form this terminated path; query/enumerate access only,
    // exclusive HKEY output and no retained pointers.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            name.as_ptr(),
            0,
            9,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(OwnedKey(handle))
}
fn names(key: &OwnedKey, metadata: &Info) -> io::Result<Vec<Vec<u16>>> {
    let mut result = Vec::new();
    let mut scratch = vec![0; metadata.max_child as usize + 1];
    for index in 0..metadata.children {
        let mut length = scratch.len() as u32;
        // SAFETY: owned enumerate-only HKEY, exclusive initialized WCHAR
        // scratch/DWORD length of exact declared capacity, optional outputs
        // NULL; returned length and component grammar checked below.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                scratch.as_mut_ptr(),
                &mut length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if length as usize >= scratch.len() {
            return Err(invalid("runtime child enumeration exceeded its buffer"));
        }
        let name = scratch[..length as usize].to_vec();
        child_path(&[], &name)?;
        result.push(name);
    }
    result.sort();
    Ok(result)
}
fn changed(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(234 | 259))
}
pub(super) fn stable(
    key: &OwnedKey,
    budget: &ValueBudget,
    reserved: usize,
) -> io::Result<(Vec<Value>, Vec<Vec<u16>>)> {
    for _ in 0..3 {
        let before = info(key)?;
        // Reserve prospective children before enumeration, so pending sibling
        // lists across recursive frames cannot multiply the global key limit.
        if before.children as usize > MAX_TREE_KEYS - reserved
            || before.max_child as usize > MAX_COMPONENT_UNITS
            || before.values as usize > MAX_VALUES - budget.count
        {
            return Err(invalid(
                "installed subtree metadata exceeds aggregate bounds",
            ));
        }
        let sample = || -> io::Result<_> {
            Ok((
                values(key, &before, MAX_TOTAL_BYTES - budget.bytes)?,
                names(key, &before)?,
            ))
        };
        let first = match sample() {
            Ok(value) => value,
            Err(error) if changed(&error) => continue,
            Err(error) => return Err(error),
        };
        let second = match sample() {
            Ok(value) => value,
            Err(error) if changed(&error) => continue,
            Err(error) => return Err(error),
        };
        if before == info(key)? && first == second {
            return Ok(first);
        }
    }
    Err(invalid(
        "installed runtime key changed during bounded snapshot",
    ))
}
fn node(
    path: Vec<u16>,
    depth: usize,
    budget: &mut ValueBudget,
    metadata: &mut TreeBudget,
    reserved: &mut usize,
    root: Option<OwnedKey>,
    opener: &mut impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<KeyTree> {
    metadata.charge(&path, depth)?;
    let (values, names) = {
        let key = match root {
            Some(key) => key,
            None => opener(&path)?,
        };
        stable(&key, budget, *reserved)?
    }; // Native HKEY closes before any descendant is opened.
    *reserved += names.len();
    for value in &values {
        budget.charge(value)?;
    }
    let mut children = Vec::new();
    for name in names {
        let next = child_path(&path, &name)?;
        children.push((
            name,
            node(next, depth + 1, budget, metadata, reserved, None, opener)?,
        ));
    }
    Ok(KeyTree { values, children })
}
