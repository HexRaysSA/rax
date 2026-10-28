//! Capture exactly the fixed AppModel machine subtree through both Win32 views.
//! Guest paths, access masks and handles never reach these acquisition calls.
use super::super::appmodel::{MACHINE_KEY, RegistryView};
use super::*;

pub(super) fn capture(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, open)
}

fn capture_with(
    mut registry: Registry,
    mut opener: impl FnMut(RegistryView, &[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let selected = tree::capture_path_budgeted(
            &registry,
            MACHINE_KEY.encode_utf16().collect(),
            registry.appmodel_budget()?,
            |path| opener(view, path),
        )?;
        // Charge the first view before acquiring the second; the pair shares
        // the existing global value budget and one key/path metadata budget.
        registry = registry.with_appmodel_view(view, selected)?;
    }
    Ok(registry)
}

fn open(view: RegistryView, path: &[u16]) -> io::Result<OwnedKey> {
    let fixed: Vec<_> = MACHINE_KEY.encode_utf16().collect();
    if path.contains(&0)
        || (path != fixed && (!path.starts_with(&fixed) || path.get(fixed.len()) != Some(&92)))
    {
        return Err(invalid("native AppModel path outside fixed selection"));
    }
    let prefix: Vec<_> = "\\Registry\\Machine\\".encode_utf16().collect();
    let name: Vec<_> = path
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| invalid("fixed AppModel path lacks native HKLM root"))?
        .iter()
        .copied()
        .chain(Some(0))
        .collect();
    let mut handle = null_mut();
    // SAFETY: compile-time fixed path plus bounded native-enumerated children,
    // terminated WCHAR buffer, read-only explicit view, exclusive HKEY output.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            name.as_ptr(),
            0,
            9 | view.flag(),
            &mut handle,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(OwnedKey(handle))
}

#[cfg(test)]
#[path = "appmodel_tests.rs"]
mod tests;
