//! Capture the two fixed HKLM AppModel subtrees through both Win32 views.
//! Guest paths, access masks and handles never reach these acquisition calls.
use super::super::appmodel::{AppModelRoot, RegistryView};
use super::*;

pub(super) fn capture(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, open)
}

fn capture_with(
    mut registry: Registry,
    mut opener: impl FnMut(AppModelRoot, RegistryView, &[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    for selected in AppModelRoot::ALL {
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let tree = tree::capture_path_budgeted(
                &registry,
                selected.path().encode_utf16().collect(),
                registry.appmodel_budget()?,
                |path| opener(selected, view, path),
            )?;
            // Charge every completed root/view before acquiring the next;
            // all four trees share aggregate value and metadata budgets.
            registry = registry.with_appmodel_view(selected, view, tree)?;
        }
    }
    Ok(registry)
}

fn open(selected: AppModelRoot, view: RegistryView, path: &[u16]) -> io::Result<OwnedKey> {
    let fixed: Vec<_> = selected.path().encode_utf16().collect();
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
