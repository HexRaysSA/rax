//! Acquire fixed subjects before exposing immutable logical registry views.
use super::*;

pub(in crate::user::windows::registry) trait Source {
    type Key;

    fn open(&mut self, view: RegistryView) -> io::Result<Self::Key>;
    fn identity(&mut self, key: &Self::Key) -> io::Result<(Vec<u16>, KeyAccess)>;
    fn tree(
        &mut self,
        registry: &Registry,
        view: RegistryView,
        key: Self::Key,
    ) -> io::Result<CommandTree>;
}

pub(in crate::user::windows::registry) fn capture(
    mut registry: Registry,
    root: SnapshotRoot,
    sid: &[u8],
    source: &mut impl Source,
) -> io::Result<Registry> {
    if registry.upcase.len() != 65_536
        || [RegistryView::Native64, RegistryView::Wow32]
            .iter()
            .any(|&view| registry.views.roots.contains_key(&(root.selection(), view)))
    {
        return Err(invalid(
            "invalid or duplicate Command Processor acquisition",
        ));
    }
    root.path(sid)?;
    if root.is_user() {
        registry.check_primary_hive_sid(sid)?;
    }
    if root.is_shared() {
        return shared(registry, root, sid, source);
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let selected = match open(source, view)? {
            Ok(key) => {
                let tree = source.tree(&registry, view, key)?;
                Ok((tree.header, Some(tree.children)))
            }
            Err(status) => Err(status),
        };
        registry = registry.with_snapshot_selection(root, sid, view, selected)?;
    }
    Ok(registry)
}

fn shared(
    mut registry: Registry,
    root: SnapshotRoot,
    sid: &[u8],
    source: &mut impl Source,
) -> io::Result<Registry> {
    let native = open(source, RegistryView::Native64)?;
    let wow = open(source, RegistryView::Wow32)?;
    let tree = match (native, wow) {
        (Ok(native), Ok(wow)) => {
            let first = source.identity(&native)?;
            let second = source.identity(&wow)?;
            root.check_name(&registry, sid, RegistryView::Native64, &first.0)?;
            root.check_name(&registry, sid, RegistryView::Wow32, &second.0)?;
            if !same_identity(&registry, &first, &second) {
                return Err(invalid(&format!(
                    "{} physical identity/grant changed between view opens",
                    root.label()
                )));
            }
            // Shared subjects have one physical tree. Close the other view's
            // root before descendant acquisition; never traverse that tree a
            // second time merely to assign the other logical view's tags.
            drop(wow);
            let tree = source.tree(&registry, RegistryView::Native64, native)?;
            let captured = (tree.header.canonical.clone(), tree.header.access);
            if !same_identity(&registry, &first, &captured) {
                return Err(invalid(&format!(
                    "{} physical identity/grant changed during capture",
                    root.label()
                )));
            }
            tree
        }
        (Err(first), Err(second)) => {
            registry =
                registry.with_snapshot_selection(root, sid, RegistryView::Native64, Err(first))?;
            return registry.with_snapshot_selection(root, sid, RegistryView::Wow32, Err(second));
        }
        _ => {
            return Err(invalid(&format!(
                "{} existence changed between view opens",
                root.label()
            )));
        }
    };
    // The ordinary builders validate and charge both logical projections,
    // including every descendant, value, grant and child FILETIME.
    registry = registry.with_snapshot_selection(
        root,
        sid,
        RegistryView::Native64,
        Ok((tree.header.clone(), Some(tree.children.clone()))),
    )?;
    registry.with_snapshot_selection(
        root,
        sid,
        RegistryView::Wow32,
        Ok((tree.header, Some(tree.children))),
    )
}

fn same_identity(
    registry: &Registry,
    left: &(Vec<u16>, KeyAccess),
    right: &(Vec<u16>, KeyAccess),
) -> bool {
    left.1 == right.1
        && left.0.len() == right.0.len()
        && left
            .0
            .iter()
            .zip(&right.0)
            .all(|(&a, &b)| registry.upcase[usize::from(a)] == registry.upcase[usize::from(b)])
}

fn open<S: Source>(source: &mut S, view: RegistryView) -> io::Result<Result<S::Key, u32>> {
    match source.open(view) {
        Ok(key) => Ok(Ok(key)),
        Err(error) if error.raw_os_error() == Some(2) => Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND)),
        Err(error) if error.raw_os_error() == Some(3) => Ok(Err(STATUS_OBJECT_PATH_NOT_FOUND)),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "capture/tests.rs"]
mod tests;
