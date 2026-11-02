//! Immutable paired views retained by handles, without host callbacks or cycles.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RegistryView {
    Native64,
    Wow32,
}
impl RegistryView {
    pub(crate) fn flag(self) -> u32 {
        match self {
            Self::Native64 => 0x100,
            Self::Wow32 => 0x200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ViewRoot {
    AppModel(AppModelRoot),
    CommandMachine,
    CommandSystem,
    CommandUser,
    Ole,
    LocalSettings,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RegistryViews {
    pub(super) roots: BTreeMap<(ViewRoot, RegistryView), Option<Arc<Key>>>,
    pub(super) paths: BTreeMap<ViewRoot, Arc<[u16]>>,
    pub(super) missing_paths: BTreeSet<(ViewRoot, RegistryView)>,
    pub(super) upcase: Arc<[u16]>,
}
impl RegistryViews {
    pub(crate) fn lookup(&self, name: &[u16], view: RegistryView) -> Lookup {
        if self.roots.is_empty() || name.first() != Some(&92) || name.get(1) == Some(&92) {
            return Lookup::Unselected;
        }
        let mut normalized = Vec::with_capacity(name.len());
        for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            normalized.push(92);
            normalized.extend_from_slice(component);
        }
        let folded: Vec<_> = normalized
            .iter()
            .map(|&u| self.upcase[usize::from(u)])
            .collect();
        for (&selected, path) in &self.paths {
            let prefix: Vec<_> = path.iter().map(|&u| self.upcase[usize::from(u)]).collect();
            if folded.starts_with(&prefix)
                && (folded.len() == prefix.len() || normalized.get(prefix.len()) == Some(&92))
            {
                return match self.roots.get(&(selected, view)) {
                    Some(Some(root)) => root.relative(&normalized[prefix.len()..]),
                    Some(None) if self.missing_paths.contains(&(selected, view)) => {
                        Lookup::MissingPath
                    }
                    Some(None) => Lookup::Missing,
                    None => Lookup::Unselected,
                };
            }
        }
        // The machine 32-bit leaf also has an explicit physical spelling.
        // Native64 ignores view flags on that spelling; WoW64 handle tags
        // still distinguish the explicit path from logical view selection.
        let physical: Vec<_> =
            "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor"
                .encode_utf16()
                .collect();
        let prefix: Vec<_> = physical
            .iter()
            .map(|&u| self.upcase[usize::from(u)])
            .collect();
        if folded.starts_with(&prefix)
            && (folded.len() == prefix.len() || normalized.get(prefix.len()) == Some(&92))
        {
            return match self
                .roots
                .get(&(ViewRoot::CommandMachine, RegistryView::Wow32))
            {
                Some(Some(root)) => root.relative(&normalized[prefix.len()..]),
                Some(None)
                    if self
                        .missing_paths
                        .contains(&(ViewRoot::CommandMachine, RegistryView::Wow32)) =>
                {
                    Lookup::MissingPath
                }
                Some(None) => Lookup::Missing,
                None => Lookup::Unselected,
            };
        }
        // Captured canonical aliases (notably the creator hive's native alias)
        // preserve the requested view when both records name the same key.
        for preferred in [
            view,
            if view == RegistryView::Native64 {
                RegistryView::Wow32
            } else {
                RegistryView::Native64
            },
        ] {
            for ((kind, captured), root) in &self.roots {
                if *captured != preferred || matches!(kind, ViewRoot::AppModel(_)) {
                    continue;
                }
                let Some(root) = root else {
                    continue;
                };
                let prefix = root.fold(&root.path);
                if folded.starts_with(&prefix)
                    && (folded.len() == prefix.len() || normalized.get(prefix.len()) == Some(&92))
                {
                    return root.relative(&normalized[prefix.len()..]);
                }
            }
        }
        Lookup::Unselected
    }

    pub(crate) fn relative(&self, root: &Key, name: &[u16], view: RegistryView) -> Lookup {
        let absolute: Vec<_> = root
            .logical_path
            .as_deref()
            .unwrap_or(&root.path)
            .iter()
            .copied()
            .chain(Some(92))
            .chain(name.iter().copied())
            .collect();
        self.lookup(&absolute, view)
    }
}
