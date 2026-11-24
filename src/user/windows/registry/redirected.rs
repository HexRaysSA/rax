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
    OleAutomation,
    AutoEnrollment,
    LocalSettings,
    ShellFolders,
    CurrentVersion,
    WindowsNt,
    UserNtCurrentVersion,
    UserRegistryPolicy,
    ThemeManager,
    ThemePersonalize,
    SideBySide,
    Wow64Amd64,
    Wow64X86Jit,
    Processor0,
    ProcessConfig(ProcessConfigKey),
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
                let suffix = &normalized[prefix.len()..];
                // Fixed process configuration headers own exact absolute
                // names. A child can be an independently captured subject.
                if matches!(selected, ViewRoot::ProcessConfig(_)) && !suffix.is_empty() {
                    continue;
                }
                return self.lookup_selected(selected, view, suffix);
            }
        }
        // These explicit physical spellings always select the x86 key.
        for (selected, physical) in [
            (
                ViewRoot::CommandMachine,
                "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor",
            ),
            (ViewRoot::SideBySide, snapshot_root::SIDE_BY_SIDE_WOW_KEY),
            (
                ViewRoot::OleAutomation,
                snapshot_root::OLE_AUTOMATION_WOW_KEY,
            ),
            (
                ViewRoot::AutoEnrollment,
                snapshot_root::AUTO_ENROLLMENT_WOW_KEY,
            ),
        ] {
            let prefix: Vec<_> = physical
                .encode_utf16()
                .map(|u| self.upcase[usize::from(u)])
                .collect();
            if folded.starts_with(&prefix)
                && (folded.len() == prefix.len() || normalized.get(prefix.len()) == Some(&92))
            {
                return self.lookup_selected(
                    selected,
                    RegistryView::Wow32,
                    &normalized[prefix.len()..],
                );
            }
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
                    let suffix = &normalized[prefix.len()..];
                    if matches!(kind, ViewRoot::ProcessConfig(_)) && !suffix.is_empty() {
                        continue;
                    }
                    return root.relative(suffix);
                }
            }
        }
        Lookup::Unselected
    }

    fn lookup_selected(&self, root: ViewRoot, view: RegistryView, suffix: &[u16]) -> Lookup {
        if !suffix.is_empty()
            && matches!(
                root,
                ViewRoot::UserRegistryPolicy | ViewRoot::ThemeManager | ViewRoot::ThemePersonalize
            )
        {
            return Lookup::Unselected;
        }
        let selection = (root, view);
        match self.roots.get(&selection) {
            Some(Some(key)) => key.relative(suffix),
            Some(None) if self.missing_paths.contains(&selection) => Lookup::MissingPath,
            Some(None) => Lookup::Missing,
            None => Lookup::Unselected,
        }
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
