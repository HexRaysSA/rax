//! Fixed startup subjects share immutable subtree construction and view guards.
//! A subject is selected by Rust policy, never by a guest-supplied host path.
use super::command_processor::subtree;
use super::*;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(crate) const OLE_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\OLE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotRoot {
    Command(CommandRoot),
    Ole,
}
impl SnapshotRoot {
    pub(super) fn path(self, sid: &[u8]) -> io::Result<Vec<u16>> {
        match self {
            Self::Command(root) => root.path(sid),
            Self::Ole => Ok(OLE_KEY.encode_utf16().collect()),
        }
    }
    pub(super) fn selection(self) -> ViewRoot {
        match self {
            Self::Command(root) => root.selection(),
            Self::Ole => ViewRoot::Ole,
        }
    }
    pub(super) fn is_user(self) -> bool {
        matches!(self, Self::Command(CommandRoot::User))
    }
    fn is_shared(self) -> bool {
        matches!(self, Self::Ole | Self::Command(CommandRoot::System))
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Command(_) => "Command Processor",
            Self::Ole => "OLE",
        }
    }
    fn shared_label(self) -> &'static str {
        match self {
            Self::Command(_) => "System Command Processor",
            Self::Ole => "OLE",
        }
    }
    pub(super) fn check_name(
        self,
        registry: &Registry,
        sid: &[u8],
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        match self {
            Self::Command(root) => registry.check_command_name(root, sid, view, canonical),
            Self::Ole => {
                let expected = self.path(sid)?;
                if canonical.len() != expected.len()
                    || canonical.contains(&0)
                    || !canonical.iter().zip(&expected).all(|(&a, &b)| {
                        registry.upcase[usize::from(a)] == registry.upcase[usize::from(b)]
                    })
                {
                    return Err(invalid("OLE canonical name is outside fixed selection"));
                }
                Ok(())
            }
        }
    }
}

impl Registry {
    pub(crate) fn with_ole_tree(
        self,
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(
            SnapshotRoot::Ole,
            &[],
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }
    pub(super) fn with_snapshot_selection(
        mut self,
        root: SnapshotRoot,
        sid: &[u8],
        view: RegistryView,
        selected_tree: Result<(CommandHeader, Option<Vec<(Vec<u16>, CommandTree)>>), u32>,
    ) -> io::Result<Self> {
        let label = root.label();
        let selected = root.selection();
        if self.upcase.len() != 65_536 || self.views.roots.contains_key(&(selected, view)) {
            return Err(invalid(&format!(
                "invalid or duplicate {label} registry view"
            )));
        }
        if root.is_user() {
            self.check_primary_hive_sid(sid)?;
        }
        let logical = root.path(sid)?;
        if self
            .views
            .paths
            .get(&selected)
            .is_some_and(|path| path.as_ref() != logical)
        {
            return Err(invalid(&format!("{label} views select different subjects")));
        }
        let missing_path =
            matches!(&selected_tree, Err(status) if *status == STATUS_OBJECT_PATH_NOT_FOUND);
        let key = match selected_tree {
            Ok((header, children)) => {
                root.check_name(&self, sid, view, &header.canonical)?;
                let mut builder = subtree::Builder::new(&self, view, root.label())?;
                Some(builder.build(logical.clone(), header, children, 0)?)
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => None,
            Err(_) => {
                return Err(invalid(&format!(
                    "{label} absence is not a native not-found result"
                )));
            }
        };
        // Shared fixed subjects admit one canonical physical subject,
        // unlike the independently redirected Software views. A race cannot
        // leave its two records disagreeing about existence or absence class.
        if root.is_shared() {
            for (&(kind, captured_view), other) in &self.views.roots {
                if kind != selected {
                    continue;
                }
                if key.is_some() != other.is_some()
                    || key.is_none()
                        && missing_path != self.views.missing_paths.contains(&(kind, captured_view))
                {
                    return Err(invalid(&format!(
                        "{} existence changed between view captures",
                        root.shared_label()
                    )));
                }
            }
        }
        if let Some(key) = &key {
            for ((kind, _), other) in &self.views.roots {
                if *kind != selected {
                    continue;
                }
                if let Some(other) = other {
                    if key.fold(&key.path) == other.fold(&other.path)
                        && !subtree::same_physical_contents(key, other)
                    {
                        return Err(invalid(&format!(
                            "{label} shared physical key changed between view captures"
                        )));
                    }
                }
            }
        }
        let views = Arc::make_mut(&mut self.views);
        views.upcase = self.upcase.clone();
        views.paths.insert(selected, logical.into());
        views.roots.insert((selected, view), key);
        if missing_path {
            views.missing_paths.insert((selected, view));
        }
        self.relink_machine_hive()?;
        self.link_primary_hive_policy()?;
        Ok(self)
    }
}

#[cfg(test)]
#[path = "ole_tests.rs"]
mod ole_tests;
