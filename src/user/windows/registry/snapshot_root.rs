//! Fixed startup subjects share immutable subtree construction and view guards.
//! A subject is selected by Rust policy, never by a guest-supplied host path.
use super::command_processor::subtree;
use super::*;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

#[path = "snapshot_root/capture.rs"]
pub(super) mod capture;

#[cfg(test)]
#[path = "snapshot_root/side_by_side_tests.rs"]
mod side_by_side_tests;

pub(super) const USER_NT_CURRENT_VERSION_SUFFIX: &str =
    "\\Software\\Microsoft\\Windows NT\\CurrentVersion";

pub(super) const CREATOR_COMPAT_LAYERS: &str = "AppCompatFlags\\Layers";

pub(crate) const OLE_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\OLE";
const SIDE_BY_SIDE_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\SideBySide";
pub(super) const SIDE_BY_SIDE_WOW_KEY: &str =
    "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\SideBySide";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotRoot {
    Command(CommandRoot),
    Ole,
    LocalSettings,
    ShellFolders,
    UserNtCurrentVersion,
    SideBySide,
    Wow64Amd64,
    Wow64X86Jit,
    Processor0,
}
impl SnapshotRoot {
    pub(super) fn path(self, sid: &[u8]) -> io::Result<Vec<u16>> {
        match self {
            Self::Command(root) => root.path(sid),
            Self::Ole => Ok(OLE_KEY.encode_utf16().collect()),
            Self::LocalSettings => local_settings::path(sid),
            Self::ShellFolders => shell_folders::path(sid),
            Self::UserNtCurrentVersion => Ok(user_policy::user_hive_path(sid)?
                .into_iter()
                .chain(USER_NT_CURRENT_VERSION_SUFFIX.encode_utf16())
                .collect()),
            Self::SideBySide => Ok(SIDE_BY_SIDE_KEY.encode_utf16().collect()),
            Self::Wow64Amd64 => Ok(WOW64_AMD64_KEY.encode_utf16().collect()),
            Self::Wow64X86Jit => Ok(wow64_amd64::WOW64_X86_JIT_KEY.encode_utf16().collect()),
            Self::Processor0 => Ok(PROCESSOR0_KEY.encode_utf16().collect()),
        }
    }
    pub(super) fn selection(self) -> ViewRoot {
        match self {
            Self::Command(root) => root.selection(),
            Self::Ole => ViewRoot::Ole,
            Self::LocalSettings => ViewRoot::LocalSettings,
            Self::ShellFolders => ViewRoot::ShellFolders,
            Self::UserNtCurrentVersion => ViewRoot::UserNtCurrentVersion,
            Self::SideBySide => ViewRoot::SideBySide,
            Self::Wow64Amd64 => ViewRoot::Wow64Amd64,
            Self::Wow64X86Jit => ViewRoot::Wow64X86Jit,
            Self::Processor0 => ViewRoot::Processor0,
        }
    }
    pub(super) fn is_user(self) -> bool {
        matches!(
            self,
            Self::Command(CommandRoot::User)
                | Self::LocalSettings
                | Self::ShellFolders
                | Self::UserNtCurrentVersion
        )
    }
    fn is_shared(self) -> bool {
        matches!(
            self,
            Self::Ole
                | Self::Command(CommandRoot::System)
                | Self::LocalSettings
                | Self::ShellFolders
                | Self::UserNtCurrentVersion
                | Self::Processor0
        )
    }
    pub(super) fn requires_complete_metadata(self) -> bool {
        matches!(
            self,
            Self::LocalSettings
                | Self::ShellFolders
                | Self::Wow64Amd64
                | Self::Wow64X86Jit
                | Self::Processor0
        )
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Command(_) => "Command Processor",
            Self::Ole => "OLE",
            Self::LocalSettings => "Local Settings",
            Self::ShellFolders => "Shell Folders",
            Self::UserNtCurrentVersion => "creator Windows NT CurrentVersion",
            Self::SideBySide => "SideBySide",
            Self::Wow64Amd64 => "WOW64 amd64",
            Self::Wow64X86Jit => "WOW64 x86 XtaJit",
            Self::Processor0 => "Processor0",
        }
    }
    fn shared_label(self) -> &'static str {
        if self == Self::Command(CommandRoot::System) {
            "System Command Processor"
        } else {
            self.label()
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
            Self::LocalSettings => registry.check_local_settings_name(sid, canonical),
            Self::ShellFolders => registry.check_shell_folders_name(sid, canonical),
            Self::Wow64Amd64 | Self::Wow64X86Jit => {
                registry.check_wow64_software_name(self, view, canonical)
            }
            Self::UserNtCurrentVersion => {
                let expected = self.path(sid)?;
                let alias = registry
                    .primary_hive
                    .as_ref()
                    .and_then(|hive| hive.root.as_ref())
                    .map(|root| {
                        root.path
                            .iter()
                            .copied()
                            .chain(USER_NT_CURRENT_VERSION_SUFFIX.encode_utf16())
                            .collect::<Vec<_>>()
                    });
                let same = |candidate: &[u16]| {
                    canonical.len() == candidate.len()
                        && canonical.iter().zip(candidate).all(|(&a, &b)| {
                            registry.upcase[usize::from(a)] == registry.upcase[usize::from(b)]
                        })
                };
                if same(&expected) || alias.as_deref().is_some_and(same) {
                    Ok(())
                } else {
                    Err(invalid(
                        "CurrentVersion canonical name is outside creator selection",
                    ))
                }
            }
            Self::Ole | Self::Processor0 | Self::SideBySide => {
                let expected = if self == Self::SideBySide && view == RegistryView::Wow32 {
                    SIDE_BY_SIDE_WOW_KEY.encode_utf16().collect()
                } else {
                    self.path(sid)?
                };
                if canonical.len() != expected.len()
                    || canonical.contains(&0)
                    || !canonical.iter().zip(&expected).all(|(&a, &b)| {
                        registry.upcase[usize::from(a)] == registry.upcase[usize::from(b)]
                    })
                {
                    return Err(invalid(&format!(
                        "{} canonical name is outside fixed selection",
                        self.label()
                    )));
                }
                Ok(())
            }
        }
    }
}

impl Registry {
    pub(crate) fn creator_compat_layer_absent(&self, image: &[u16], view: RegistryView) -> bool {
        let subject = (ViewRoot::UserNtCurrentVersion, view);
        let Some(Some(current_version)) = self.views.roots.get(&subject) else {
            return false;
        };
        let relative: Vec<_> = CREATOR_COMPAT_LAYERS.encode_utf16().collect();
        match current_version.relative(&relative) {
            Lookup::Present(layers) => layers.value(image).is_none(),
            Lookup::Missing | Lookup::MissingPath => true,
            _ => false,
        }
    }

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
        self,
        root: SnapshotRoot,
        sid: &[u8],
        view: RegistryView,
        selected_tree: Result<(CommandHeader, Option<Vec<(Vec<u16>, CommandTree)>>), u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_routes(root, sid, view, selected_tree, None)
    }

    pub(super) fn with_creator_current_version(
        self,
        sid: &[u8],
        view: RegistryView,
        header: Result<CommandHeader, u32>,
        layers: Option<Result<CommandHeader, u32>>,
    ) -> io::Result<Self> {
        self.with_snapshot_routes(
            SnapshotRoot::UserNtCurrentVersion,
            sid,
            view,
            header.map(|header| (header, None)),
            layers,
        )
    }

    fn with_snapshot_routes(
        mut self,
        root: SnapshotRoot,
        sid: &[u8],
        view: RegistryView,
        selected_tree: Result<(CommandHeader, Option<Vec<(Vec<u16>, CommandTree)>>), u32>,
        layers: Option<Result<CommandHeader, u32>>,
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
                if root.requires_complete_metadata() && children.is_none() {
                    return Err(invalid(&format!("{label} requires complete descendants")));
                }
                root.check_name(&self, sid, view, &header.canonical)?;
                let mut builder = subtree::Builder::new(&self, view, root)?;
                let mut key = builder.build(logical.clone(), header, children, 0)?;
                if let Some(layers) = layers {
                    let key = Arc::get_mut(&mut key).expect("new snapshot key");
                    let route = build_creator_layers(&mut builder, key, &logical, layers)?;
                    let suffix: Vec<_> = CREATOR_COMPAT_LAYERS.encode_utf16().collect();
                    key.selected_paths.insert(key.fold(&suffix), route);
                }
                Some(key)
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => {
                if layers.is_some() {
                    return Err(invalid(
                        "creator Layers requires a present CurrentVersion key",
                    ));
                }
                None
            }
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
                if let (Some(key), Some(other)) = (&key, other) {
                    if key.fold(&key.path) != other.fold(&other.path) {
                        return Err(invalid(&format!(
                            "{} physical subject changed between view captures",
                            root.shared_label()
                        )));
                    }
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
                        && (!subtree::same_physical_contents(key, other)
                            || root == SnapshotRoot::UserNtCurrentVersion
                                && !same_creator_layers(key, other))
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

fn build_creator_layers(
    builder: &mut subtree::Builder,
    root: &Key,
    logical: &[u16],
    capture: Result<CommandHeader, u32>,
) -> io::Result<Lookup> {
    let header = match capture {
        Ok(header) => header,
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(Lookup::Missing),
        Err(STATUS_OBJECT_PATH_NOT_FOUND) => return Ok(Lookup::MissingPath),
        Err(_) => {
            return Err(invalid(
                "creator Layers absence is not a native not-found result",
            ));
        }
    };
    let child_path = |parent: &[u16]| {
        parent
            .iter()
            .copied()
            .chain(Some(92))
            .chain(CREATOR_COMPAT_LAYERS.encode_utf16())
            .collect::<Vec<_>>()
    };
    let component: Vec<_> = "AppCompatFlags".encode_utf16().collect();
    let top = root.fold(&component);
    if root.fold(&header.canonical) != root.fold(&child_path(&root.path))
        || !root
            .child_metadata()
            .is_some_and(|entries| entries.iter().any(|entry| root.fold(&entry.name) == top))
    {
        return Err(invalid("creator Layers does not match its captured parent"));
    }
    builder
        .build(child_path(logical), header, None, 1)
        .map(Lookup::Present)
}

fn same_creator_layers(left: &Key, right: &Key) -> bool {
    let suffix: Vec<_> = CREATOR_COMPAT_LAYERS.encode_utf16().collect();
    let route = left.fold(&suffix);
    match (
        left.selected_paths.get(&route),
        right.selected_paths.get(&route),
    ) {
        (None, None)
        | (Some(Lookup::Missing), Some(Lookup::Missing))
        | (Some(Lookup::MissingPath), Some(Lookup::MissingPath)) => true,
        (Some(Lookup::Present(a)), Some(Lookup::Present(b))) => {
            a.fold(&a.path) == b.fold(&b.path) && subtree::same_physical_contents(a, b)
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "ole_tests.rs"]
mod ole_tests;
