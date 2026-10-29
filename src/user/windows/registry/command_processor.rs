//! Fixed machine and creator-SID CMD headers and complete bounded subtrees.
use super::super::nt::status::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND};
use super::*;

#[path = "command_processor_tree.rs"]
pub(super) mod subtree;
pub(crate) use subtree::CommandTree;

pub(crate) const COMMAND_PROCESSOR_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Command Processor";
pub(crate) const SYSTEM_COMMAND_PROCESSOR_KEY: &str =
    "\\Registry\\Machine\\System\\Software\\Microsoft\\Command Processor";
pub(super) const COMMAND_SUFFIX: &str = "\\Software\\Microsoft\\Command Processor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandRoot {
    Machine,
    System,
    User,
}
impl CommandRoot {
    pub(super) fn selection(self) -> ViewRoot {
        match self {
            Self::Machine => ViewRoot::CommandMachine,
            Self::System => ViewRoot::CommandSystem,
            Self::User => ViewRoot::CommandUser,
        }
    }
    pub(crate) fn path(self, sid: &[u8]) -> io::Result<Vec<u16>> {
        match self {
            Self::Machine => Ok(COMMAND_PROCESSOR_KEY.encode_utf16().collect()),
            Self::System => Ok(SYSTEM_COMMAND_PROCESSOR_KEY.encode_utf16().collect()),
            Self::User => Ok(user_policy::user_hive_path(sid)?
                .into_iter()
                .chain(COMMAND_SUFFIX.encode_utf16())
                .collect()),
        }
    }
}

pub(crate) struct CommandHeader {
    pub(crate) enumeration: Option<Vec<BasicChild>>,
    pub(crate) canonical: Vec<u16>,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
    pub(crate) access: KeyAccess,
}

impl Registry {
    pub(crate) fn with_command_view(
        self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        header: Result<CommandHeader, u32>,
    ) -> io::Result<Self> {
        self.with_command_selection(root, sid, view, header.map(|header| (header, None)))
    }

    pub(crate) fn with_command_tree(
        self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_command_selection(
            root,
            sid,
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }

    fn with_command_selection(
        self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        selected_tree: Result<(CommandHeader, Option<Vec<(Vec<u16>, CommandTree)>>), u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(SnapshotRoot::Command(root), sid, view, selected_tree)
    }

    pub(super) fn check_command_name(
        &self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("Command Processor canonical name exceeds bounds"));
        }
        let mut bases = vec![root.path(sid)?];
        if root == CommandRoot::User {
            if let Some(hive) = &self.primary_hive {
                if let Some(key) = &hive.root {
                    bases.push(
                        key.path
                            .iter()
                            .copied()
                            .chain(COMMAND_SUFFIX.encode_utf16())
                            .collect(),
                    );
                }
            }
        }
        if view == RegistryView::Wow32 && root != CommandRoot::System {
            let redirected: Vec<Vec<u16>> = bases
                .iter()
                .map(|base| {
                    let suffix: Vec<_> = COMMAND_SUFFIX.encode_utf16().collect();
                    base[..base.len() - suffix.len()]
                        .iter()
                        .copied()
                        .chain(
                            "\\Software\\WOW6432Node\\Microsoft\\Command Processor".encode_utf16(),
                        )
                        .collect()
                })
                .collect();
            bases.extend(redirected);
        }
        let fold = |path: &[u16]| {
            path.iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect::<Vec<_>>()
        };
        if !bases.iter().any(|base| fold(base) == fold(canonical)) {
            return Err(invalid(
                "Command Processor canonical name is outside fixed selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "command_processor_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "command_processor_system_tests.rs"]
mod system_tests;

impl Key {
    pub(crate) fn command_access(&self) -> Option<KeyAccess> {
        self.command_access
    }
    pub(crate) fn command_physical_name(&self, name: &[u16]) -> bool {
        if self.command_access.is_none() {
            return false;
        }
        let mut normalized = Vec::with_capacity(name.len());
        for part in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            normalized.push(92);
            normalized.extend_from_slice(part);
        }
        let physical_suffix: Vec<_> = "\\Software\\WOW6432Node\\Microsoft\\Command Processor"
            .encode_utf16()
            .collect();
        let Some(logical) = self.logical_path.as_deref() else {
            return false;
        };
        let command_suffix: Vec<_> = COMMAND_SUFFIX.encode_utf16().collect();
        let folded_suffix = self.fold(&command_suffix);
        let Some(root) = self
            .fold(logical)
            .windows(command_suffix.len())
            .position(|part| part == folded_suffix)
        else {
            return false;
        };
        let descendants = logical.len() - root - command_suffix.len();
        let Some(root_end) = self.path.len().checked_sub(descendants) else {
            return false;
        };
        let physical_root = &self.path[..root_end];
        if !self
            .fold(physical_root)
            .ends_with(&self.fold(&physical_suffix))
        {
            return false;
        }
        let normalized = self.fold(&normalized);
        [physical_root, physical_suffix.as_slice()]
            .into_iter()
            .any(|prefix| {
                normalized.starts_with(&self.fold(prefix))
                    && (normalized.len() == prefix.len()
                        || normalized.get(prefix.len()) == Some(&92))
            })
    }
}
