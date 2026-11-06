//! The creator's fixed shared Explorer Shell Folders subtree.
use super::*;

pub(super) const SUFFIX: &str =
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";

pub(super) fn path(sid: &[u8]) -> io::Result<Vec<u16>> {
    Ok(user_policy::user_hive_path(sid)?
        .into_iter()
        .chain(SUFFIX.encode_utf16())
        .collect())
}

impl Registry {
    pub(crate) fn with_shell_folders_tree(
        self,
        sid: &[u8],
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(
            SnapshotRoot::ShellFolders,
            sid,
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }

    pub(super) fn check_shell_folders_name(&self, sid: &[u8], canonical: &[u16]) -> io::Result<()> {
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("Shell Folders canonical name exceeds bounds"));
        }
        let mut allowed = vec![path(sid)?];
        if let Some(root) = self
            .primary_hive
            .as_ref()
            .and_then(|hive| hive.root.as_ref())
        {
            allowed.push(
                root.path
                    .iter()
                    .copied()
                    .chain(SUFFIX.encode_utf16())
                    .collect(),
            );
        }
        let fold = |units: &[u16]| {
            units
                .iter()
                .map(|&unit| self.upcase[usize::from(unit)])
                .collect::<Vec<_>>()
        };
        let canonical = fold(canonical);
        if !allowed.iter().any(|path| fold(path) == canonical) {
            return Err(invalid(
                "Shell Folders canonical name is outside creator selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "shell_folders_tests.rs"]
mod tests;
