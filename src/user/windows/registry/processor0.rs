//! One fixed, shared hardware subject queried by installed startup libraries.
use super::*;

pub(crate) const PROCESSOR0_KEY: &str =
    "\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

impl Registry {
    pub(crate) fn with_processor0_tree(
        self,
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(
            SnapshotRoot::Processor0,
            &[],
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }
}

#[cfg(test)]
#[path = "processor0_tests.rs"]
mod tests;
