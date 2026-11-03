//! One complete fixed NLS selection, without overlapping partial snapshots.
use super::*;

pub(crate) const NLS_ROOT_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls";

impl Registry {
    pub(crate) fn with_nls_information_tree(self, tree: InformationTree) -> io::Result<Self> {
        if self.upcase.len() != 65_536 {
            return Err(invalid("invalid NLS case table"));
        }
        let codepage: Vec<_> = NLS_KEY.encode_utf16().collect();
        let folded: Vec<_> = codepage
            .iter()
            .map(|&u| self.upcase[usize::from(u)])
            .collect();
        if self.keys.contains_key(&folded)
            || [TreeRoot::NlsSortingVersions, TreeRoot::NlsCustomLocale]
                .iter()
                .any(|root| self.selected_trees.contains(root))
        {
            return Err(invalid(
                "complete NLS selection overlaps a partial snapshot",
            ));
        }
        let component: Vec<_> = "CodePage"
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        if !tree.tree.children.iter().any(|(name, _)| {
            name.iter()
                .map(|&u| self.upcase[usize::from(u)])
                .eq(component.iter().copied())
        }) {
            return Err(invalid(
                "complete NLS selection lacks required CodePage key",
            ));
        }
        self.with_information_tree(TreeRoot::Nls, Some(tree))
    }
}
