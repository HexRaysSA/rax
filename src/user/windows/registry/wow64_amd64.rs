//! Fixed machine compatibility subject consulted by installed x64 libraries.
//! Both views use the complete startup snapshot budget and retain their actual
//! canonical identities. No guest name or handle reaches a host registry call.
use super::*;

pub(crate) const WOW64_AMD64_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Wow64\\amd64";
const WOW32_CANONICAL: &str = "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Wow64\\amd64";

impl Registry {
    pub(crate) fn with_wow64_amd64_tree(
        self,
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(
            SnapshotRoot::Wow64Amd64,
            &[],
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }

    pub(super) fn check_wow64_amd64_name(
        &self,
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("WOW64 amd64 canonical name exceeds bounds"));
        }
        let same = |path: &str| {
            canonical.len() == path.encode_utf16().count()
                && canonical
                    .iter()
                    .copied()
                    .zip(path.encode_utf16())
                    .all(|(a, b)| self.upcase[usize::from(a)] == self.upcase[usize::from(b)])
        };
        if !same(WOW64_AMD64_KEY) && !(view == RegistryView::Wow32 && same(WOW32_CANONICAL)) {
            return Err(invalid(
                "WOW64 amd64 canonical name is outside fixed selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wow64_amd64_tests.rs"]
mod tests;
