//! Fixed machine compatibility subjects consulted by installed system libraries.
//! Both views use the complete startup snapshot budget and retain their actual
//! canonical identities. No guest name or handle reaches a host registry call.
use super::*;

pub(crate) const WOW64_AMD64_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Wow64\\amd64";
pub(super) const WOW64_X86_JIT_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Wow64\\x86\\xtajit";
const WOW32_CANONICAL: &str = "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Wow64\\amd64";
const X86_JIT_WOW32: &str =
    "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Wow64\\x86\\xtajit";

impl Registry {
    #[cfg(test)]
    pub(crate) fn with_wow64_x86_jit_absence(
        self,
        view: RegistryView,
        status: u32,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(SnapshotRoot::Wow64X86Jit, &[], view, Err(status))
    }

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

    pub(super) fn check_wow64_software_name(
        &self,
        root: SnapshotRoot,
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        let (logical, redirected) = match root {
            SnapshotRoot::Wow64Amd64 => (WOW64_AMD64_KEY, WOW32_CANONICAL),
            SnapshotRoot::Wow64X86Jit => (WOW64_X86_JIT_KEY, X86_JIT_WOW32),
            _ => return Err(invalid("key is outside the WOW64 software selection")),
        };
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("WOW64 software canonical name exceeds bounds"));
        }
        let same = |path: &str| {
            canonical.len() == path.encode_utf16().count()
                && canonical
                    .iter()
                    .copied()
                    .zip(path.encode_utf16())
                    .all(|(a, b)| self.upcase[usize::from(a)] == self.upcase[usize::from(b)])
        };
        if !same(logical) && !(view == RegistryView::Wow32 && same(redirected)) {
            return Err(invalid(
                "WOW64 software canonical name is outside fixed selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wow64_amd64_tests.rs"]
mod tests;
