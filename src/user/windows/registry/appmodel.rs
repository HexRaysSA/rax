//! Independent immutable AppModel registry views. A handle retains the whole
//! pair for the measured relative 64-to-32 transition, without reference cycles.
use super::*;

pub(crate) const MACHINE_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside\\machine";

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

#[derive(Clone, Debug, Default)]
pub(crate) struct AppModelViews {
    pub(super) roots: BTreeMap<RegistryView, Option<Arc<Key>>>,
    upcase: Arc<[u16]>,
}
impl AppModelViews {
    pub(crate) fn lookup(&self, name: &[u16], view: RegistryView) -> Lookup {
        // The registry may collapse internal separators, but the object-manager
        // prefix must begin with exactly one separator. Malformed object paths
        // remain outside this fixed snapshot rather than becoming captured keys.
        if self.roots.is_empty() || name.first() != Some(&92) || name.get(1) == Some(&92) {
            return Lookup::Unselected;
        }
        let mut normalized = Vec::with_capacity(name.len());
        for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            normalized.push(92);
            normalized.extend_from_slice(component);
        }
        let prefix: Vec<_> = MACHINE_KEY
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        let folded: Vec<_> = normalized
            .iter()
            .map(|&u| self.upcase[usize::from(u)])
            .collect();
        if !folded.starts_with(&prefix)
            || (folded.len() != prefix.len() && normalized.get(prefix.len()) != Some(&92))
        {
            return Lookup::Unselected;
        }
        match self.roots.get(&view) {
            Some(Some(root)) => root.relative(&normalized[prefix.len()..]),
            Some(None) => Lookup::Missing,
            None => Lookup::Unselected,
        }
    }

    pub(crate) fn relative(&self, root: &Key, name: &[u16], view: RegistryView) -> Lookup {
        let absolute: Vec<_> = root
            .path
            .iter()
            .copied()
            .chain(Some(92))
            .chain(name.iter().copied())
            .collect();
        self.lookup(&absolute, view)
    }
}

impl Registry {
    pub(crate) fn with_appmodel_view(
        mut self,
        view: RegistryView,
        tree: Option<KeyTree>,
    ) -> io::Result<Self> {
        if self.upcase.len() != 65_536 || self.appmodel.roots.contains_key(&view) {
            return Err(invalid("invalid or duplicate AppModel registry view"));
        }
        let root = match tree {
            Some(tree) => Some(tree::build(
                self.upcase.clone(),
                MACHINE_KEY.encode_utf16().collect(),
                tree,
                0,
                &mut self.value_budget()?,
                &mut self.appmodel_budget()?,
                Some(view),
            )?),
            None => None,
        };
        let views = Arc::make_mut(&mut self.appmodel);
        views.upcase = self.upcase.clone();
        views.roots.insert(view, root);
        Ok(self)
    }

    pub(super) fn appmodel_budget(&self) -> io::Result<tree::TreeBudget> {
        fn charge(key: &Key, depth: usize, budget: &mut tree::TreeBudget) -> io::Result<()> {
            budget.charge(&key.path, depth)?;
            if let Some(children) = &key.subkeys {
                for child in children.values() {
                    charge(child, depth + 1, budget)?;
                }
            }
            Ok(())
        }
        let mut budget = tree::TreeBudget::default();
        for root in self.appmodel.roots.values().flatten() {
            charge(root, 0, &mut budget)?;
        }
        Ok(budget)
    }
}

#[cfg(test)]
#[path = "appmodel_tests.rs"]
mod tests;
