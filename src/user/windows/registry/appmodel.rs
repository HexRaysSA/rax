//! Independent immutable AppModel registry views. A handle retains the whole
//! catalog for the measured relative 64-to-32 transition, without reference cycles.
use super::*;

pub(crate) const MACHINE_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside\\machine";
pub(crate) const USER_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside\\user";

/// Both leaves belong to HKLM. `User` does not select HKCU or a user SID hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AppModelRoot {
    Machine,
    User,
}
impl AppModelRoot {
    pub(crate) const ALL: [Self; 2] = [Self::Machine, Self::User];

    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Machine => MACHINE_KEY,
            Self::User => USER_KEY,
        }
    }
}

impl Registry {
    pub(crate) fn with_appmodel_view(
        mut self,
        selected: AppModelRoot,
        view: RegistryView,
        tree: Option<KeyTree>,
    ) -> io::Result<Self> {
        if self.upcase.len() != 65_536
            || self
                .views
                .roots
                .contains_key(&(ViewRoot::AppModel(selected), view))
        {
            return Err(invalid("invalid or duplicate AppModel registry view"));
        }
        let root = match tree {
            Some(tree) => Some(tree::build(
                self.upcase.clone(),
                selected.path().encode_utf16().collect(),
                tree,
                0,
                &mut self.value_budget()?,
                &mut self.view_budget()?,
                Some(view),
            )?),
            None => None,
        };
        let views = Arc::make_mut(&mut self.views);
        views.upcase = self.upcase.clone();
        views.paths.insert(
            ViewRoot::AppModel(selected),
            selected.path().encode_utf16().collect::<Vec<_>>().into(),
        );
        views
            .roots
            .insert((ViewRoot::AppModel(selected), view), root);
        self.relink_machine_hive()?;
        self.link_primary_hive_policy()?;
        Ok(self)
    }

    pub(super) fn view_budget(&self) -> io::Result<tree::TreeBudget> {
        let mut budget = tree::TreeBudget::default();
        for ((kind, _), root) in &self.views.roots {
            if *kind != ViewRoot::LocalSettings {
                if let Some(root) = root {
                    budget.charge_tree(root, 0)?;
                }
            }
        }
        Ok(budget)
    }
}

#[cfg(test)]
#[path = "appmodel_tests.rs"]
mod tests;
