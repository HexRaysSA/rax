//! Complete immutable subtrees below explicitly selected fixed runtime roots.
//! Descendants are owned by ancestor key handles, with no host callbacks.
use super::*;

pub(crate) const IFEO_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
pub(crate) const REDIRECTION_KEYS_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\Keys";
pub(crate) const SAFEBOOT_OPTION_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\SafeBoot\\Option";
pub(crate) const SRP_DLL_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Srp\\GP\\DLL";
pub(crate) const SAFER_CODE_IDENTIFIERS_KEY: &str =
    "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";
pub(crate) const FILESYSTEM_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem";
pub(crate) const NLS_SORTING_VERSIONS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Sorting\\Versions";
pub(crate) const ERROR_MESSAGE_INSTRUMENT_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Error Message Instrument";
pub(crate) const DISPLAY_POLICY_KEY: &str =
    "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Display";
pub(crate) const GRE_INITIALIZE_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize";
pub(crate) const COMMON_GLOB_USER_SETTINGS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CommonGlobUserSettings";
pub(crate) const MUI_SETTINGS_KEY: &str =
    "\\Registry\\Machine\\Software\\Policies\\Microsoft\\MUI\\Settings";
pub(crate) const MUI_SYSTEM_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI";
pub(crate) const LANGUAGE_OVERLAY_PACKAGES_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\LanguageOverlay\\OverlayPackages";
pub(super) const MAX_TREE_KEYS: usize = 1024;
pub(super) const MAX_TREE_DEPTH: usize = 32;
pub(super) const MAX_COMPONENT_UNITS: usize = 255;
const MAX_PATH_BYTES: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct KeyTree {
    pub(crate) values: Vec<Value>,
    pub(crate) children: Vec<(Vec<u16>, KeyTree)>,
}
/// Only these compile-time roots can select a complete native subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TreeRoot {
    Ifeo,
    RedirectionKeys,
    SafeBootOption,
    SrpDll,
    SaferCodeIdentifiers,
    FileSystem,
    NlsSortingVersions,
    ErrorMessageInstrument,
    DisplayPolicy,
    GreInitialize,
    CommonGlobUserSettings,
    MuiSettings,
    MuiSystem,
    LanguageOverlayPackages,
}
impl TreeRoot {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Ifeo => IFEO_KEY,
            Self::RedirectionKeys => REDIRECTION_KEYS_KEY,
            Self::SafeBootOption => SAFEBOOT_OPTION_KEY,
            Self::SrpDll => SRP_DLL_KEY,
            Self::SaferCodeIdentifiers => SAFER_CODE_IDENTIFIERS_KEY,
            Self::FileSystem => FILESYSTEM_KEY,
            Self::NlsSortingVersions => NLS_SORTING_VERSIONS_KEY,
            Self::ErrorMessageInstrument => ERROR_MESSAGE_INSTRUMENT_KEY,
            Self::DisplayPolicy => DISPLAY_POLICY_KEY,
            Self::GreInitialize => GRE_INITIALIZE_KEY,
            Self::CommonGlobUserSettings => COMMON_GLOB_USER_SETTINGS_KEY,
            Self::MuiSettings => MUI_SETTINGS_KEY,
            Self::MuiSystem => MUI_SYSTEM_KEY,
            Self::LanguageOverlayPackages => LANGUAGE_OVERLAY_PACKAGES_KEY,
        }
    }
}
pub(crate) enum Lookup {
    Present(Arc<Key>),
    Missing,
    Unselected,
}
#[derive(Default)]
pub(super) struct TreeBudget {
    keys: usize,
    path_bytes: usize,
}
impl TreeBudget {
    pub(super) fn key_count(&self) -> usize {
        self.keys
    }
    pub(super) fn charge(&mut self, path: &[u16], depth: usize) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH || path.len() > 32_767 {
            return Err(invalid("runtime registry depth/path exceeds bounds"));
        }
        self.keys += 1;
        self.path_bytes = self
            .path_bytes
            .checked_add(path.len() * 2)
            .ok_or_else(|| invalid("runtime registry path size overflow"))?;
        if self.keys > MAX_TREE_KEYS || self.path_bytes > MAX_PATH_BYTES {
            return Err(invalid("runtime registry key/path budget exhausted"));
        }
        Ok(())
    }
}
pub(super) fn child_path(parent: &[u16], name: &[u16]) -> io::Result<Vec<u16>> {
    if name.is_empty()
        || name.len() > MAX_COMPONENT_UNITS
        || name.iter().any(|u| matches!(*u, 0 | 92))
    {
        return Err(invalid(
            "runtime registry child name exceeds component grammar",
        ));
    }
    Ok(parent
        .iter()
        .copied()
        .chain(Some(92))
        .chain(name.iter().copied())
        .collect())
}
impl Registry {
    pub(super) fn value_budget(&self) -> io::Result<ValueBudget> {
        let mut budget = ValueBudget::default();
        let mut seen = BTreeSet::new();
        for key in self.keys.values() {
            charge_key(key, &mut budget, &mut seen)?;
        }
        for key in self.appmodel.roots.values().flatten() {
            charge_key(key, &mut budget, &mut seen)?;
        }
        Ok(budget)
    }
    pub(crate) fn with_ifeo(self, tree: KeyTree) -> io::Result<Self> {
        self.with_tree(TreeRoot::Ifeo, Some(tree))
    }
    pub(crate) fn with_absent_ifeo(self) -> io::Result<Self> {
        self.with_tree(TreeRoot::Ifeo, None)
    }
    pub(crate) fn with_tree(mut self, root: TreeRoot, tree: Option<KeyTree>) -> io::Result<Self> {
        if self.upcase.len() != 65_536 || self.selected_trees.contains(&root) {
            return Err(invalid("invalid or duplicate runtime subtree selection"));
        }
        if let Some(tree) = tree {
            let path: Vec<_> = root.path().encode_utf16().collect();
            let folded: Vec<_> = path.iter().map(|&u| self.upcase[usize::from(u)]).collect();
            let key = build(
                self.upcase.clone(),
                path,
                tree,
                0,
                &mut self.value_budget()?,
                &mut TreeBudget::default(),
                None,
            )?;
            self.keys.insert(folded, key);
        }
        self.selected_trees.insert(root);
        Ok(self)
    }
    pub(super) fn tree_lookup(&self, name: &[u16], original: &[u16]) -> Lookup {
        for root in &self.selected_trees {
            let prefix: Vec<_> = root
                .path()
                .encode_utf16()
                .map(|u| self.upcase[usize::from(u)])
                .collect();
            if name == prefix {
                return Lookup::Missing;
            }
            if !name.starts_with(&prefix) || original.get(prefix.len()) != Some(&92) {
                continue;
            }
            let Some(root) = self.keys.get(&prefix) else {
                return Lookup::Missing;
            };
            // Parse original separators and fold each child exactly once.
            // The supplied case table need not be assumed idempotent here.
            return root.relative(&original[prefix.len()..]);
        }
        for prefix in self.user_policies.values() {
            if name == prefix.as_ref() {
                return Lookup::Missing;
            }
            if name.starts_with(prefix) && original.get(prefix.len()) == Some(&92) {
                let Some(root) = self.keys.get(prefix.as_ref()) else {
                    return Lookup::Missing;
                };
                return root.relative(&original[prefix.len()..]);
            }
        }
        Lookup::Unselected
    }
}
fn charge_key(
    key: &Arc<Key>,
    budget: &mut ValueBudget,
    seen: &mut BTreeSet<usize>,
) -> io::Result<()> {
    if !seen.insert(Arc::as_ptr(key) as usize) {
        return Ok(());
    }
    for value in key.values.values() {
        budget.charge(value)?;
    }
    if let Some((_, Some(child))) = &key.selected_child {
        charge_key(child, budget, seen)?;
    }
    for child in key.selected_paths.values().flatten() {
        charge_key(child, budget, seen)?;
    }
    if let Some(children) = &key.subkeys {
        for child in children.values() {
            charge_key(child, budget, seen)?;
        }
    }
    Ok(())
}
impl Key {
    pub(crate) fn relative(self: &Arc<Self>, name: &[u16]) -> Lookup {
        if !self.selected_paths.is_empty() {
            let mut normalized = Vec::with_capacity(name.len());
            for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
                if !normalized.is_empty() {
                    normalized.push(92);
                }
                normalized.extend_from_slice(component);
            }
            let folded = self.fold(&normalized);
            for (selected, child) in &self.selected_paths {
                if folded.starts_with(selected)
                    && (folded.len() == selected.len()
                        || normalized.get(selected.len()) == Some(&92))
                {
                    return match child {
                        Some(child) => child.relative(&normalized[selected.len()..]),
                        None => Lookup::Missing,
                    };
                }
            }
        }
        let mut key = self.clone();
        // Native registry opens ignore repeated and trailing separators.
        // Dot components and '/' remain literal registry names.
        for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            let folded = key.fold(component);
            if let Some((selected, child)) = &key.selected_child {
                if selected == &folded {
                    let Some(child) = child.clone() else {
                        return Lookup::Missing;
                    };
                    key = child;
                    continue;
                }
            }
            let Some(children) = &key.subkeys else {
                return if key.children == 0 {
                    Lookup::Missing
                } else {
                    Lookup::Unselected
                };
            };
            let Some(child) = children.get(&folded) else {
                return Lookup::Missing;
            };
            key = child.clone();
        }
        Lookup::Present(key)
    }
}
pub(super) fn build(
    upcase: Arc<[u16]>,
    path: Vec<u16>,
    tree: KeyTree,
    depth: usize,
    values: &mut ValueBudget,
    metadata: &mut TreeBudget,
    appmodel_view: Option<RegistryView>,
) -> io::Result<Arc<Key>> {
    metadata.charge(&path, depth)?;
    if tree.children.len() >= MAX_TREE_KEYS {
        return Err(invalid("runtime registry child count exceeds bounds"));
    }
    let raw_values = bounded_values(&upcase, tree.values, values)?;
    let mut key = Key {
        path,
        appmodel_view,
        children: tree.children.len() as u32,
        upcase,
        values: Arc::new(raw_values),
        subkeys: None,
        selected_child: None,
        selected_paths: BTreeMap::new(),
    };
    let mut children = BTreeMap::new();
    for (name, child) in tree.children {
        let path = child_path(&key.path, &name)?;
        let name = key.fold(&name);
        let child = build(
            key.upcase.clone(),
            path,
            child,
            depth + 1,
            values,
            metadata,
            appmodel_view,
        )?;
        if children.insert(name, child).is_some() {
            return Err(invalid("duplicate ordinal runtime registry child"));
        }
    }
    key.subkeys = Some(children);
    Ok(Arc::new(key))
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "redirection_tests.rs"]
mod redirection_tests;
