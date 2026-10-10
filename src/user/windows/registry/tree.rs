//! A complete immutable subtree below the one fixed IFEO loader-policy root.
//! Descendants are owned by ancestor key handles, with no host callbacks.
use super::*;

pub(crate) const IFEO_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
pub(super) const MAX_TREE_KEYS: usize = 1024;
pub(super) const MAX_TREE_DEPTH: usize = 32;
pub(super) const MAX_COMPONENT_UNITS: usize = 255;
const MAX_PATH_BYTES: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct IfeoTree {
    pub(crate) values: Vec<Value>,
    pub(crate) children: Vec<(Vec<u16>, IfeoTree)>,
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
    pub(super) fn charge(&mut self, path: &[u16], depth: usize) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH || path.len() > 32_767 {
            return Err(invalid("IFEO registry depth/path exceeds bounds"));
        }
        self.keys += 1;
        self.path_bytes = self
            .path_bytes
            .checked_add(path.len() * 2)
            .ok_or_else(|| invalid("IFEO registry path size overflow"))?;
        if self.keys > MAX_TREE_KEYS || self.path_bytes > MAX_PATH_BYTES {
            return Err(invalid("IFEO registry key/path budget exhausted"));
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
            "IFEO registry child name exceeds component grammar",
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
        for key in self.keys.values() {
            charge_key(key, &mut budget)?;
        }
        Ok(budget)
    }
    pub(crate) fn with_ifeo(mut self, tree: IfeoTree) -> io::Result<Self> {
        if self.upcase.len() != 65_536 {
            return Err(invalid("IFEO registry lacks selected ordinal case table"));
        }
        let path: Vec<_> = IFEO_KEY.encode_utf16().collect();
        let folded: Vec<_> = path.iter().map(|&u| self.upcase[usize::from(u)]).collect();
        if self.ifeo_selected {
            return Err(invalid("duplicate IFEO registry selection"));
        }
        let key = build(
            self.upcase.clone(),
            path,
            tree,
            0,
            &mut self.value_budget()?,
            &mut TreeBudget::default(),
        )?;
        self.keys.insert(folded, key);
        self.ifeo_selected = true;
        Ok(self)
    }
    pub(crate) fn with_absent_ifeo(mut self) -> io::Result<Self> {
        if self.upcase.len() != 65_536 || self.ifeo_selected {
            return Err(invalid("invalid or duplicate absent IFEO selection"));
        }
        self.ifeo_selected = true;
        Ok(self)
    }
    pub(super) fn ifeo_lookup(&self, name: &[u16], original: &[u16]) -> Lookup {
        if !self.ifeo_selected {
            return Lookup::Unselected;
        }
        let prefix: Vec<_> = IFEO_KEY
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        if name == prefix {
            return Lookup::Missing;
        }
        if !name.starts_with(&prefix) || original.get(prefix.len()) != Some(&92) {
            return Lookup::Unselected;
        }
        let Some(root) = self.keys.get(&prefix) else {
            return Lookup::Missing;
        };
        // Parse original separators and fold each child exactly once.
        // The supplied case table need not be assumed idempotent here.
        root.relative(&original[prefix.len()..])
    }
}
fn charge_key(key: &Key, budget: &mut ValueBudget) -> io::Result<()> {
    for value in key.values.values() {
        budget.charge(value)?;
    }
    if let Some((_, Some(child))) = &key.selected_child {
        charge_key(child, budget)?;
    }
    if let Some(children) = &key.subkeys {
        for child in children.values() {
            charge_key(child, budget)?;
        }
    }
    Ok(())
}
impl Key {
    pub(crate) fn relative(self: &Arc<Self>, name: &[u16]) -> Lookup {
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
fn build(
    upcase: Arc<[u16]>,
    path: Vec<u16>,
    tree: IfeoTree,
    depth: usize,
    values: &mut ValueBudget,
    metadata: &mut TreeBudget,
) -> io::Result<Arc<Key>> {
    metadata.charge(&path, depth)?;
    if tree.children.len() >= MAX_TREE_KEYS {
        return Err(invalid("IFEO registry child count exceeds bounds"));
    }
    let raw_values = bounded_values(&upcase, tree.values, values)?;
    let mut key = Key {
        path,
        children: tree.children.len() as u32,
        upcase,
        values: Arc::new(raw_values),
        subkeys: None,
        selected_child: None,
    };
    let mut children = BTreeMap::new();
    for (name, child) in tree.children {
        let path = child_path(&key.path, &name)?;
        let name = key.fold(&name);
        let child = build(key.upcase.clone(), path, child, depth + 1, values, metadata)?;
        if children.insert(name, child).is_some() {
            return Err(invalid("duplicate ordinal IFEO registry child"));
        }
    }
    key.subkeys = Some(children);
    Ok(Arc::new(key))
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
