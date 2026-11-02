//! The fixed MACHINE header and handle-owned routes to already selected keys.
//! No descendant walk, native handle, or host callback is retained.
use super::*;

pub(crate) const MACHINE_HIVE_KEY: &str = "\\Registry\\Machine";
pub(crate) struct MachineHeader {
    pub(crate) enumeration: Option<Vec<BasicChild>>,
    pub(crate) canonical: Vec<u16>,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
    pub(crate) access: KeyAccess,
}

#[derive(Debug)]
pub(super) struct MachineKey {
    access: KeyAccess,
    paths: BTreeMap<Vec<u16>, Option<Arc<Key>>>,
    views: Arc<RegistryViews>,
}

fn prefix(path: &[u16]) -> bool {
    let expected: Vec<_> = MACHINE_HIVE_KEY.encode_utf16().collect();
    let ascii_upper = |u: u16| if (97..=122).contains(&u) { u - 32 } else { u };
    path.len() >= expected.len()
        && path
            .iter()
            .zip(&expected)
            .all(|(&a, &b)| ascii_upper(a) == ascii_upper(b))
}

impl Registry {
    pub(crate) fn with_machine_hive(mut self, header: MachineHeader) -> io::Result<Self> {
        let expected = MACHINE_HIVE_KEY.encode_utf16().count();
        if self.upcase.len() != 65_536
            || self.machine_hive.is_some()
            || header.canonical.len() != expected
            || !prefix(&header.canonical)
            || header.access.maximum_access & !super::access::KEY_ALL_ACCESS != 0
            || (header.access.system_security_status != 0
                && header.access.system_security_status & 0x8000_0000 == 0)
        {
            return Err(invalid("invalid or duplicate MACHINE hive selection"));
        }
        let mut budget = self.value_budget()?;
        let values = bounded_values(&self.upcase, header.values, &mut budget)?;
        let enumeration = key_enumeration::bounded(
            &self.upcase,
            header.enumeration,
            header.children,
            &mut budget,
        )?;
        let machine = self.machine_paths(header.access, header.children)?;
        self.machine_hive = Some(Arc::new(Key {
            enumeration,
            path: header.canonical,
            redirected_view: None,
            children: header.children,
            upcase: self.upcase.clone(),
            values: Arc::new(values),
            subkeys: None,
            selected_child: None,
            selected_paths: BTreeMap::new(),
            command_access: None,
            logical_path: None,
            root_views: None,
            machine: Some(machine),
        }));
        Ok(self)
    }

    fn machine_paths(&self, access: KeyAccess, children: u32) -> io::Result<MachineKey> {
        let length = MACHINE_HIVE_KEY.encode_utf16().count();
        let fold = |name: &[u16]| {
            name.iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect::<Vec<_>>()
        };
        let mut paths = BTreeMap::new();
        let mut present = BTreeSet::new();
        for key in self.keys.values() {
            if !prefix(&key.path) || key.path.get(length) != Some(&92) {
                continue;
            }
            if key.machine.is_some() {
                return Err(invalid("MACHINE route would retain its own root"));
            }
            let name = &key.path[length + 1..];
            present.insert(fold(name.split(|u| *u == 92).next().unwrap_or_default()));
            paths.insert(fold(name), Some(key.clone()));
        }
        for selected in &self.selected_trees {
            let name: Vec<_> = selected.path().encode_utf16().skip(length + 1).collect();
            paths.entry(fold(&name)).or_insert(None);
        }
        for key in self.views.roots.values().flatten() {
            if prefix(&key.path) && key.path.get(length) == Some(&92) {
                let child = key.path[length + 1..]
                    .split(|u| *u == 92)
                    .next()
                    .unwrap_or_default();
                present.insert(fold(child));
            }
        }
        if present.len() > children as usize {
            return Err(invalid("selected keys contradict MACHINE child count"));
        }
        Ok(MachineKey {
            access,
            paths,
            views: self.views.clone(),
        })
    }

    pub(super) fn relink_machine_hive(&mut self) -> io::Result<()> {
        let Some(root) = &self.machine_hive else {
            return Ok(());
        };
        let access = root.machine.as_ref().expect("MACHINE root").access;
        let machine = self.machine_paths(access, root.children)?;
        self.machine_hive = Some(Arc::new(Key {
            enumeration: root.enumeration.clone(),
            path: root.path.clone(),
            redirected_view: None,
            children: root.children,
            upcase: root.upcase.clone(),
            values: root.values.clone(),
            subkeys: None,
            selected_child: None,
            selected_paths: BTreeMap::new(),
            command_access: None,
            logical_path: None,
            root_views: None,
            machine: Some(machine),
        }));
        Ok(())
    }

    pub(super) fn machine_hive_lookup(
        &self,
        folded: &[u16],
        name: &[u16],
        view: RegistryView,
    ) -> Lookup {
        let Some(root) = &self.machine_hive else {
            return Lookup::Unselected;
        };
        let logical: Vec<_> = MACHINE_HIVE_KEY.encode_utf16().collect();
        let selected = root.fold(&logical);
        if folded == selected {
            Lookup::Present(root.clone())
        } else if folded.starts_with(&selected) && name.get(logical.len()) == Some(&92) {
            root.relative_in_view(&name[logical.len()..], view)
        } else {
            Lookup::Unselected
        }
    }
}

impl Key {
    pub(crate) fn is_machine_hive(&self) -> bool {
        self.machine.is_some()
    }
    pub(crate) fn captured_access(&self) -> Option<KeyAccess> {
        self.command_access
            .or_else(|| self.machine.as_ref().map(|machine| machine.access))
    }
    pub(crate) fn hive_views(&self) -> Option<Arc<RegistryViews>> {
        self.root_views
            .clone()
            .or_else(|| self.machine.as_ref().map(|machine| machine.views.clone()))
    }
    pub(crate) fn relative_in_view(self: &Arc<Self>, name: &[u16], view: RegistryView) -> Lookup {
        let Some(machine) = &self.machine else {
            if let Some(views) = &self.root_views {
                let absolute: Vec<_> = self
                    .logical_path
                    .as_deref()
                    .unwrap_or(&self.path)
                    .iter()
                    .copied()
                    .chain(Some(92))
                    .chain(name.iter().copied())
                    .collect();
                match views.lookup(&absolute, view) {
                    Lookup::Unselected => {}
                    result => return result,
                }
            }
            return self.relative_selected(name);
        };
        let mut normalized = Vec::with_capacity(name.len());
        for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            if !normalized.is_empty() {
                normalized.push(92);
            }
            normalized.extend_from_slice(component);
        }
        if normalized.is_empty() {
            return Lookup::Present(self.clone());
        }
        let absolute: Vec<_> = MACHINE_HIVE_KEY
            .encode_utf16()
            .chain(Some(92))
            .chain(normalized.iter().copied())
            .collect();
        match machine.views.lookup(&absolute, view) {
            Lookup::Unselected => {}
            selected => return selected,
        }
        let folded = self.fold(&normalized);
        for (prefix, child) in &machine.paths {
            if folded.starts_with(prefix)
                && (folded.len() == prefix.len() || normalized.get(prefix.len()) == Some(&92))
            {
                return match child {
                    Some(child) => child.relative(&normalized[prefix.len()..]),
                    None => Lookup::Missing,
                };
            }
        }
        if self.children == 0 {
            Lookup::Missing
        } else {
            Lookup::Unselected
        }
    }
}

#[cfg(test)]
#[path = "machine_hive_tests.rs"]
mod tests;
