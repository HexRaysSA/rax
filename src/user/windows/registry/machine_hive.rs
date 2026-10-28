//! The fixed MACHINE header and handle-owned routes to already selected keys.
//! No descendant walk, native handle, or host callback is retained.
use super::super::nt::status::STATUS_ACCESS_DENIED;
use super::*;

pub(crate) const MACHINE_HIVE_KEY: &str = "\\Registry\\Machine";
const KEY_ALL_ACCESS: u32 = 0x000F_003F;

#[derive(Clone, Copy, Debug)]
pub(crate) struct MachineAccess {
    pub(crate) maximum_access: u32,
    pub(crate) system_security_status: u32,
}
impl MachineAccess {
    pub(crate) fn grant(self, access: u32) -> Result<u32, u32> {
        let mut requested = access & !(0xF200_0300);
        // Native key-object mappings, including the observed CREATE_LINK bit
        // in generic execute. View bits select routes, not granted rights.
        for (generic, specific) in [
            (0x8000_0000, 0x0002_0019),
            (0x4000_0000, 0x0002_0006),
            (0x2000_0000, 0x0002_0039),
            (0x1000_0000, KEY_ALL_ACCESS),
        ] {
            if access & generic != 0 {
                requested |= specific;
            }
        }
        if requested & !(KEY_ALL_ACCESS | 0x0100_0000) != 0
            || requested & KEY_ALL_ACCESS & !self.maximum_access != 0
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & 0x0100_0000 != 0 && self.system_security_status != 0 {
            return Err(self.system_security_status);
        }
        if access & 0x0200_0000 != 0 {
            requested |= self.maximum_access;
        }
        if requested == 0 {
            Err(STATUS_ACCESS_DENIED)
        } else {
            Ok(requested)
        }
    }
}

pub(crate) struct MachineHeader {
    pub(crate) canonical: Vec<u16>,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
    pub(crate) access: MachineAccess,
}

#[derive(Debug)]
pub(super) struct MachineKey {
    access: MachineAccess,
    paths: BTreeMap<Vec<u16>, Option<Arc<Key>>>,
    appmodel: Arc<AppModelViews>,
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
            || header.access.maximum_access & !KEY_ALL_ACCESS != 0
            || (header.access.system_security_status != 0
                && header.access.system_security_status & 0x8000_0000 == 0)
        {
            return Err(invalid("invalid or duplicate MACHINE hive selection"));
        }
        let values = bounded_values(&self.upcase, header.values, &mut self.value_budget()?)?;
        let machine = self.machine_paths(header.access, header.children)?;
        self.machine_hive = Some(Arc::new(Key {
            path: header.canonical,
            appmodel_view: None,
            children: header.children,
            upcase: self.upcase.clone(),
            values: Arc::new(values),
            subkeys: None,
            selected_child: None,
            selected_paths: BTreeMap::new(),
            machine: Some(machine),
        }));
        Ok(self)
    }

    fn machine_paths(&self, access: MachineAccess, children: u32) -> io::Result<MachineKey> {
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
        if self.appmodel.roots.values().any(Option::is_some) {
            present.insert(fold(&"Software".encode_utf16().collect::<Vec<_>>()));
        }
        if present.len() > children as usize {
            return Err(invalid("selected keys contradict MACHINE child count"));
        }
        Ok(MachineKey {
            access,
            paths,
            appmodel: self.appmodel.clone(),
        })
    }

    pub(super) fn relink_machine_hive(&mut self) -> io::Result<()> {
        let Some(root) = &self.machine_hive else {
            return Ok(());
        };
        let access = root.machine.as_ref().expect("MACHINE root").access;
        let machine = self.machine_paths(access, root.children)?;
        self.machine_hive = Some(Arc::new(Key {
            path: root.path.clone(),
            appmodel_view: None,
            children: root.children,
            upcase: root.upcase.clone(),
            values: root.values.clone(),
            subkeys: None,
            selected_child: None,
            selected_paths: BTreeMap::new(),
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
    pub(crate) fn machine_access(&self) -> Option<MachineAccess> {
        self.machine.as_ref().map(|machine| machine.access)
    }
    pub(crate) fn machine_views(&self) -> Option<Arc<AppModelViews>> {
        self.machine
            .as_ref()
            .map(|machine| machine.appmodel.clone())
    }
    pub(crate) fn relative_in_view(self: &Arc<Self>, name: &[u16], view: RegistryView) -> Lookup {
        let Some(machine) = &self.machine else {
            return self.relative(name);
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
        match machine.appmodel.lookup(&absolute, view) {
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
