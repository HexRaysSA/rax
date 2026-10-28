//! The creator's hive header and its captured native alias. This partial key
//! owns the already selected policy route; other nonempty descendants stay unknown.
use super::*;

#[derive(Debug, Clone)]
pub(super) struct PrimaryHive {
    path: Vec<u16>,
    root: Option<Arc<Key>>,
}

pub(crate) struct HiveHeader {
    pub(crate) canonical: Vec<u16>,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
}

impl Registry {
    pub(super) fn check_primary_hive_sid(&self, sid: &[u8]) -> io::Result<()> {
        let path = user_policy::user_hive_path(sid)?;
        if self
            .primary_hive
            .as_ref()
            .is_some_and(|hive| hive.path != path)
        {
            return Err(invalid("primary hive and policy select different subjects"));
        }
        if let Some(policy) = &self.user_policy {
            let expected: Vec<_> = user_policy_path(sid)?
                .iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect();
            if policy.as_ref() != expected {
                return Err(invalid("primary hive and policy select different subjects"));
            }
        }
        Ok(())
    }

    pub(crate) fn with_primary_hive(
        mut self,
        sid: &[u8],
        header: Option<HiveHeader>,
    ) -> io::Result<Self> {
        if self.upcase.len() != 65_536 || self.primary_hive.is_some() {
            return Err(invalid("invalid or duplicate primary hive selection"));
        }
        let path = user_policy::user_hive_path(sid)?;
        self.check_primary_hive_sid(sid)?;
        let root = match header {
            Some(header) => {
                let prefix: Vec<_> = "\\Registry\\User\\".encode_utf16().collect();
                if header.canonical.len() > MAX_NAME_UNITS
                    || header.canonical.len() <= prefix.len()
                    || header.canonical.contains(&0)
                    || header.canonical[prefix.len()..].contains(&92)
                    || !prefix
                        .iter()
                        .zip(&header.canonical)
                        .all(|(&a, &b)| self.upcase[usize::from(a)] == self.upcase[usize::from(b)])
                {
                    return Err(invalid("captured primary hive name is outside native HKU"));
                }
                let values =
                    bounded_values(&self.upcase, header.values, &mut self.value_budget()?)?;
                Some(Arc::new(Key {
                    path: header.canonical,
                    children: header.children,
                    upcase: self.upcase.clone(),
                    values: Arc::new(values),
                    subkeys: None,
                    selected_child: None,
                    selected_path: None,
                }))
            }
            None => None,
        };
        if let Some(root) = &root {
            self.insert_hive_aliases(&path, root);
        }
        self.primary_hive = Some(PrimaryHive { path, root });
        self.link_primary_hive_policy()?;
        Ok(self)
    }

    fn insert_hive_aliases(&mut self, path: &[u16], root: &Arc<Key>) {
        self.keys.insert(root.fold(path), root.clone());
        self.keys.insert(root.fold(&root.path), root.clone());
    }

    pub(super) fn link_primary_hive_policy(&mut self) -> io::Result<()> {
        let (Some(hive), Some(policy)) = (&self.primary_hive, &self.user_policy) else {
            return Ok(());
        };
        let child = self.keys.get(policy.as_ref()).cloned();
        let Some(root) = &hive.root else {
            if child.is_some() {
                return Err(invalid(
                    "selected policy exists below an absent primary hive",
                ));
            }
            return Ok(());
        };
        if root.children == 0 && child.is_some() {
            return Err(invalid(
                "selected policy exists below a childless primary hive",
            ));
        }
        let relative: Vec<_> = user_policy::POLICY_SUFFIX.encode_utf16().skip(1).collect();
        let root = Arc::new(Key {
            path: root.path.clone(),
            children: root.children,
            upcase: root.upcase.clone(),
            values: root.values.clone(),
            subkeys: None,
            selected_child: None,
            selected_path: Some((root.fold(&relative), child)),
        });
        let path = hive.path.clone();
        self.insert_hive_aliases(&path, &root);
        self.primary_hive.as_mut().unwrap().root = Some(root);
        Ok(())
    }

    pub(super) fn primary_hive_lookup(&self, folded: &[u16], name: &[u16]) -> Lookup {
        let Some(hive) = &self.primary_hive else {
            return Lookup::Unselected;
        };
        let primary: Vec<_> = hive
            .path
            .iter()
            .map(|&u| self.upcase[usize::from(u)])
            .collect();
        let Some(root) = &hive.root else {
            return if folded == primary
                || folded.starts_with(&primary) && name.get(primary.len()) == Some(&92)
            {
                Lookup::Missing
            } else {
                Lookup::Unselected
            };
        };
        for prefix in [&hive.path, &root.path] {
            let selected = root.fold(prefix);
            if folded.starts_with(&selected) && name.get(prefix.len()) == Some(&92) {
                return root.relative(&name[prefix.len()..]);
            }
        }
        Lookup::Unselected
    }
}

#[cfg(test)]
#[path = "primary_hive_tests.rs"]
mod tests;
