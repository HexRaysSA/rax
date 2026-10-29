//! Complete CMD trees own every child and that child's captured access profile.
use super::*;
use crate::user::windows::registry::tree::{TreeBudget, child_path};

pub(crate) struct CommandTree {
    pub(crate) header: CommandHeader,
    pub(crate) children: Vec<(Vec<u16>, CommandTree)>,
}

pub(super) struct Builder {
    upcase: Arc<[u16]>,
    view: RegistryView,
    values: ValueBudget,
    metadata: TreeBudget,
}

impl Builder {
    pub(super) fn new(registry: &Registry, view: RegistryView) -> io::Result<Self> {
        Ok(Self {
            upcase: registry.upcase.clone(),
            view,
            values: registry.value_budget()?,
            metadata: registry.view_budget()?,
        })
    }

    pub(super) fn build(
        &mut self,
        logical: Vec<u16>,
        header: CommandHeader,
        children: Option<Vec<(Vec<u16>, CommandTree)>>,
        depth: usize,
    ) -> io::Result<Arc<Key>> {
        if header.canonical.len() > MAX_NAME_UNITS || header.canonical.contains(&0) {
            return Err(invalid("Command Processor canonical name exceeds bounds"));
        }
        if header.access.maximum_access & !super::super::access::KEY_ALL_ACCESS != 0
            || header.access.system_security_status != 0
                && header.access.system_security_status & 0x8000_0000 == 0
        {
            return Err(invalid("invalid Command Processor access ceiling"));
        }
        if children.as_ref().is_some_and(|children| {
            children.len() != header.children as usize
                || children.len() >= super::super::tree::MAX_TREE_KEYS
        }) {
            return Err(invalid("Command Processor complete child count differs"));
        }
        self.metadata.charge(&header.canonical, depth)?;
        let values = bounded_values(&self.upcase, header.values, &mut self.values)?;
        let enumeration = super::super::key_enumeration::bounded(
            &self.upcase,
            header.enumeration,
            header.children,
            &mut self.values,
        )?;
        let mut key = Key {
            enumeration,
            path: header.canonical,
            redirected_view: Some(self.view),
            children: header.children,
            upcase: self.upcase.clone(),
            values: Arc::new(values),
            subkeys: None,
            selected_child: None,
            selected_paths: BTreeMap::new(),
            command_access: Some(header.access),
            logical_path: Some(logical.clone().into()),
            root_views: None,
            machine: None,
        };
        if let Some(children) = children {
            let mut selected = BTreeMap::new();
            for (name, child) in children {
                let physical = child_path(&key.path, &name)?;
                if key.fold(&physical) != key.fold(&child.header.canonical) {
                    return Err(invalid("Command Processor child escapes captured parent"));
                }
                let logical = child_path(&logical, &name)?;
                let child = self.build(logical, child.header, Some(child.children), depth + 1)?;
                if selected.insert(key.fold(&name), child).is_some() {
                    return Err(invalid("duplicate ordinal Command Processor child"));
                }
            }
            if key.enumeration.as_ref().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| !selected.contains_key(&key.fold(&entry.name)))
            }) {
                return Err(invalid(
                    "Command Processor enumeration differs from captured children",
                ));
            }
            key.subkeys = Some(selected);
        }
        Ok(Arc::new(key))
    }
}

pub(super) fn same_physical_contents(left: &Key, right: &Key) -> bool {
    if left.children != right.children
        || left.values != right.values
        || left.command_access != right.command_access
    {
        return false;
    }
    if let (Some(left), Some(right)) = (&left.enumeration, &right.enumeration)
        && left != right
    {
        return false;
    }
    match (&left.subkeys, &right.subkeys) {
        (Some(left), Some(right)) => {
            left.len() == right.len()
                && left.iter().all(|(name, child)| {
                    right.get(name).is_some_and(|other| {
                        child.fold(&child.path) == other.fold(&other.path)
                            && same_physical_contents(child, other)
                    })
                })
        }
        // A separately selected partial header makes no descendant assertion.
        _ => true,
    }
}

#[cfg(test)]
#[path = "command_processor_tree_tests.rs"]
mod tests;
