//! Ordered parent metadata survives an inaccessible descendant body.
use super::*;
use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;

pub(crate) struct CapturedTree {
    pub(crate) tree: KeyTree,
    pub(crate) nodes: BTreeMap<Vec<u16>, CapturedTreeNode>,
}

pub(crate) enum CapturedTreeNode {
    Readable(Vec<BasicChild>),
    /// The parent supplies this count; no descendant body is invented.
    Denied {
        children: u32,
    },
}

impl Key {
    pub(crate) fn open_denial(&self) -> Option<u32> {
        self.open_denial
    }
}

pub(super) fn attach(
    key: &mut Arc<Key>,
    nodes: &mut BTreeMap<Vec<u16>, CapturedTreeNode>,
    budget: &mut ValueBudget,
    root: bool,
) -> io::Result<()> {
    let key = Arc::get_mut(key)
        .ok_or_else(|| invalid("captured runtime tree was shared before metadata attachment"))?;
    let node = nodes
        .remove(&key.path)
        .ok_or_else(|| invalid("captured runtime tree is missing node metadata"))?;
    match node {
        CapturedTreeNode::Readable(entries) => {
            let entries =
                key_enumeration::bounded(&key.upcase, Some(entries), key.children, budget)?
                    .ok_or_else(|| invalid("readable captured tree has no enumeration"))?;
            let children = key
                .subkeys
                .as_ref()
                .ok_or_else(|| invalid("readable captured tree has no descendant selection"))?;
            if entries
                .iter()
                .any(|entry| !children.contains_key(&key.fold(&entry.name)))
            {
                return Err(invalid(
                    "captured enumeration differs from selected descendants",
                ));
            }
            key.enumeration = Some(entries);
            for child in key
                .subkeys
                .as_mut()
                .expect("validated selected children")
                .values_mut()
            {
                attach(child, nodes, budget, false)?;
            }
        }
        CapturedTreeNode::Denied { children } => {
            if root
                || !key.values.is_empty()
                || key.children != 0
                || key.subkeys.as_ref().is_none_or(|keys| !keys.is_empty())
            {
                return Err(invalid("access-denied tree node contains an invented body"));
            }
            key.open_denial = Some(STATUS_ACCESS_DENIED);
            key.children = children;
            // Zero is known empty. A positive parent-reported count remains
            // uncaptured, so lookup must not turn unknown descendants into
            // missing paths. Only a final open consumes the retained denial.
            key.subkeys = None;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "captured_tree_tests.rs"]
mod tests;
