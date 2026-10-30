//! Stable per-node values, names and grants, with one shared traversal budget.
use super::*;
use crate::user::windows::registry::tree::{TreeBudget, child_path};
use crate::user::windows::registry::{CommandTree, ValueBudget};

struct Capture<'a, F> {
    registry: &'a Registry,
    root: SnapshotRoot,
    sid: &'a [u8],
    view: RegistryView,
    values: ValueBudget,
    metadata: TreeBudget,
    reserved: usize,
    opener: F,
}

pub(super) fn capture(
    registry: &Registry,
    root: SnapshotRoot,
    sid: &[u8],
    view: RegistryView,
    key: OwnedKey,
) -> io::Result<CommandTree> {
    capture_snapshot_with(registry, root, sid, view, key, |path| {
        open_snapshot_path(root, sid, view, path)
    })
}

#[cfg(test)]
pub(super) fn capture_with(
    registry: &Registry,
    root: CommandRoot,
    sid: &[u8],
    view: RegistryView,
    key: OwnedKey,
    opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<CommandTree> {
    capture_snapshot_with(
        registry,
        SnapshotRoot::Command(root),
        sid,
        view,
        key,
        opener,
    )
}

fn capture_snapshot_with(
    registry: &Registry,
    root: SnapshotRoot,
    sid: &[u8],
    view: RegistryView,
    key: OwnedKey,
    opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<CommandTree> {
    let (values, metadata) = registry.snapshot_budgets(root)?;
    let reserved = metadata
        .key_count()
        .checked_add(1)
        .filter(|count| *count <= metadata.key_limit())
        .ok_or_else(|| invalid("Command Processor key budget exhausted"))?;
    let mut capture = Capture {
        registry,
        root,
        sid,
        view,
        values,
        metadata,
        reserved,
        opener,
    };
    capture.node(root.path(sid)?, None, 0, Some(key))
}

impl<F: FnMut(&[u16]) -> io::Result<OwnedKey>> Capture<'_, F> {
    fn node(
        &mut self,
        logical: Vec<u16>,
        expected: Option<Vec<u16>>,
        depth: usize,
        supplied: Option<OwnedKey>,
    ) -> io::Result<CommandTree> {
        let (header, names) = {
            let key = match supplied {
                Some(key) => key,
                None => (self.opener)(&logical)?,
            };
            let canonical = canonical_hive_name(&key, "Command Processor")?;
            if let Some(expected) = expected {
                let fold = |path: &[u16]| {
                    path.iter()
                        .map(|&u| self.registry.upcase[usize::from(u)])
                        .collect::<Vec<_>>()
                };
                if fold(&canonical) != fold(&expected) {
                    return Err(invalid("Command Processor child escapes captured parent"));
                }
            } else {
                self.root
                    .check_name(self.registry, self.sid, self.view, &canonical)?;
            }
            self.metadata.charge(&canonical, depth)?;
            let access = access(&key, &canonical)?;
            let (values, names) = super::super::key_enumeration::stable_bounded(
                &key,
                &self.values,
                self.reserved,
                self.metadata.key_limit(),
            )?;
            if canonical_hive_name(&key, "Command Processor")? != canonical
                || super::super::native_key::basic(&key, "Command Processor")?
                    != access.maximum_access
            {
                return Err(invalid(
                    "Command Processor identity/grant changed during capture",
                ));
            }
            (
                CommandHeader {
                    enumeration: Some(names.clone()),
                    canonical,
                    children: names.len() as u32,
                    values,
                    access,
                },
                names,
            )
        }; // Close the native parent before opening any descendant.
        self.reserved += names.len();
        self.values.charge_enumeration(&names)?;
        for value in &header.values {
            self.values.charge(value)?;
        }
        let mut children = Vec::new();
        for child in names {
            let name = child.name;
            let next = child_path(&logical, &name)?;
            let physical = child_path(&header.canonical, &name)?;
            children.push((name, self.node(next, Some(physical), depth + 1, None)?));
        }
        Ok(CommandTree { header, children })
    }
}

fn access(key: &OwnedKey, canonical: &[u16]) -> io::Result<KeyAccess> {
    let maximum_access = super::super::native_key::basic(key, "Command Processor")?;
    let system_security_status = match super::super::native_key::open(canonical, 0x01000000) {
        Ok(security) => {
            if super::super::native_key::basic(&security, "Command Processor security")?
                & 0x01000000
                == 0
            {
                return Err(invalid(
                    "Command Processor security grant lacks requested access",
                ));
            }
            0
        }
        Err(0) => {
            return Err(invalid(
                "Command Processor security open returned no handle",
            ));
        }
        Err(status) => status,
    };
    Ok(KeyAccess {
        maximum_access,
        system_security_status,
    })
}
