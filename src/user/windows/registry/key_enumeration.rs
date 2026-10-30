//! Ordered native child metadata is independent of selected descendant bodies.
use super::*;

/// Immutable `KeyBasicInformation` source data. Time is the native FILETIME,
/// in 100 ns units since 1601-01-01 UTC; no host handle or callback is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BasicChild {
    pub(crate) name: Vec<u16>,
    pub(crate) last_write: u64,
}

impl Key {
    pub(crate) fn child_metadata(&self) -> Option<&[BasicChild]> {
        self.enumeration.as_deref()
    }
}

impl ValueBudget {
    pub(super) fn charge_enumeration(&mut self, children: &[BasicChild]) -> io::Result<()> {
        self.enumeration_count = self
            .enumeration_count
            .checked_add(children.len())
            .ok_or_else(|| invalid("registry enumeration count overflow"))?;
        for child in children {
            self.enumeration_bytes = self
                .enumeration_bytes
                .checked_add(child.name.len() * 2 + 8)
                .ok_or_else(|| invalid("registry enumeration size overflow"))?;
        }
        if self.enumeration_count > self.limits.entries
            || self.enumeration_bytes > self.limits.entry_bytes
        {
            return Err(invalid("registry enumeration aggregate exceeds bounds"));
        }
        Ok(())
    }
}

pub(super) fn bounded(
    upcase: &[u16],
    children: Option<Vec<BasicChild>>,
    count: u32,
    budget: &mut ValueBudget,
) -> io::Result<Option<Arc<[BasicChild]>>> {
    let Some(children) = children else {
        return Ok(None);
    };
    if children.len() != count as usize || children.len() > budget.limits.keys {
        return Err(invalid(
            "registry enumeration child count differs or exceeds bounds",
        ));
    }
    let mut seen = BTreeSet::new();
    for child in &children {
        tree::child_path(&[], &child.name)?;
        let folded: Vec<_> = child.name.iter().map(|&u| upcase[usize::from(u)]).collect();
        if !seen.insert(folded) {
            return Err(invalid("duplicate ordinal registry enumeration child"));
        }
    }
    budget.charge_enumeration(&children)?;
    Ok(Some(children.into()))
}

#[cfg(test)]
#[path = "key_enumeration_tests.rs"]
mod tests;
