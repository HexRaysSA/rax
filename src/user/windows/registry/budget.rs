//! Fixed snapshot domains bound acquisition before any guest execution.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) keys: usize,
    pub(super) path_bytes: usize,
    pub(super) values: usize,
    pub(super) value_bytes: usize,
    pub(super) entries: usize,
    pub(super) entry_bytes: usize,
}

pub(super) const STARTUP: Limits = Limits {
    keys: tree::MAX_TREE_KEYS,
    path_bytes: 1 << 20,
    values: MAX_VALUES,
    value_bytes: MAX_TOTAL_BYTES,
    entries: 2 * tree::MAX_TREE_KEYS,
    entry_bytes: 1 << 20,
};

// An observed ordinary creator has 4,315 keys and 11,668 values per view.
// This fixed subject has its own aggregate domain across both retained views.
pub(super) const LOCAL_SETTINGS: Limits = Limits {
    keys: 16_384,
    path_bytes: 8 << 20,
    values: 65_536,
    value_bytes: 32 << 20,
    entries: 32_768,
    entry_bytes: 2 << 20,
};

pub(super) struct ValueBudget {
    pub(super) limits: Limits,
    pub(super) enumeration_count: usize,
    pub(super) enumeration_bytes: usize,
    pub(super) count: usize,
    pub(super) bytes: usize,
}

impl Default for ValueBudget {
    fn default() -> Self {
        Self::with_limits(STARTUP)
    }
}

impl ValueBudget {
    pub(super) fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            enumeration_count: 0,
            enumeration_bytes: 0,
            count: 0,
            bytes: 0,
        }
    }

    pub(super) fn remaining_values(&self) -> usize {
        self.limits.values.saturating_sub(self.count)
    }

    pub(super) fn remaining_bytes(&self) -> usize {
        self.limits.value_bytes.saturating_sub(self.bytes)
    }

    pub(super) fn charge(&mut self, value: &Value) -> io::Result<()> {
        if value.name.len() > MAX_NAME_UNITS || value.data.len() > MAX_VALUE_BYTES {
            return Err(invalid("runtime registry value exceeds bounds"));
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("runtime registry count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(value.name.len() * 2 + value.data.len())
            .ok_or_else(|| invalid("runtime registry size overflow"))?;
        if self.count > self.limits.values || self.bytes > self.limits.value_bytes {
            return Err(invalid("runtime registry aggregate exceeds bounds"));
        }
        Ok(())
    }
}

impl Registry {
    pub(super) fn snapshot_budgets(
        &self,
        root: SnapshotRoot,
    ) -> io::Result<(ValueBudget, tree::TreeBudget)> {
        if root != SnapshotRoot::LocalSettings {
            return Ok((self.value_budget()?, self.view_budget()?));
        }
        let mut values = ValueBudget::with_limits(LOCAL_SETTINGS);
        let mut metadata = tree::TreeBudget::with_limits(LOCAL_SETTINGS);
        let mut seen = BTreeSet::new();
        for ((kind, _), key) in &self.views.roots {
            if *kind == ViewRoot::LocalSettings {
                if let Some(key) = key {
                    tree::charge_key(key, &mut values, &mut seen)?;
                    metadata.charge_tree(key, 0)?;
                }
            }
        }
        Ok((values, metadata))
    }
}
