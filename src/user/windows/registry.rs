//! Immutable, explicitly selected runtime registry metadata. Guest key handles
//! reference these records; they never contain or forward a host HKEY.
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

pub(crate) const NLS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
pub(crate) const SESSION_MANAGER_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
pub(crate) const MAX_VALUES: usize = 4096;
pub(crate) const MAX_NAME_UNITS: usize = 16_383;
pub(crate) const MAX_VALUE_BYTES: usize = 1 << 20;
const MAX_TOTAL_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Value {
    pub(crate) name: Vec<u16>,
    pub(crate) kind: u32,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct SelectedKey {
    pub(crate) path: &'static str,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
}

/// A guest-owned immutable registry key, shared by reference-counted handles.
/// No native handle or host-operation callback is stored in this object.
#[derive(Debug)]
pub struct Key {
    pub(crate) path: Vec<u16>,
    pub(crate) children: u32,
    upcase: Arc<[u16]>,
    values: BTreeMap<Vec<u16>, Value>,
}
impl Key {
    pub(crate) fn fold(&self, units: &[u16]) -> Vec<u16> {
        units.iter().map(|&u| self.upcase[usize::from(u)]).collect()
    }
    pub(crate) fn value(&self, name: &[u16]) -> Option<&Value> {
        self.values.get(&self.fold(name))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Registry {
    keys: BTreeMap<Vec<u16>, Arc<Key>>,
    upcase: Arc<[u16]>,
}
impl Registry {
    #[cfg(test)]
    pub(crate) fn nls(upcase: Vec<u16>, values: Vec<Value>, children: u32) -> io::Result<Self> {
        Self::selected(
            upcase,
            vec![SelectedKey {
                path: NLS_KEY,
                children,
                values,
            }],
        )
    }
    pub(crate) fn selected(upcase: Vec<u16>, selected: Vec<SelectedKey>) -> io::Result<Self> {
        if upcase.len() != 65_536 || selected.len() > 2 {
            return Err(invalid("runtime registry table exceeds bounds"));
        }
        let mut result = Self {
            keys: BTreeMap::new(),
            upcase: upcase.into(),
        };
        let (mut total, mut count) = (0usize, 0usize);
        for selected in selected {
            if !matches!(selected.path, NLS_KEY | SESSION_MANAGER_KEY) {
                return Err(invalid("registry key outside fixed runtime selection"));
            }
            count = count
                .checked_add(selected.values.len())
                .ok_or_else(|| invalid("runtime registry count overflow"))?;
            if count > MAX_VALUES {
                return Err(invalid("runtime registry value count exceeds bounds"));
            }
            let mut key = Key {
                path: selected.path.encode_utf16().collect(),
                children: selected.children,
                upcase: result.upcase.clone(),
                values: BTreeMap::new(),
            };
            for value in selected.values {
                if value.name.len() > MAX_NAME_UNITS || value.data.len() > MAX_VALUE_BYTES {
                    return Err(invalid("runtime registry value exceeds bounds"));
                }
                total = total
                    .checked_add(value.name.len() * 2 + value.data.len())
                    .ok_or_else(|| invalid("runtime registry size overflow"))?;
                let name = key.fold(&value.name);
                if total > MAX_TOTAL_BYTES || key.values.insert(name, value).is_some() {
                    return Err(invalid("oversized or duplicate runtime registry values"));
                }
            }
            if result
                .keys
                .insert(key.fold(&key.path), Arc::new(key))
                .is_some()
            {
                return Err(invalid("duplicate selected runtime registry key"));
            }
        }
        Ok(result)
    }
    pub(crate) fn codepages(&self) -> std::collections::BTreeSet<u32> {
        // Session Manager numeric names are not codepage declarations.
        let key = self.key(&NLS_KEY.encode_utf16().collect::<Vec<_>>());
        key.as_ref()
            .into_iter()
            .flat_map(|key| key.values.values())
            .filter_map(|value| {
                if value.name.is_empty() {
                    return None;
                }
                value.name.iter().try_fold(0u32, |n, &u| {
                    if !(48..=57).contains(&u) {
                        return None;
                    }
                    n.checked_mul(10)?.checked_add(u32::from(u - 48))
                })
            })
            .collect()
    }
    pub(crate) fn key(&self, name: &[u16]) -> Option<Arc<Key>> {
        if self.keys.is_empty() {
            return None;
        }
        let folded: Vec<_> = name.iter().map(|&u| self.upcase[usize::from(u)]).collect();
        self.keys.get(&folded).cloned()
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(windows)]
#[path = "registry/installed.rs"]
mod installed;
#[cfg(windows)]
pub(crate) use installed::snapshot;
#[cfg(not(windows))]
pub(crate) fn snapshot() -> io::Result<Registry> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed runtime registry metadata requires Windows",
    ))
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod tests;
