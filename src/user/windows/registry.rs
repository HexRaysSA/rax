//! Immutable, explicitly selected runtime registry metadata. Guest key handles
//! reference these records; they never contain or forward a host HKEY.
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

pub(crate) const NLS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
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

/// A guest-owned immutable registry key, shared by reference-counted handles.
/// No native handle or host-operation callback is stored in this object.
#[derive(Debug)]
pub struct Key {
    pub(crate) path: Vec<u16>,
    pub(crate) children: u32,
    upcase: Vec<u16>,
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
    key: Option<Arc<Key>>,
}
impl Registry {
    pub(crate) fn nls(upcase: Vec<u16>, values: Vec<Value>, children: u32) -> io::Result<Self> {
        if upcase.len() != 65_536 || values.len() > MAX_VALUES {
            return Err(invalid("runtime NLS registry table exceeds bounds"));
        }
        let mut key = Key {
            path: NLS_KEY.encode_utf16().collect(),
            children,
            upcase,
            values: BTreeMap::new(),
        };
        let mut total = 0usize;
        for value in values {
            if value.name.len() > MAX_NAME_UNITS || value.data.len() > MAX_VALUE_BYTES {
                return Err(invalid("runtime NLS registry value exceeds bounds"));
            }
            total = total
                .checked_add(value.name.len() * 2 + value.data.len())
                .ok_or_else(|| invalid("runtime NLS registry size overflow"))?;
            let name = key.fold(&value.name);
            if total > MAX_TOTAL_BYTES || key.values.insert(name, value).is_some() {
                return Err(invalid(
                    "oversized or duplicate runtime NLS registry values",
                ));
            }
        }
        Ok(Self {
            key: Some(Arc::new(key)),
        })
    }
    pub(crate) fn key(&self, name: &[u16]) -> Option<Arc<Key>> {
        self.key
            .as_ref()
            .filter(|key| key.fold(name) == key.fold(&key.path))
            .cloned()
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
        "installed NLS metadata requires Windows",
    ))
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod tests;
